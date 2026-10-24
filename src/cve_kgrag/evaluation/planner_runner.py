"""Runs the gold investigation cases for the planner evaluation and writes what they gave.

Each case runs once with the deterministic policy and, when model runs are asked for,
that many more times with the model planner, over the packaged fixture and the FiGHT
source the case names. Every evidence set and the report go to a new result directory that only
its owner can read: a set holds the query and the model's plan text, so the directory
is sensitive. The report is ``analyze_planner_runs``'s, which reads the sets alone.

A gold file is untrusted input: a problem in it is reported in the server's words,
never by quoting the file.
"""

import os
import re
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml
from pydantic import ValidationError

from cve_kgrag.adapters.fight.pinned_yaml import UnavailableFightSource
from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.adapters.strict_yaml import load_strict_yaml
from cve_kgrag.application.investigate import InvestigationService
from cve_kgrag.application.investigation_policy import describe_deterministic_planner
from cve_kgrag.application.planner_setup import ModelPlanning, PlannerSetup
from cve_kgrag.composition import DETERMINISTIC_PLANNING, build_investigation_service
from cve_kgrag.domain.contract_model import list_validation_problems
from cve_kgrag.domain.evidence_set_verification_report import bound_violations
from cve_kgrag.domain.hashing import canonical_sha256
from cve_kgrag.domain.investigation import InvestigationRequest, KnowledgeEvidenceSet
from cve_kgrag.domain.search import SCHEMA_VERSION
from cve_kgrag.evaluation.planner_analysis import CaseRuns, analyze_planner_runs
from cve_kgrag.evaluation.planner_report import (
    GIT_COMMIT_PATTERN,
    EvaluationIdentity,
    PlannerEvaluationReport,
    format_report,
)

MAX_GOLD_FILE_BYTES = 1024 * 1024
MAX_GOLD_CASES = 100
MAX_MODEL_RUNS = 20
UNAVAILABLE_REVISION = "unavailable"
REPORT_FILE_NAME = "report.json"
GIT_TIMEOUT_SECONDS = 10

FightChoice = Literal["packaged", "unavailable"]


class GoldFileError(ValueError):
    """The gold file is not an investigation gold file; the message never quotes it."""


@dataclass(frozen=True)
class GoldCase:
    """One gold row: the request and the FiGHT source its deployment serves.
    ``case_sha256`` names it in the report in place of its query."""

    case_sha256: str
    request: InvestigationRequest
    fight: FightChoice


def read_gold_case(row: object, position: int) -> GoldCase:
    if not isinstance(row, dict):
        raise GoldFileError(f"case {position} is not a mapping")
    sources = row.get("sources")
    fight_name = sources.get("mitre_fight") if isinstance(sources, dict) else None
    fight: FightChoice
    if fight_name == "packaged":
        fight = "packaged"
    elif fight_name == "unavailable":
        fight = "unavailable"
    else:
        raise GoldFileError(f"case {position}: sources.mitre_fight is not packaged or unavailable")
    try:
        request = InvestigationRequest.model_validate(row.get("request"))
    except ValidationError as error:
        problems = "; ".join(bound_violations(list_validation_problems(error)))
        raise GoldFileError(f"case {position}: request: {problems}") from None
    case_sha256 = canonical_sha256({"request": request.model_dump(mode="json"), "fight": fight})
    return GoldCase(case_sha256=case_sha256, request=request, fight=fight)


def load_gold_cases(gold_bytes: bytes) -> tuple[GoldCase, ...]:
    """The cases of an investigation gold file: a ``trajectories`` list whose rows each
    hold a ``request`` and ``sources.mitre_fight``; every other key is the labels, which the
    evaluation does not read. Raises ``GoldFileError`` for any other file, more than
    ``MAX_GOLD_CASES`` rows or a row repeating an earlier one."""
    if len(gold_bytes) > MAX_GOLD_FILE_BYTES:
        raise GoldFileError(f"the gold file is larger than {MAX_GOLD_FILE_BYTES} bytes")
    try:
        gold_document = load_strict_yaml(gold_bytes.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        raise GoldFileError("the gold file is not UTF-8 YAML a strict loader accepts") from None
    rows = gold_document.get("trajectories") if isinstance(gold_document, dict) else None
    if not isinstance(rows, list) or not rows:
        raise GoldFileError("the gold file holds no trajectories list")
    if len(rows) > MAX_GOLD_CASES:
        raise GoldFileError(f"the gold file holds more than {MAX_GOLD_CASES} cases")
    cases: list[GoldCase] = []
    case_hashes: set[str] = set()
    for position, row in enumerate(rows, start=1):
        case = read_gold_case(row, position)
        if case.case_sha256 in case_hashes:
            raise GoldFileError(f"case {position} repeats an earlier case")
        case_hashes.add(case.case_sha256)
        cases.append(case)
    return tuple(cases)


def run_git(directory: Path, *arguments: str) -> str | None:
    """Git's stripped output for ``arguments`` run in ``directory``; ``None`` when git is
    missing, fails or takes longer than ``GIT_TIMEOUT_SECONDS``. Git takes no optional
    lock, so reading the revision never rewrites the checkout's index."""
    try:
        completed = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(directory), *arguments],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def read_source_revision(package_dir: Path) -> str:
    """The commit of the git checkout whose ``src/cve_kgrag`` is ``package_dir``, with
    ``+dirty`` when tracked files have uncommitted changes; ``unavailable`` for an installed
    package, which is no checkout, or one inside another repository."""
    toplevel = run_git(package_dir, "rev-parse", "--show-toplevel")
    if toplevel is None:
        return UNAVAILABLE_REVISION
    if (Path(toplevel) / "src" / "cve_kgrag").resolve() != package_dir.resolve():
        return UNAVAILABLE_REVISION
    commit = run_git(package_dir, "rev-parse", "HEAD")
    tracked_changes = run_git(package_dir, "status", "--porcelain", "--untracked-files=no")
    if commit is None or tracked_changes is None or not re.fullmatch(GIT_COMMIT_PATTERN, commit):
        return UNAVAILABLE_REVISION
    if tracked_changes:
        return f"{commit}+dirty"
    return commit


class ResultDirectory:
    """A new directory, readable by its owner only, whose files are each written once."""

    def __init__(self, path: Path) -> None:
        self.path = path

    @classmethod
    def create(cls, output_dir: Path) -> "ResultDirectory":
        """A new ``planner-*`` directory under ``output_dir``, which is created when missing
        but never its parents. Raises ``OSError`` when either cannot be made."""
        output_dir.mkdir(mode=0o700, exist_ok=True)
        return cls(Path(tempfile.mkdtemp(prefix="planner-", dir=output_dir)))

    def write(self, relative_path: str, content: bytes) -> None:
        """Write ``content`` to a file that must not exist yet, readable by its owner only."""
        file_path = self.path / relative_path
        file_path.parent.mkdir(mode=0o700, exist_ok=True)
        file_descriptor = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(file_descriptor, "wb") as result_file:
            result_file.write(content)


@dataclass(frozen=True)
class ModelRuns:
    """The model planner to evaluate and how many times each case runs with it."""

    model_planning: ModelPlanning
    runs_per_case: int


def build_case_service(
    bundle: FixtureBundle, fight: FightChoice, planner_setup: PlannerSetup
) -> InvestigationService:
    """The production service for a case: the packaged FiGHT excerpt, composition's
    default, or a source that serves nothing."""
    if fight == "unavailable":
        return build_investigation_service(
            bundle, fight_source=UnavailableFightSource(), planner_setup=planner_setup
        )
    return build_investigation_service(bundle, planner_setup=planner_setup)


def encode_evidence_set(evidence_set: KnowledgeEvidenceSet) -> bytes:
    return evidence_set.model_dump_json(indent=2).encode()


def run_case(
    case: GoldCase,
    bundle: FixtureBundle,
    model_runs: ModelRuns | None,
    result_directory: ResultDirectory,
) -> CaseRuns:
    """The case's deterministic run, then its model runs, each set written as it seals."""
    deterministic_service = build_case_service(bundle, case.fight, DETERMINISTIC_PLANNING)
    deterministic_set = deterministic_service.investigate(case.request)
    result_directory.write(
        f"deterministic/{case.case_sha256}.json", encode_evidence_set(deterministic_set)
    )
    model_sets: list[KnowledgeEvidenceSet] = []
    if model_runs is not None:
        model_service = build_case_service(bundle, case.fight, model_runs.model_planning)
        for run_number in range(1, model_runs.runs_per_case + 1):
            model_set = model_service.investigate(case.request)
            result_directory.write(
                f"model/{case.case_sha256}-{run_number:02d}.json", encode_evidence_set(model_set)
            )
            model_sets.append(model_set)
    return CaseRuns(
        case_sha256=case.case_sha256,
        deterministic_set=deterministic_set,
        model_sets=tuple(model_sets),
    )


def run_planner_evaluation(
    cases: Sequence[GoldCase],
    *,
    gold_sha256: str,
    bundle: FixtureBundle,
    model_runs: ModelRuns | None,
    source_revision: str,
    result_directory: ResultDirectory,
) -> PlannerEvaluationReport:
    """Run every case (``run_case``), then write and return the report on the sets.

    Without ``model_runs`` only the deterministic baseline runs. The report's identity is
    built first, so a run that could not be reported never starts. Raises ``OSError`` when
    a result cannot be written.
    """
    model_planner_sha256 = None
    if model_runs is not None:
        model_planner_sha256 = canonical_sha256(
            model_runs.model_planning.identity.model_dump(mode="json")
        )
    identity = EvaluationIdentity(
        evidence_set_schema_version=SCHEMA_VERSION,
        source_revision=source_revision,
        gold_sha256=gold_sha256,
        deterministic_planner_sha256=canonical_sha256(
            describe_deterministic_planner().model_dump(mode="json")
        ),
        model_planner_sha256=model_planner_sha256,
        model_runs_per_case=0 if model_runs is None else model_runs.runs_per_case,
    )
    case_runs: list[CaseRuns] = []
    for case in cases:
        case_runs.append(run_case(case, bundle, model_runs, result_directory))
    report = analyze_planner_runs(identity, case_runs)
    result_directory.write(REPORT_FILE_NAME, format_report(report))
    return report
