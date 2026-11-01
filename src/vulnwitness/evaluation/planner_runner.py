"""Runs the planner evaluation: every gold case, deterministically and with the model
planner when model runs are asked for, then the report on the sets.

Every evidence set and the report go to a new result directory that only its owner can
read: a set holds the query and the model's plan text, so the directory is sensitive.
The report is ``analyze_planner_runs``'s, which reads the sets alone. It names the
package it measured by the digest of its files, code and packaged data alike, and is
written only when every run saw that package (``CaseRunner``).
"""

import re
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from vulnwitness.application.investigation_policy import describe_deterministic_planner
from vulnwitness.application.serving_data_plane import ServingDataPlane
from vulnwitness.application.threaded_call_runner import ThreadedCallRunner
from vulnwitness.domain.hashing import canonical_sha256
from vulnwitness.domain.search import SCHEMA_VERSION
from vulnwitness.evaluation.case_runner import (
    IDLE_WAIT_SECONDS,
    CaseRunner,
    ModelRuns,
    read_package_digest,
)
from vulnwitness.evaluation.gold_cases import FightChoice, GoldCase
from vulnwitness.evaluation.gold_sets import DerivedSets
from vulnwitness.evaluation.labelled_cases import GoldFile, SubjectKind
from vulnwitness.evaluation.planner_analysis import CaseRuns, analyze_planner_runs
from vulnwitness.evaluation.planner_report import (
    GIT_COMMIT_PATTERN,
    DatasetIdentity,
    EvaluationIdentity,
    PlannerEvaluationReport,
    format_report,
)
from vulnwitness.evaluation.result_directory import ResultDirectory
from vulnwitness.evaluation.sufficiency_analysis import analyze_sufficiency

MAX_MODEL_RUNS = 20
UNAVAILABLE_REVISION = "unavailable"
REPORT_FILE_NAME = "report.json"
GIT_TIMEOUT_SECONDS = 10


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
    """The commit of the git checkout whose ``src/vulnwitness`` is ``package_dir``, with
    ``+dirty`` when tracked files have uncommitted changes; ``unavailable`` for an installed
    package, which is no checkout, or one inside another repository."""
    toplevel = run_git(package_dir, "rev-parse", "--show-toplevel")
    if toplevel is None:
        return UNAVAILABLE_REVISION
    if (Path(toplevel) / "src" / "vulnwitness").resolve() != package_dir.resolve():
        return UNAVAILABLE_REVISION
    commit = run_git(package_dir, "rev-parse", "HEAD")
    tracked_changes = run_git(package_dir, "status", "--porcelain", "--untracked-files=no")
    if commit is None or tracked_changes is None or not re.fullmatch(GIT_COMMIT_PATTERN, commit):
        return UNAVAILABLE_REVISION
    if tracked_changes:
        return f"{commit}+dirty"
    return commit


@dataclass(frozen=True)
class LabelledCases:
    """What an M7b evaluation scores its runs against: the gold file's labelled cases
    and each case's recorded sets."""

    gold_file: GoldFile
    gold_sets: dict[str, dict[SubjectKind, DerivedSets]]


def run_planner_evaluation(
    cases: Sequence[GoldCase],
    *,
    gold_sha256: str,
    data_planes: Mapping[FightChoice, ServingDataPlane],
    dataset: DatasetIdentity,
    labelled_cases: LabelledCases | None,
    model_runs: ModelRuns | None,
    source_revision: str,
    package_dir: Path,
    result_directory: ResultDirectory,
    idle_wait_seconds: float = IDLE_WAIT_SECONDS,
) -> PlannerEvaluationReport:
    """Run every case (``CaseRunner.run_case``) over ``data_planes``, then write and return
    the report on the sets, scored against ``labelled_cases`` when the gold file labels
    them.

    Without ``model_runs`` only the deterministic baseline runs. The report's identity is
    built first, so a run that could not be reported never starts, and names the package
    at ``package_dir`` by its digest. Raises ``EvaluationStopped``, without writing the
    report, when a call an earlier run abandoned is still live after
    ``idle_wait_seconds``, or the package's files changed or could not be read before a
    run or after the last; ``OSError`` when a result cannot be written.
    """
    model_planner_sha256 = None
    if model_runs is not None:
        model_planner_sha256 = canonical_sha256(
            model_runs.model_planning.identity.model_dump(mode="json")
        )
    identity = EvaluationIdentity(
        evidence_set_schema_version=SCHEMA_VERSION,
        source_revision=source_revision,
        package_sha256=read_package_digest(package_dir),
        gold_sha256=gold_sha256,
        dataset=dataset,
        deterministic_planner_sha256=canonical_sha256(
            describe_deterministic_planner().model_dump(mode="json")
        ),
        model_planner_sha256=model_planner_sha256,
        model_runs_per_case=0 if model_runs is None else model_runs.runs_per_case,
    )
    case_runner = CaseRunner(
        data_planes,
        ThreadedCallRunner(),
        result_directory,
        package_dir,
        identity.package_sha256,
        idle_wait_seconds,
    )
    case_runs: list[CaseRuns] = []
    for case in cases:
        case_runs.append(case_runner.run_case(case, model_runs))
    case_runner.check_package()
    sufficiency = None
    if labelled_cases is not None:
        sufficiency = analyze_sufficiency(
            labelled_cases.gold_file, labelled_cases.gold_sets, case_runs, model_runs is not None
        )
    report = analyze_planner_runs(identity, case_runs, sufficiency)
    result_directory.write(REPORT_FILE_NAME, format_report(report))
    return report
