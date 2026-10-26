"""Runs planner evaluation cases one after another on one call runner.

A run starts only once every call an earlier run abandoned has returned, so the process
never holds more abandoned calls than one investigation may leave (ADR 0005 §2), and only
while the package's files are still those the report names.
"""

from dataclasses import dataclass
from pathlib import Path

from cve_kgrag.adapters.fight.pinned_yaml import UnavailableFightSource
from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.application.investigate import InvestigationService
from cve_kgrag.application.planner_setup import ModelPlanning, PlannerSetup
from cve_kgrag.application.threaded_call_runner import ThreadedCallRunner
from cve_kgrag.composition import (
    DETERMINISTIC_PLANNING,
    build_investigation_service,
    build_serving_data_plane,
)
from cve_kgrag.domain.investigation import KnowledgeEvidenceSet
from cve_kgrag.evaluation.gold_cases import FightChoice, GoldCase
from cve_kgrag.evaluation.package_digest import fingerprint_package
from cve_kgrag.evaluation.planner_analysis import CaseRuns
from cve_kgrag.evaluation.result_directory import ResultDirectory

# How long a run waits for the calls earlier runs abandoned to return. Waiting longer
# never loosens the bound, since no run starts while a call is live; it only lets an
# adapter that honours its timeout finish connecting to every address it tries.
IDLE_WAIT_SECONDS = 60.0
ABANDONED_CALLS_STILL_LIVE = (
    f"a call an earlier run abandoned was still running {IDLE_WAIT_SECONDS:.0f} seconds "
    "after that run ended"
)
PACKAGE_CHANGED = "the package's files changed while the evaluation ran"
PACKAGE_UNREADABLE = "the package's files could not be read"


class EvaluationStopped(RuntimeError):
    """The evaluation stopped before its report; the message is one of the fixed
    sentences above."""


@dataclass(frozen=True)
class ModelRuns:
    """The model planner to evaluate and how many times each case runs with it."""

    model_planning: ModelPlanning
    runs_per_case: int


def read_package_digest(package_dir: Path) -> str:
    """``fingerprint_package``, or ``EvaluationStopped`` when a file cannot be read."""
    try:
        return fingerprint_package(package_dir)
    except OSError:
        raise EvaluationStopped(PACKAGE_UNREADABLE) from None


def encode_evidence_set(evidence_set: KnowledgeEvidenceSet) -> bytes:
    return evidence_set.model_dump_json(indent=2).encode()


class CaseRunner:
    """Runs cases over ``bundle`` on ``call_runner``, writing each set to
    ``result_directory`` as it seals, while the package at ``package_dir`` keeps the digest
    ``package_sha256``."""

    def __init__(
        self,
        bundle: FixtureBundle,
        call_runner: ThreadedCallRunner,
        result_directory: ResultDirectory,
        package_dir: Path,
        package_sha256: str,
        idle_wait_seconds: float,
    ) -> None:
        self._bundle = bundle
        self._call_runner = call_runner
        self._result_directory = result_directory
        self._package_dir = package_dir
        self._package_sha256 = package_sha256
        self._idle_wait_seconds = idle_wait_seconds

    def run_case(self, case: GoldCase, model_runs: ModelRuns | None) -> CaseRuns:
        """The case's deterministic run, then its model runs."""
        deterministic_service = self._build_service(case.fight, DETERMINISTIC_PLANNING)
        deterministic_set = self._investigate(deterministic_service, case)
        self._result_directory.write(
            f"deterministic/{case.case_sha256}.json", encode_evidence_set(deterministic_set)
        )
        model_sets: list[KnowledgeEvidenceSet] = []
        if model_runs is not None:
            model_service = self._build_service(case.fight, model_runs.model_planning)
            for run_number in range(1, model_runs.runs_per_case + 1):
                model_set = self._investigate(model_service, case)
                self._result_directory.write(
                    f"model/{case.case_sha256}-{run_number:02d}.json",
                    encode_evidence_set(model_set),
                )
                model_sets.append(model_set)
        return CaseRuns(
            case_sha256=case.case_sha256,
            deterministic_set=deterministic_set,
            model_sets=tuple(model_sets),
        )

    def check_package(self) -> None:
        """Raise ``EvaluationStopped`` unless the package's files still have the digest
        the report names."""
        if read_package_digest(self._package_dir) != self._package_sha256:
            raise EvaluationStopped(PACKAGE_CHANGED)

    def _build_service(
        self, fight: FightChoice, planner_setup: PlannerSetup
    ) -> InvestigationService:
        """The production service for a case on the shared call runner: the packaged
        FiGHT excerpt, composition's default, or a source that serves nothing."""
        if fight == "unavailable":
            return build_investigation_service(
                build_serving_data_plane(self._bundle, fight_source=UnavailableFightSource()),
                planner_setup=planner_setup,
                call_runner=self._call_runner,
            )
        return build_investigation_service(
            build_serving_data_plane(self._bundle),
            planner_setup=planner_setup,
            call_runner=self._call_runner,
        )

    def _investigate(self, service: InvestigationService, case: GoldCase) -> KnowledgeEvidenceSet:
        """The case's run, started once every call an earlier run abandoned has returned
        and while the package is unchanged; raises ``EvaluationStopped`` otherwise."""
        if not self._call_runner.wait_until_idle(self._idle_wait_seconds):
            raise EvaluationStopped(ABANDONED_CALLS_STILL_LIVE)
        self.check_package()
        return service.investigate(case.request)
