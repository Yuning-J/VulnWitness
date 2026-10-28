"""Builders for the planner evaluation: a report identity, gold rows and files, and the
model runs of one question with scripted replies."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.domain.investigation import KnowledgeEvidenceSet
from cve_kgrag.domain.planning import ModelReply, PlanningInput
from cve_kgrag.domain.search import SCHEMA_VERSION
from cve_kgrag.evaluation.planner_report import DatasetIdentity, EvaluationIdentity, FightProfile
from tests.support.clocks import SteppingClock
from tests.support.investigation import (
    build_investigation_request,
    build_test_investigation_service,
)
from tests.support.planners import UNAVAILABLE_REPLY, ScriptedModelPort

# The directory, under a test's tmp_path, that evaluation results go to.
EVAL_RESULTS = "eval-results"

# Two cases, one per FiGHT choice, that each finish in round 1 under the policy.
SMALL_GOLD_ROWS: list[dict[str, Any]] = [
    {
        "id": "topic_search",
        "request": {"query": "5G-AKA", "scope": "implementation_only"},
        "sources": {"mitre_fight": "packaged"},
        "expected": {"labels": "ignored by the evaluation"},
    },
    {
        "id": "exact_id",
        "request": {"query": "CVE-9999-0003", "scope": "implementation_only"},
        "sources": {"mitre_fight": "unavailable"},
    },
]


def build_identity(model_runs_per_case: int) -> EvaluationIdentity:
    """An identity whose hashes stand for no particular file or planner."""
    return EvaluationIdentity(
        evidence_set_schema_version=SCHEMA_VERSION,
        source_revision="unavailable",
        package_sha256="e" * 64,
        gold_sha256="a" * 64,
        dataset=DatasetIdentity(
            cve_search_version="fixture-test",
            fight_profile=FightProfile.PER_CASE,
            fight_snapshot_sha256=None,
            sets_sha256=None,
        ),
        deterministic_planner_sha256="b" * 64,
        model_planner_sha256="c" * 64 if model_runs_per_case else None,
        model_runs_per_case=model_runs_per_case,
    )


def build_gold_row(query: str, fight: str = "packaged", **request_fields: Any) -> dict[str, Any]:
    """An implementation-scope gold row; ``request_fields`` override the request's."""
    return {
        "request": {"query": query, "scope": "implementation_only", **request_fields},
        "sources": {"mitre_fight": fight},
    }


def encode_gold(rows: list[Any]) -> bytes:
    return yaml.safe_dump({"trajectories": rows}).encode()


def build_package_dir(directory: Path) -> Path:
    """A stand-in for an installed package: one module and one data file."""
    package_dir = directory / "package"
    (package_dir / "knowledge").mkdir(parents=True, exist_ok=True)
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "knowledge" / "card.yaml").write_text("name: card\n", encoding="utf-8")
    return package_dir


def write_gold_file(directory: Path, rows: list[Any]) -> Path:
    gold_path = directory / "gold.yaml"
    gold_path.write_bytes(encode_gold(rows))
    return gold_path


def run_deterministically(
    fixture_bundle: FixtureBundle, query: str, scope: str, **fields: Any
) -> KnowledgeEvidenceSet:
    service = build_test_investigation_service(fixture_bundle)
    return service.investigate(build_investigation_request(query, scope, **fields))


def run_with_replies(
    fixture_bundle: FixtureBundle,
    query: str,
    scope: str,
    *replies: ModelReply,
    seconds_per_call: float = 0.0,
    **fields: Any,
) -> KnowledgeEvidenceSet:
    """One run whose model planner answers round by round with ``replies``, each taking
    ``seconds_per_call`` on the run's clock."""
    clock = SteppingClock()
    model_port = ScriptedModelPort(list(replies), clock=clock, seconds_per_call=seconds_per_call)
    service = build_test_investigation_service(
        fixture_bundle, model_port=model_port, monotonic_clock=clock.read
    )
    return service.investigate(build_investigation_request(query, scope, **fields))


def list_entry_names(directory: Path) -> list[str]:
    entry_names: list[str] = []
    for entry in directory.iterdir():
        entry_names.append(entry.name)
    return entry_names


@dataclass
class PackageEditingModelPort:
    """A planner that changes a file of the package under evaluation on its first call
    and answers every call unavailable."""

    package_file: Path
    calls: int = 0

    def propose_plan(self, planning_input: PlanningInput, timeout_seconds: float) -> ModelReply:
        if self.calls == 0:
            self.package_file.write_text("EDITED = True\n", encoding="utf-8")
        self.calls += 1
        return UNAVAILABLE_REPLY
