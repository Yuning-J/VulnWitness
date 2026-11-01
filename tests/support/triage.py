"""Real fixture services and injected failures for triage integration tests."""

from collections.abc import Callable
from functools import partial
from pathlib import Path

from tests.support.clocks import SteppingClock, read_fixed_clock
from vulnwitness.adapters.session.recorder import SessionRecorder
from vulnwitness.adapters.session.triage_artifacts import SessionTriageArtifacts
from vulnwitness.application.triage_workflow import TriageWorkflow
from vulnwitness.composition import (
    build_investigation_deployment,
    build_investigation_service,
    build_serving_data_plane,
    load_packaged_fixture,
)
from vulnwitness.domain.search import SearchResponse
from vulnwitness.domain.triage import TriageLimits
from vulnwitness.interfaces.cli_session import encode_cli_answer
from vulnwitness.interfaces.knowledge_toolbox import describe_knowledge_capabilities
from vulnwitness.ports.triage_artifacts import TriageArtifacts


def read_triage_tree(directory: Path) -> dict[str, bytes]:
    contents: dict[str, bytes] = {}
    for path in directory.rglob("*"):
        if path.is_file():
            contents[str(path.relative_to(directory))] = path.read_bytes()
    return contents


def build_triage_workflow(
    directory: Path,
    *,
    limits: TriageLimits | None = None,
    lookup: Callable[[str], SearchResponse] | None = None,
    clock: SteppingClock | None = None,
    artifacts: TriageArtifacts | None = None,
) -> TriageWorkflow:
    plane = build_serving_data_plane(load_packaged_fixture(), clock=read_fixed_clock)
    assert plane.session_dataset is not None
    deployment = build_investigation_deployment(plane, wall_clock=read_fixed_clock)
    limits = limits or TriageLimits()
    clock = clock or SteppingClock()
    return TriageWorkflow(
        capabilities=partial(
            describe_knowledge_capabilities,
            deployment,
            build_investigation_service(plane).describe_capabilities(),
        ),
        query_product=deployment.product_query_service.query,
        lookup=lookup or deployment.search_service.lookup,
        recorder=SessionRecorder(
            directory, plane.session_dataset, read_fixed_clock, call_limit=limits.call_limit
        ),
        artifacts=artifacts or SessionTriageArtifacts(directory),
        clock=clock.read,
        limits=limits,
        encode=encode_cli_answer,
    )


class FailingLookup:
    """One real lookup succeeds, then an injected service failure stops the run."""

    def __init__(self, lookup: Callable[[str], SearchResponse]) -> None:
        self._lookup = lookup
        self.calls: list[str] = []

    def lookup(self, cve_id: str) -> SearchResponse:
        self.calls.append(cve_id)
        if len(self.calls) == 2:
            raise RuntimeError("injected lookup failure")
        return self._lookup(cve_id)
