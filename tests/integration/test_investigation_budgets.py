"""Every cap stops the run honestly: lowered caps end in budget_exhausted, and charges stand."""

import threading
import time
from typing import Any

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.adapters.lexical.bm25_index import Bm25LexicalIndex
from cve_kgrag.composition import (
    build_investigation_service,
    build_serving_data_plane,
    load_packaged_fight_source,
)
from cve_kgrag.domain.budget import BudgetBreach
from cve_kgrag.domain.investigation import (
    CveBackendRequest,
    FightBackendRequest,
    KnowledgeEvidenceSet,
    PlannerOutcome,
    StepAdmission,
    StopReason,
)
from cve_kgrag.domain.search import RetrievalOutcome
from cve_kgrag.domain.taxonomy import BackendStatus, ResultStatus
from cve_kgrag.domain.text import normalize_query
from tests.support.clocks import ONE_SECOND_RUN_REAL_SECONDS, SteppingClock, read_fixed_clock
from tests.support.fakes import (
    CannedRetriever,
    DeadlineNearingRetriever,
    FightRequestRecorder,
    InventingRetriever,
    LexicalRequestRecorder,
    SlowRetriever,
    build_failure,
)
from tests.support.investigation import (
    BlockingBackend,
    build_blocking_investigation_service,
    build_deadline_nearing_service,
    build_investigation_request,
    build_test_investigation_service,
    list_step_tools,
    list_transitions,
    list_warning_codes,
)
from tests.support.planners import ScriptedModelPort, build_plan_reply
from tests.support.services import build_fixture_service


def list_backend_limits(evidence_set: KnowledgeEvidenceSet) -> list[int]:
    backend_limits: list[int] = []
    for step in evidence_set.trajectory.steps:
        for backend_request in step.backend_requests:
            backend_limits.append(backend_request.limit)
    return backend_limits


def list_recorded_cve_requests(evidence_set: KnowledgeEvidenceSet) -> list[tuple[str, int]]:
    """Each CVE request the trajectory records, as the lexical channel receives it: the
    normalized query (these queries name no CVE ID) and the limit."""
    cve_requests: list[tuple[str, int]] = []
    for step in evidence_set.trajectory.steps:
        for backend_request in step.backend_requests:
            if isinstance(backend_request, CveBackendRequest):
                cve_requests.append((normalize_query(backend_request.query), backend_request.limit))
    return cve_requests


def list_recorded_fight_requests(
    evidence_set: KnowledgeEvidenceSet,
) -> list[tuple[tuple[str, ...], int]]:
    fight_requests: list[tuple[tuple[str, ...], int]] = []
    for step in evidence_set.trajectory.steps:
        for backend_request in step.backend_requests:
            if isinstance(backend_request, FightBackendRequest):
                fight_requests.append((backend_request.terms, backend_request.limit))
    return fight_requests


@pytest.mark.parametrize(
    ("query", "scope", "budget", "expected_breach", "expected_tools", "expected_stop_basis"),
    [
        (
            "5gaka",
            "implementation_only",
            {"max_rounds": 1},
            BudgetBreach.ROUNDS,
            ["cve_search"],
            "round_cap_reached",
        ),
        (
            "5gaka",
            "mixed",
            {"max_tool_calls": 4},
            BudgetBreach.TOOL_CALLS,
            [],
            "plan_over_budget",
        ),
        (
            "5gaka",
            "mixed",
            {"max_sources": 1},
            BudgetBreach.SOURCES,
            [],
            "plan_over_budget",
        ),
        (
            "CVE-9999-0003",
            "implementation_only",
            {"max_context_bytes": 1024},
            BudgetBreach.CONTEXT_BYTES,
            ["cve_exact_lookup"],
            "budget_breached",
        ),
    ],
    ids=["max_rounds_1", "max_tool_calls_4", "max_sources_1", "max_context_bytes_1024"],
)
def test_lowered_cap_ends_the_run_as_budget_exhausted(
    fixture_bundle: FixtureBundle,
    query: str,
    scope: str,
    budget: dict[str, int],
    expected_breach: BudgetBreach,
    expected_tools: list[str],
    expected_stop_basis: str,
) -> None:
    service = build_test_investigation_service(fixture_bundle)

    evidence_set = service.investigate(build_investigation_request(query, scope, budget=budget))

    assert (evidence_set.stop_reason, evidence_set.status) == (
        StopReason.BUDGET_EXHAUSTED,
        ResultStatus.PARTIAL,
    )
    assert evidence_set.trajectory.budget_used.breach is expected_breach
    assert list_step_tools(evidence_set) == expected_tools
    assert list_transitions(evidence_set)[-2][2] == expected_stop_basis
    assert evidence_set.has_answer() is False


def test_response_over_the_byte_cap_is_discarded_with_a_warning(
    fixture_bundle: FixtureBundle,
) -> None:
    service = build_test_investigation_service(fixture_bundle)

    evidence_set = service.investigate(
        build_investigation_request(
            "CVE-9999-0003", "implementation_only", budget={"max_context_bytes": 1024}
        )
    )

    step = evidence_set.trajectory.steps[0]
    assert step.admission is StepAdmission.DISCARDED_OVER_CONTEXT_BUDGET
    assert step.context_bytes > 1024
    assert step.result_sha256 is not None
    assert evidence_set.trajectory.budget_used.context_bytes == 0
    assert list_warning_codes(evidence_set) == ["evidence_discarded"]


@pytest.mark.parametrize(
    ("query", "scope", "expected_answer_ids"),
    [
        ("democorp", "implementation_only", ("CVE-9999-0001",)),
        ("5gaka", "protocol_context_only", ("CVE-9999-0003", "FGT1499.503")),
        ("5gaka", "mixed", ("CVE-9999-0003", "FGT1499.503")),
    ],
    ids=["cve_search", "topic_context_protocol", "topic_context_mixed"],
)
def test_lowered_result_cap_limits_what_every_tool_returns(
    fixture_bundle: FixtureBundle,
    query: str,
    scope: str,
    expected_answer_ids: tuple[str, ...],
) -> None:
    # Uncapped, each of these calls returns two to seven answer IDs.
    service = build_test_investigation_service(fixture_bundle)

    evidence_set = service.investigate(
        build_investigation_request(query, scope, budget={"max_results_per_call": 1})
    )

    step = evidence_set.trajectory.steps[0]
    assert len(evidence_set.trajectory.steps) == 1
    assert set(list_backend_limits(evidence_set)) == {1}
    assert step.answer_ids == expected_answer_ids
    assert evidence_set.status is ResultStatus.OK


@pytest.mark.parametrize("max_results_per_call", [1, 5, 20])
@pytest.mark.parametrize(
    ("query", "scope", "expected_tools"),
    [
        ("5gaka", "implementation_only", ["cve_search", "topic_context"]),
        ("5gaka", "mixed", ["topic_context"]),
        ("5gaka", "protocol_context_only", ["topic_context"]),
    ],
    ids=["literal_miss_then_topic", "topic_mixed", "topic_protocol"],
)
def test_every_backend_request_stays_within_max_results_per_call(
    fixture_bundle: FixtureBundle,
    query: str,
    scope: str,
    expected_tools: list[str],
    max_results_per_call: int,
) -> None:
    lexical_recorder = LexicalRequestRecorder(Bm25LexicalIndex(fixture_bundle.records))
    packaged_fight_source, pinned_fight_snapshot = load_packaged_fight_source(read_fixed_clock)
    fight_recorder = FightRequestRecorder(packaged_fight_source)
    service = build_investigation_service(
        build_serving_data_plane(
            fixture_bundle,
            search_service=build_fixture_service(
                fixture_bundle, lexical_retriever=lexical_recorder
            ),
            fight_source=fight_recorder,
            pinned_fight_snapshot=pinned_fight_snapshot,
        ),
        wall_clock=read_fixed_clock,
        monotonic_clock=SteppingClock().read,
    )

    evidence_set = service.investigate(
        build_investigation_request(
            query, scope, budget={"max_results_per_call": max_results_per_call}
        )
    )

    assert list_step_tools(evidence_set) == expected_tools
    sent_limits: list[int] = []
    for _, cve_limit in lexical_recorder.requests:
        sent_limits.append(cve_limit)
    for _, fight_limit in fight_recorder.requests:
        sent_limits.append(fight_limit)
    assert sent_limits
    assert max(sent_limits) <= max_results_per_call
    assert list_recorded_cve_requests(evidence_set) == lexical_recorder.requests
    assert list_recorded_fight_requests(evidence_set) == fight_recorder.requests


def test_lowered_result_cap_limits_each_section(fixture_bundle: FixtureBundle) -> None:
    service = build_test_investigation_service(fixture_bundle)

    evidence_set = service.investigate(
        build_investigation_request(
            "5gaka", "protocol_context_only", budget={"max_results_per_call": 1}
        )
    )

    assert len(evidence_set.protocol_context) == 1
    assert len(evidence_set.excluded_implementation_candidates) == 1


def test_slow_call_finishing_past_the_deadline_is_discarded_and_nothing_follows(
    fixture_bundle: FixtureBundle,
) -> None:
    clock = SteppingClock()
    slow_lexical = SlowRetriever(Bm25LexicalIndex(fixture_bundle.records), clock, seconds=31)
    service = build_test_investigation_service(
        fixture_bundle, monotonic_clock=clock.read, lexical_retriever=slow_lexical
    )

    evidence_set = service.investigate(build_investigation_request("5gaka", "implementation_only"))

    step = evidence_set.trajectory.steps[0]
    assert list_step_tools(evidence_set) == ["cve_search"]
    assert step.admission is StepAdmission.DISCARDED_AFTER_DEADLINE
    assert evidence_set.trajectory.budget_used.breach is BudgetBreach.WALL_TIME
    assert evidence_set.stop_reason is StopReason.BUDGET_EXHAUSTED
    assert evidence_set.timings.steps[0].duration_ms == 31_000


def test_slow_refinement_landing_past_the_deadline_discards_only_that_round(
    fixture_bundle: FixtureBundle,
) -> None:
    clock = SteppingClock()
    slow_lexical = SlowRetriever(Bm25LexicalIndex(fixture_bundle.records), clock, seconds=10)
    service = build_test_investigation_service(
        fixture_bundle, monotonic_clock=clock.read, lexical_retriever=slow_lexical
    )

    evidence_set = service.investigate(build_investigation_request("5gaka", "implementation_only"))

    admissions: list[StepAdmission] = []
    for step in evidence_set.trajectory.steps:
        admissions.append(step.admission)
    assert admissions == [StepAdmission.ADMITTED, StepAdmission.DISCARDED_AFTER_DEADLINE]
    assert evidence_set.trajectory.budget_used.breach is BudgetBreach.WALL_TIME
    assert evidence_set.has_answer() is False


@pytest.mark.parametrize(
    ("retrievers", "query", "expected_tool_calls"),
    [
        ({"lexical_retriever": CannedRetriever(build_failure(BackendStatus.ERROR))}, "5gaka", 1),
        ({"lexical_retriever": InventingRetriever()}, "crash", 1),
        ({}, "zzqx", 1),
        (
            {"lexical_retriever": CannedRetriever(RetrievalOutcome(status=BackendStatus.OK))},
            "CVE-9999-4242 5gaka",
            5,
        ),
    ],
    ids=["failed_source", "invalid_evidence", "no_match", "no_match_after_refinement"],
)
def test_failed_and_empty_calls_stay_charged(
    fixture_bundle: FixtureBundle,
    retrievers: dict[str, Any],
    query: str,
    expected_tool_calls: int,
) -> None:
    service = build_test_investigation_service(fixture_bundle, **retrievers)

    evidence_set = service.investigate(build_investigation_request(query, "implementation_only"))

    charged_tool_calls = 0
    for step in evidence_set.trajectory.steps:
        charged_tool_calls += step.charged_tool_calls
    assert evidence_set.trajectory.budget_used.tool_calls == expected_tool_calls
    assert charged_tool_calls == expected_tool_calls


def test_deadline_reached_before_the_refinement_round_issues_no_further_call(
    fixture_bundle: FixtureBundle,
) -> None:
    service = build_deadline_nearing_service(fixture_bundle)

    evidence_set = service.investigate(build_investigation_request("5gaka", "implementation_only"))

    assert list_step_tools(evidence_set) == ["cve_search"]
    assert evidence_set.trajectory.steps[0].admission is StepAdmission.ADMITTED
    assert evidence_set.trajectory.budget_used.tool_calls == 1
    assert evidence_set.trajectory.budget_used.breach is BudgetBreach.WALL_TIME
    assert list_transitions(evidence_set)[-2] == ["refine", "validate", "budget_breached"]
    assert (evidence_set.stop_reason, evidence_set.status) == (
        StopReason.BUDGET_EXHAUSTED,
        ResultStatus.PARTIAL,
    )


def test_deadline_reached_before_the_round_two_planner_call_skips_the_planner(
    fixture_bundle: FixtureBundle,
) -> None:
    model_port = ScriptedModelPort([build_plan_reply({"tool": "cve_search", "query": "5gaka"})] * 2)
    service = build_deadline_nearing_service(fixture_bundle, model_port)

    evidence_set = service.investigate(build_investigation_request("5gaka", "implementation_only"))

    skipped_round = evidence_set.trajectory.rounds[1]
    assert len(model_port.timeouts) == 1
    assert skipped_round.planner_outcome is PlannerOutcome.MODEL_SKIPPED_AT_DEADLINE
    assert (skipped_round.rejections, skipped_round.model_reply) == ((), None)
    assert skipped_round.model_reply_sha256 is None
    assert (skipped_round.accepted_plan, skipped_round.executed_step_indices) == ((), ())
    assert evidence_set.trajectory.budget_used.planner_calls == 1
    assert evidence_set.trajectory.budget_used.breach is BudgetBreach.WALL_TIME
    assert list_transitions(evidence_set)[-2] == ["refine", "validate", "budget_breached"]
    assert evidence_set.stop_reason is StopReason.BUDGET_EXHAUSTED


TWO_SEARCH_PLAN = build_plan_reply(
    {"tool": "cve_search", "query": "5g aka"}, {"tool": "cve_search", "query": "ausf"}
)


@pytest.mark.parametrize(
    ("budget", "retriever_kind", "expected_admission", "expected_stop"),
    [
        (
            {"max_context_bytes": 1500},
            "fixture",
            StepAdmission.DISCARDED_OVER_CONTEXT_BUDGET,
            StopReason.BUDGET_EXHAUSTED,
        ),
        ({}, "inventing", StepAdmission.REJECTED_INVALID_EVIDENCE, StopReason.INVALID_EVIDENCE),
        ({}, "deadline_nearing", StepAdmission.ADMITTED, StopReason.BUDGET_EXHAUSTED),
    ],
    ids=["over_context_bytes", "invalid_evidence", "deadline_reached"],
)
def test_step_that_ends_the_run_leaves_the_rest_of_its_plan_unissued(
    fixture_bundle: FixtureBundle,
    budget: dict[str, int],
    retriever_kind: str,
    expected_admission: StepAdmission,
    expected_stop: StopReason,
) -> None:
    clock = SteppingClock()
    retrievers: dict[str, Any] = {}
    if retriever_kind == "inventing":
        retrievers["lexical_retriever"] = InventingRetriever()
    elif retriever_kind == "deadline_nearing":
        retrievers["lexical_retriever"] = DeadlineNearingRetriever(
            Bm25LexicalIndex(fixture_bundle.records), clock, seconds=29.5, seconds_per_read=1.0
        )
    service = build_test_investigation_service(
        fixture_bundle,
        model_port=ScriptedModelPort([TWO_SEARCH_PLAN]),
        monotonic_clock=clock.read,
        **retrievers,
    )

    evidence_set = service.investigate(
        build_investigation_request("5G-AKA", "implementation_only", budget=budget)
    )

    assert len(evidence_set.trajectory.rounds[0].accepted_plan) == 2
    assert len(evidence_set.trajectory.steps) == 1
    assert evidence_set.trajectory.steps[0].admission is expected_admission
    assert evidence_set.trajectory.budget_used.tool_calls == 1
    assert evidence_set.stop_reason is expected_stop


@pytest.mark.parametrize(
    ("blocking_backend", "query", "scope", "expected_tool", "expected_charge"),
    [
        ("lexical", "5gaka", "implementation_only", "cve_search", 1),
        ("fight", "5gaka", "protocol_context_only", "topic_context", 5),
    ],
    ids=["lexical_never_returns", "fight_never_returns"],
)
def test_backend_that_never_returns_is_abandoned_at_the_deadline(
    fixture_bundle: FixtureBundle,
    blocked_call_release: threading.Event,
    blocking_backend: BlockingBackend,
    query: str,
    scope: str,
    expected_tool: str,
    expected_charge: int,
) -> None:
    service = build_blocking_investigation_service(
        fixture_bundle, blocking_backend, blocked_call_release
    )
    request = build_investigation_request(query, scope, budget={"max_wall_time_seconds": 1})

    real_started_at = time.monotonic()
    evidence_set = service.investigate(request)
    real_elapsed_seconds = time.monotonic() - real_started_at

    assert real_elapsed_seconds < ONE_SECOND_RUN_REAL_SECONDS
    step = evidence_set.trajectory.steps[0]
    assert list_step_tools(evidence_set) == [expected_tool]
    assert step.admission is StepAdmission.TIMED_OUT
    assert (step.status, step.result_sha256, step.answer_ids) == (None, None, ())
    assert step.charged_tool_calls == expected_charge
    assert evidence_set.trajectory.budget_used.tool_calls == expected_charge
    assert evidence_set.trajectory.budget_used.breach is BudgetBreach.WALL_TIME
    assert (evidence_set.stop_reason, evidence_set.status) == (
        StopReason.BUDGET_EXHAUSTED,
        ResultStatus.PARTIAL,
    )
    assert evidence_set.has_answer() is False
    step_timing = evidence_set.timings.steps[0]
    assert step_timing.started_offset_ms + step_timing.duration_ms >= 1000
    assert list_warning_codes(evidence_set)[-1] == "evidence_discarded"


def test_fast_run_on_the_real_clock_matches_the_run_on_a_still_clock(
    fixture_bundle: FixtureBundle,
) -> None:
    request = build_investigation_request("5gaka", "implementation_only")
    still_clock_set = build_test_investigation_service(fixture_bundle).investigate(request)
    real_clock_service = build_test_investigation_service(
        fixture_bundle, monotonic_clock=time.monotonic
    )

    real_clock_set = real_clock_service.investigate(request)

    assert real_clock_set.result_sha256 == still_clock_set.result_sha256
    assert real_clock_set.stop_reason is StopReason.SUFFICIENT
