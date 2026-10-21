"""Runs are reproducible: equal requests over equal data give byte-identical sets, timing
never changes the hash, and replay runs the controller again for a set's request, with its
recorded model replies and deadline point put back, and names every recorded part that
differs from the set it seals now. So a step summary or an answer rewritten over a real
response hash is caught, a source that answers differently now changes the stop, rounds
and transitions replay reports, and a replay that runs out of time says so."""

import threading
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any, Literal

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import (
    FixtureBundle,
    default_fixture_dir,
    load_fixture_bundle,
)
from cve_kgrag.adapters.lexical.bm25_index import Bm25LexicalIndex
from cve_kgrag.application.investigation_deployment import InvestigationDeployment
from cve_kgrag.application.trajectory_replay import (
    ReplayCompleted,
    ReplayDifference,
    ReplayTimedOut,
    replay_evidence_set,
)
from cve_kgrag.composition import build_evidence_catalog, build_investigation_service
from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.investigation import (
    InvestigationRequest,
    InvestigationWarning,
    InvestigationWarningCode,
    KnowledgeEvidenceSet,
    PlannerOutcome,
    StepAdmission,
    StopReason,
    derive_investigation_id,
)
from cve_kgrag.domain.investigation_validation import UNCONFIGURED_SEMANTIC_WARNING
from cve_kgrag.domain.taxonomy import ResultStatus
from cve_kgrag.domain.threat_context import KnownFightSnapshot
from cve_kgrag.domain.topic_context import (
    KnowledgeSource,
    SourceOutcome,
    TopicContextWarning,
    TopicContextWarningCode,
)
from cve_kgrag.topics.registry import TopicRegistry
from tests.support.builders import build_bundle_with
from tests.support.clocks import (
    LATE_START_SECONDS,
    ONE_SECOND_RUN_REAL_SECONDS,
    LateStartClock,
    SteppingClock,
)
from tests.support.fakes import (
    BlockingRetriever,
    InventingRetriever,
    SlowRetriever,
)
from tests.support.investigation import (
    ONE_SECOND_REQUEST,
    build_blocking_investigation_service,
    build_deadline_nearing_service,
    build_investigation_request,
    build_test_deployment,
    build_test_investigation_service,
    choose_fight_source,
    label_row,
    load_gold_rows,
    reseal_evidence_set,
    rewrite_step,
    verify_as_sealed,
)
from tests.support.investigation_runs import (
    build_semantic_hit_retriever,
    investigate,
    investigate_with_model_replies,
    run_cve_under_protocol_scope,
    run_exact_id,
    run_five_g_aka,
    run_five_g_aka_mixed,
    run_model_accepted,
    run_model_low_signal_search,
    run_model_refinement_unavailable,
    run_model_rejected,
    run_model_reply_after_deadline,
    run_model_skipped_at_deadline,
    run_model_unavailable,
    run_over_the_byte_cap,
    run_policy_plan_over_budget,
    run_semantic_hit,
    run_with_invalid_evidence,
)
from tests.support.planners import BlockingModelPort, ScriptedModelPort, build_plan_reply

# The deployment a set was produced on and is replayed against: the packaged one, one whose
# pinned FiGHT backend is down, one whose lexical channel invents a record, or one with a
# semantic channel that matches CVE-9999-0003.
Deployment = Literal["packaged", "failing", "inventing", "semantic"]
Run = Callable[[FixtureBundle], KnowledgeEvidenceSet]
REPLAYED_REQUESTS = [
    InvestigationRequest(query="5gaka", scope="protocol_context_only"),
    InvestigationRequest(query="5gaka", scope="implementation_only"),
    InvestigationRequest(query="CVE-9999-4242 AUSF resynchronization crash", scope="mixed"),
]
REPLAYED_IDS = ["protocol_5gaka", "impl_5gaka_refines", "unknown_id_residual_mixed"]
GOLD_ROWS = load_gold_rows()
FORGED_SHA256 = "f" * 64
# One byte over the server's byte cap: a response this size is discarded whatever the run
# admitted before it.
OVER_THE_SERVER_BYTE_CAP = 200_001
NO_DIFFERENCE = ReplayCompleted(())


def read_later_clock() -> datetime:
    return datetime(2027, 1, 1, tzinfo=UTC)


def build_replay_deployment(
    fixture_bundle: FixtureBundle, deployment: Deployment
) -> InvestigationDeployment:
    if deployment == "inventing":
        return build_test_deployment(fixture_bundle, lexical_retriever=InventingRetriever())
    if deployment == "semantic":
        return build_test_deployment(
            fixture_bundle, semantic_retriever=build_semantic_hit_retriever()
        )
    return build_test_deployment(fixture_bundle, fight=deployment)


def build_bundle_matching_zzqx(fixture_bundle: FixtureBundle) -> FixtureBundle:
    """``fixture_bundle`` plus a record whose description holds ``zzqx``, a term no fixture
    record holds."""
    return build_bundle_with(fixture_bundle, "CVE-9999-0712", "[SYNTHETIC] zzqx parser crash.")


def build_bundle_with_more_five_g_aka_records(fixture_bundle: FixtureBundle) -> FixtureBundle:
    """``fixture_bundle`` plus four more 5G-AKA records, so a ``5G-AKA`` search's response is
    about twice the size."""
    bigger_bundle = fixture_bundle
    for record_number in range(4):
        bigger_bundle = build_bundle_with(
            bigger_bundle,
            f"CVE-9999-072{record_number}",
            f"[SYNTHETIC] 5G-AKA authentication vector flaw {record_number} in the AUSF.",
        )
    return bigger_bundle


def run_protocol_context(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    return build_test_investigation_service(fixture_bundle).investigate(REPLAYED_REQUESTS[0])


def run_refinement(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    return build_test_investigation_service(fixture_bundle).investigate(REPLAYED_REQUESTS[1])


def run_unknown_id_residual(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    return build_test_investigation_service(fixture_bundle).investigate(REPLAYED_REQUESTS[2])


def run_dropping_an_unrelated_candidate(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """``heap overflow`` finds a CVE unrelated to the topic, which the answer drops."""
    return investigate(fixture_bundle, "5gaka heap overflow", "implementation_only")


def run_truncating_the_answer(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """Under a result cap of one, a model plan's lookup and search find two CVEs, and the
    merged answer keeps one."""
    return investigate_with_model_replies(
        fixture_bundle,
        build_investigation_request(
            "CVE-9999-0004 5G-AKA", "implementation_only", budget={"max_results_per_call": 1}
        ),
        build_plan_reply(
            {"tool": "cve_exact_lookup", "cve_ids": ["CVE-9999-0004"]},
            {"tool": "cve_search", "query": "5g aka"},
        ),
    )


def run_past_the_deadline(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """The one search lands after the deadline, so it is discarded."""
    clock = SteppingClock()
    slow_lexical = SlowRetriever(Bm25LexicalIndex(fixture_bundle.records), clock, seconds=31)
    service = build_test_investigation_service(
        fixture_bundle, monotonic_clock=clock.read, lexical_retriever=slow_lexical
    )
    return service.investigate(build_investigation_request("5gaka", "implementation_only"))


def run_deadline_before_the_refinement_round(
    fixture_bundle: FixtureBundle,
) -> KnowledgeEvidenceSet:
    """Round 1's search lands in time, and the deterministic round 2 is planned past the
    deadline, so it runs nothing."""
    service = build_deadline_nearing_service(fixture_bundle)
    return service.investigate(build_investigation_request("5gaka", "implementation_only"))


def run_deadline_before_the_second_step(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """A model plan of two searches whose first lands in time; the second never starts."""
    model_port = ScriptedModelPort(
        [
            build_plan_reply(
                {"tool": "cve_search", "query": "5g aka"},
                {"tool": "cve_search", "query": "ausf suci"},
            )
        ]
    )
    service = build_deadline_nearing_service(fixture_bundle, model_port)
    return service.investigate(build_investigation_request("5G-AKA", "implementation_only"))


def run_naming_a_product(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """A named product adds its unknown applicability and warning."""
    return investigate(
        fixture_bundle, "5G-AKA", "implementation_only", filters={"products": ["f5gc"]}
    )


def run_with_failing_fight(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """The pinned FiGHT backend is down, so the topic step reports it unavailable."""
    service = build_test_investigation_service(fixture_bundle, fight="failing")
    return service.investigate(REPLAYED_REQUESTS[0])


def run_model_search_for_zzqx(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """One round whose model plan, ``cve_search("zzqx")``, finds what the fixture holds."""
    return investigate_with_model_replies(
        fixture_bundle,
        build_investigation_request("zzqx", "implementation_only"),
        build_plan_reply({"tool": "cve_search", "query": "zzqx"}),
    )


@pytest.fixture(scope="module")
def timed_out_step_set() -> Iterator[KnowledgeEvidenceSet]:
    """A genuine set whose one lexical search never returned before the one-second deadline;
    immutable, so it is built once per module."""
    release = threading.Event()
    service = build_blocking_investigation_service(
        load_fixture_bundle(default_fixture_dir()), "lexical", release
    )
    yield service.investigate(ONE_SECOND_REQUEST)
    release.set()


@pytest.fixture(scope="module")
def timed_out_planner_set() -> Iterator[KnowledgeEvidenceSet]:
    """A genuine set whose round-1 planner never replied before the one-second deadline."""
    release = threading.Event()
    service = build_test_investigation_service(
        load_fixture_bundle(default_fixture_dir()),
        model_port=BlockingModelPort(release),
        monotonic_clock=LateStartClock(LATE_START_SECONDS).read,
    )
    yield service.investigate(ONE_SECOND_REQUEST)
    release.set()


def rewrite_answer_warning(
    evidence_set: KnowledgeEvidenceSet, code: InvestigationWarningCode, subject: str | None
) -> KnowledgeEvidenceSet:
    """``evidence_set`` resealed with the ``code`` warning given ``subject``, removed when
    ``subject`` is ``None``, or appended last when the set has none."""
    warnings: list[InvestigationWarning] = []
    has_rewritten = False
    for warning in evidence_set.warnings:
        if warning.code is not code:
            warnings.append(warning)
            continue
        has_rewritten = True
        if subject is not None:
            warnings.append(warning.model_copy(update={"subject": subject}))
    if not has_rewritten and subject is not None:
        warnings.append(InvestigationWarning(code=code, subject=subject))
    return reseal_evidence_set(evidence_set, warnings=tuple(warnings))


def rewrite_a_backend_request(
    evidence_set: KnowledgeEvidenceSet, request_position: int, **changes: str | int
) -> KnowledgeEvidenceSet:
    """``evidence_set`` resealed with one of its first step's backend requests rewritten."""
    backend_requests = list(evidence_set.trajectory.steps[0].backend_requests)
    backend_requests[request_position] = backend_requests[request_position].model_copy(
        update=changes
    )
    return rewrite_step(evidence_set, 1, backend_requests=tuple(backend_requests))


@pytest.mark.parametrize("request_model", REPLAYED_REQUESTS, ids=REPLAYED_IDS)
def test_independent_services_return_byte_identical_sets(
    fixture_bundle: FixtureBundle, request_model: InvestigationRequest
) -> None:
    first_set = build_test_investigation_service(fixture_bundle).investigate(request_model)
    second_set = build_test_investigation_service(fixture_bundle).investigate(request_model)

    assert first_set.model_dump_json() == second_set.model_dump_json()


def test_start_time_and_speed_never_change_the_result_hash(fixture_bundle: FixtureBundle) -> None:
    request = REPLAYED_REQUESTS[1]
    later_service = build_investigation_service(
        fixture_bundle,
        wall_clock=read_later_clock,
        monotonic_clock=SteppingClock(seconds_per_read=0.25).read,
    )

    fixed_set = build_test_investigation_service(fixture_bundle).investigate(request)
    later_set = later_service.investigate(request)

    assert later_set.timings != fixed_set.timings
    assert later_set.investigation_id == fixed_set.investigation_id
    assert later_set.result_sha256 == fixed_set.result_sha256


@pytest.mark.parametrize(
    ("run", "deployment"),
    [
        (run_protocol_context, "packaged"),
        (run_refinement, "packaged"),
        (run_unknown_id_residual, "packaged"),
        (run_dropping_an_unrelated_candidate, "packaged"),
        (run_truncating_the_answer, "packaged"),
        (run_over_the_byte_cap, "packaged"),
        (run_naming_a_product, "packaged"),
        (run_cve_under_protocol_scope, "packaged"),
        (run_policy_plan_over_budget, "packaged"),
        (run_with_invalid_evidence, "inventing"),
        (run_with_failing_fight, "failing"),
        (run_semantic_hit, "semantic"),
        (run_model_accepted, "packaged"),
        (run_model_low_signal_search, "packaged"),
        (run_model_rejected, "packaged"),
        (run_model_unavailable, "packaged"),
        (run_model_refinement_unavailable, "packaged"),
        (run_past_the_deadline, "packaged"),
        (run_deadline_before_the_refinement_round, "packaged"),
        (run_deadline_before_the_second_step, "packaged"),
        (run_model_reply_after_deadline, "packaged"),
        (run_model_skipped_at_deadline, "packaged"),
    ],
    ids=[
        "protocol_5gaka",
        "impl_5gaka_refines",
        "unknown_id_residual_mixed",
        "unrelated_candidate_dropped",
        "answer_truncated",
        "discarded_over_the_byte_cap",
        "named_product",
        "interpretation_stop",
        "policy_plan_over_budget",
        "invalid_evidence",
        "fight_backend_down",
        "semantic_hit",
        "model_accepted",
        "model_search_with_a_low_signal_word",
        "model_rejected",
        "model_unavailable",
        "model_refinement_unavailable",
        "discarded_after_the_deadline",
        "deadline_before_the_refinement_round",
        "deadline_before_the_second_step",
        "model_reply_after_deadline",
        "model_skipped_at_deadline",
    ],
)
def test_replay_of_a_genuine_set_over_unchanged_data_finds_no_difference(
    fixture_bundle: FixtureBundle, run: Run, deployment: Deployment
) -> None:
    evidence_set = run(fixture_bundle)

    replay_outcome = replay_evidence_set(
        evidence_set, build_replay_deployment(fixture_bundle, deployment)
    )

    assert replay_outcome == NO_DIFFERENCE


@pytest.mark.parametrize("row", GOLD_ROWS, ids=label_row)
def test_replay_of_every_gold_trajectory_finds_no_difference(
    fixture_bundle: FixtureBundle, row: dict[str, Any]
) -> None:
    fight = row["sources"]["mitre_fight"]
    service = build_test_investigation_service(fixture_bundle, fight=fight)
    evidence_set = service.investigate(InvestigationRequest.model_validate(row["request"]))

    replay_outcome = replay_evidence_set(
        evidence_set, build_test_deployment(fixture_bundle, fight=fight)
    )

    assert replay_outcome == NO_DIFFERENCE


def test_replay_of_a_timed_out_planner_finds_no_difference(
    fixture_bundle: FixtureBundle, timed_out_planner_set: KnowledgeEvidenceSet
) -> None:
    """The planner was abandoned with no reply, so the replay's planner is never asked."""
    assert timed_out_planner_set.trajectory.rounds[0].planner_outcome is (
        PlannerOutcome.MODEL_TIMED_OUT
    )

    replay_outcome = replay_evidence_set(
        timed_out_planner_set, build_test_deployment(fixture_bundle)
    )

    assert replay_outcome == NO_DIFFERENCE


def test_replay_of_a_timed_out_step_never_reissues_the_abandoned_call(
    fixture_bundle: FixtureBundle,
    timed_out_step_set: KnowledgeEvidenceSet,
    blocked_call_release: threading.Event,
) -> None:
    """The recorded deadline fell while the call ran, so the replay's call runner finds it
    reached there and never starts the call: replaying against a backend that still blocks
    returns at once, with nothing to report."""
    assert timed_out_step_set.trajectory.steps[0].admission is StepAdmission.TIMED_OUT
    blocking_deployment = build_test_deployment(
        fixture_bundle,
        monotonic_clock=time.monotonic,
        lexical_retriever=BlockingRetriever(blocked_call_release),
    )

    real_started_at = time.monotonic()
    blocking_outcome = replay_evidence_set(timed_out_step_set, blocking_deployment)
    real_elapsed_seconds = time.monotonic() - real_started_at
    packaged_outcome = replay_evidence_set(
        timed_out_step_set, build_test_deployment(fixture_bundle)
    )

    assert real_elapsed_seconds < ONE_SECOND_REQUEST.budget.max_wall_time_seconds
    assert (blocking_outcome, packaged_outcome) == (NO_DIFFERENCE, NO_DIFFERENCE)


def test_replay_against_a_backend_that_never_returns_times_out_within_the_cap(
    fixture_bundle: FixtureBundle, blocked_call_release: threading.Event
) -> None:
    """The reviewer's repro: a genuine set under a one-second cap, replayed against a
    deployment whose lexical channel blocks. The replay's call runner abandons the call at
    the cap, and the replay reports that it timed out instead of comparing anything."""
    evidence_set = build_test_investigation_service(fixture_bundle).investigate(ONE_SECOND_REQUEST)
    blocking_deployment = build_test_deployment(
        fixture_bundle,
        monotonic_clock=time.monotonic,
        lexical_retriever=BlockingRetriever(blocked_call_release),
    )

    real_started_at = time.monotonic()
    replay_outcome = replay_evidence_set(evidence_set, blocking_deployment)
    real_elapsed_seconds = time.monotonic() - real_started_at

    assert replay_outcome == ReplayTimedOut()
    assert real_elapsed_seconds < ONE_SECOND_RUN_REAL_SECONDS


def test_replay_of_a_late_result_against_a_backend_that_never_returns_times_out(
    fixture_bundle: FixtureBundle, blocked_call_release: threading.Event
) -> None:
    """The recorded search finished after the one-second deadline and was discarded; the
    replay's own call never returns, so the replay finds the deadline during the call, not
    at the recorded finish, and has compared nothing."""
    clock = SteppingClock()
    late_lexical = SlowRetriever(Bm25LexicalIndex(fixture_bundle.records), clock, seconds=1.5)
    evidence_set = build_test_investigation_service(
        fixture_bundle, monotonic_clock=clock.read, lexical_retriever=late_lexical
    ).investigate(ONE_SECOND_REQUEST)
    blocking_deployment = build_test_deployment(
        fixture_bundle,
        monotonic_clock=time.monotonic,
        lexical_retriever=BlockingRetriever(blocked_call_release),
    )

    real_started_at = time.monotonic()
    replay_outcome = replay_evidence_set(evidence_set, blocking_deployment)
    real_elapsed_seconds = time.monotonic() - real_started_at

    assert evidence_set.trajectory.steps[0].admission is StepAdmission.DISCARDED_AFTER_DEADLINE
    assert replay_outcome == ReplayTimedOut()
    assert real_elapsed_seconds < ONE_SECOND_RUN_REAL_SECONDS


def test_replay_over_changed_data_names_the_step_and_answer_parts_it_changes(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_refinement(fixture_bundle)
    changed_bundle = build_bundle_with(
        fixture_bundle,
        "CVE-9999-0710",
        "[SYNTHETIC] Heap overflow while parsing 5G-AKA authentication vectors.",
    )

    replay_outcome = replay_evidence_set(evidence_set, build_test_deployment(changed_bundle))

    assert replay_outcome == ReplayCompleted(
        (
            ReplayDifference(2, "answer_ids"),
            ReplayDifference(2, "evidence_ids"),
            ReplayDifference(2, "result_sha256"),
            ReplayDifference(2, "context_bytes"),
            ReplayDifference(None, "implementation_candidates"),
            ReplayDifference(None, "claims"),
            ReplayDifference(None, "evidence"),
            ReplayDifference(None, "trajectory.evidence_ids"),
            ReplayDifference(None, "trajectory.budget_used.context_bytes"),
        )
    )


def test_replay_of_a_response_that_shrank_under_the_cap_names_the_new_stop(
    fixture_bundle: FixtureBundle,
) -> None:
    """The reviewer's repro: a ``5G-AKA`` response too big for the byte cap was discarded,
    so the run stopped ``budget_exhausted`` / ``partial`` with an ``evidence_discarded``
    warning. The deployment's source now answers in fewer bytes than the cap, so a run
    today admits it and stops ``sufficient`` / ``ok``; replay names every part of that."""
    bigger_bundle = build_bundle_with_more_five_g_aka_records(fixture_bundle)
    current_bytes = run_five_g_aka(fixture_bundle).trajectory.steps[0].context_bytes
    request = build_investigation_request(
        "5G-AKA", "implementation_only", budget={"max_context_bytes": current_bytes + 1000}
    )
    evidence_set = build_test_investigation_service(bigger_bundle).investigate(request)
    assert evidence_set.trajectory.steps[0].context_bytes > current_bytes + 1000
    assert (evidence_set.stop_reason, evidence_set.status) == (
        StopReason.BUDGET_EXHAUSTED,
        ResultStatus.PARTIAL,
    )

    replay_outcome = replay_evidence_set(evidence_set, build_test_deployment(fixture_bundle))

    assert replay_outcome == ReplayCompleted(
        (
            ReplayDifference(1, "admission"),
            ReplayDifference(1, "answer_ids"),
            ReplayDifference(1, "evidence_ids"),
            ReplayDifference(1, "result_sha256"),
            ReplayDifference(1, "context_bytes"),
            ReplayDifference(None, "status"),
            ReplayDifference(None, "stop_reason"),
            ReplayDifference(None, "implementation_candidates"),
            ReplayDifference(None, "claims"),
            ReplayDifference(None, "evidence"),
            ReplayDifference(None, "warnings"),
            ReplayDifference(None, "trajectory.transitions"),
            ReplayDifference(None, "trajectory.evidence_ids"),
            ReplayDifference(None, "trajectory.budget_used.context_bytes"),
            ReplayDifference(None, "trajectory.budget_used.breach"),
            ReplayDifference(None, "coverage.source_outcomes"),
            ReplayDifference(None, "coverage.basis"),
        )
    )


def test_replay_whose_first_round_now_answers_runs_no_refinement_round(
    fixture_bundle: FixtureBundle,
) -> None:
    """Round 1's literal search for ``5gaka`` found nothing, so round 2 explored the topic.
    The source now holds a record naming ``5gaka``, so round 1 answers and the replayed run
    stops there: replay names the step only the record holds, the rounds, the transitions
    and ``refinement_applied``, rather than running the recorded round 2 again."""
    evidence_set = run_refinement(fixture_bundle)
    changed_bundle = build_bundle_with(
        fixture_bundle, "CVE-9999-0711", "[SYNTHETIC] 5gaka handshake crash in the AUSF."
    )

    replay_outcome = replay_evidence_set(evidence_set, build_test_deployment(changed_bundle))

    assert replay_outcome == ReplayCompleted(
        (
            ReplayDifference(1, "status"),
            ReplayDifference(1, "source_outcomes"),
            ReplayDifference(1, "answer_ids"),
            ReplayDifference(1, "evidence_ids"),
            ReplayDifference(1, "result_sha256"),
            ReplayDifference(1, "context_bytes"),
            ReplayDifference(2, "step"),
            ReplayDifference(None, "implementation_candidates"),
            ReplayDifference(None, "claims"),
            ReplayDifference(None, "evidence"),
            ReplayDifference(None, "trajectory.transitions"),
            ReplayDifference(None, "trajectory.rounds"),
            ReplayDifference(None, "trajectory.evidence_ids"),
            ReplayDifference(None, "trajectory.budget_used.rounds"),
            ReplayDifference(None, "trajectory.budget_used.tool_calls"),
            ReplayDifference(None, "trajectory.budget_used.context_bytes"),
            ReplayDifference(None, "coverage.refinement_applied"),
        )
    )


def test_replay_that_stops_before_the_recorded_deadline_point_names_the_breach(
    fixture_bundle: FixtureBundle,
) -> None:
    """The recorded run found the deadline when it came to plan round 2. The source now
    answers round 1, so the replayed run stops before that point: the deadline is never put
    back, and replay names the stop, the breach and the rounds the deadline gave."""
    evidence_set = run_deadline_before_the_refinement_round(fixture_bundle)
    changed_bundle = build_bundle_with(
        fixture_bundle, "CVE-9999-0711", "[SYNTHETIC] 5gaka handshake crash in the AUSF."
    )

    replay_outcome = replay_evidence_set(evidence_set, build_test_deployment(changed_bundle))

    assert replay_outcome == ReplayCompleted(
        (
            ReplayDifference(1, "status"),
            ReplayDifference(1, "source_outcomes"),
            ReplayDifference(1, "answer_ids"),
            ReplayDifference(1, "evidence_ids"),
            ReplayDifference(1, "result_sha256"),
            ReplayDifference(1, "context_bytes"),
            ReplayDifference(None, "status"),
            ReplayDifference(None, "stop_reason"),
            ReplayDifference(None, "implementation_candidates"),
            ReplayDifference(None, "claims"),
            ReplayDifference(None, "evidence"),
            ReplayDifference(None, "trajectory.transitions"),
            ReplayDifference(None, "trajectory.rounds"),
            ReplayDifference(None, "trajectory.evidence_ids"),
            ReplayDifference(None, "trajectory.budget_used.rounds"),
            ReplayDifference(None, "trajectory.budget_used.context_bytes"),
            ReplayDifference(None, "trajectory.budget_used.breach"),
            ReplayDifference(None, "coverage.source_outcomes"),
            ReplayDifference(None, "coverage.basis"),
        )
    )


def test_replay_that_no_longer_asks_for_a_recorded_reply_names_the_rounds(
    fixture_bundle: FixtureBundle,
) -> None:
    """Round 2's planner replied ``unavailable`` after round 1's model search for ``zzqx``
    found nothing. The source now holds a ``zzqx`` record, so round 1 answers and round 2's
    recorded reply is never asked for."""
    evidence_set = run_model_refinement_unavailable(fixture_bundle)
    assert len(evidence_set.trajectory.rounds) == 2

    replay_outcome = replay_evidence_set(
        evidence_set, build_test_deployment(build_bundle_matching_zzqx(fixture_bundle))
    )

    assert replay_outcome == ReplayCompleted(
        (
            ReplayDifference(1, "status"),
            ReplayDifference(1, "source_outcomes"),
            ReplayDifference(1, "answer_ids"),
            ReplayDifference(1, "evidence_ids"),
            ReplayDifference(1, "result_sha256"),
            ReplayDifference(1, "context_bytes"),
            ReplayDifference(None, "status"),
            ReplayDifference(None, "stop_reason"),
            ReplayDifference(None, "implementation_candidates"),
            ReplayDifference(None, "claims"),
            ReplayDifference(None, "evidence"),
            ReplayDifference(None, "trajectory.transitions"),
            ReplayDifference(None, "trajectory.rounds"),
            ReplayDifference(None, "trajectory.evidence_ids"),
            ReplayDifference(None, "trajectory.budget_used.rounds"),
            ReplayDifference(None, "trajectory.budget_used.planner_calls"),
            ReplayDifference(None, "trajectory.budget_used.context_bytes"),
            ReplayDifference(None, "coverage.source_outcomes"),
            ReplayDifference(None, "coverage.basis"),
        )
    )


def test_replay_that_asks_for_a_reply_the_record_lacks_names_the_rounds(
    fixture_bundle: FixtureBundle,
) -> None:
    """Round 1's model search for ``zzqx`` answered, so no round 2 was planned. The source no
    longer holds that record, so the replayed run plans round 2, whose planner the record
    holds no reply for: it is told ``unavailable``, and the round differs."""
    evidence_set = run_model_search_for_zzqx(build_bundle_matching_zzqx(fixture_bundle))
    assert len(evidence_set.trajectory.rounds) == 1

    replay_outcome = replay_evidence_set(evidence_set, build_test_deployment(fixture_bundle))

    assert replay_outcome == ReplayCompleted(
        (
            ReplayDifference(1, "status"),
            ReplayDifference(1, "source_outcomes"),
            ReplayDifference(1, "answer_ids"),
            ReplayDifference(1, "evidence_ids"),
            ReplayDifference(1, "result_sha256"),
            ReplayDifference(1, "context_bytes"),
            ReplayDifference(None, "status"),
            ReplayDifference(None, "stop_reason"),
            ReplayDifference(None, "implementation_candidates"),
            ReplayDifference(None, "claims"),
            ReplayDifference(None, "evidence"),
            ReplayDifference(None, "trajectory.transitions"),
            ReplayDifference(None, "trajectory.rounds"),
            ReplayDifference(None, "trajectory.evidence_ids"),
            ReplayDifference(None, "trajectory.budget_used.rounds"),
            ReplayDifference(None, "trajectory.budget_used.planner_calls"),
            ReplayDifference(None, "trajectory.budget_used.context_bytes"),
            ReplayDifference(None, "coverage.source_outcomes"),
            ReplayDifference(None, "coverage.basis"),
        )
    )


def test_replay_names_a_topic_step_whose_template_search_was_rewritten(
    fixture_bundle: FixtureBundle,
) -> None:
    """A topic step's first template search claims another query and limit, which the
    validator cannot check without the card."""
    evidence_set = investigate(fixture_bundle, "5gaka", "mixed", budget={"max_results_per_call": 5})
    forged_set = rewrite_a_backend_request(
        evidence_set, 1, query="anything a forger likes", limit=1
    )

    replay_outcome = replay_evidence_set(forged_set, build_test_deployment(fixture_bundle))

    assert replay_outcome == ReplayCompleted((ReplayDifference(1, "backend_requests"),))


def test_replay_names_a_responseless_step_whose_request_was_rewritten(
    fixture_bundle: FixtureBundle,
) -> None:
    """A step whose evidence failed integrity has no hash, but its request is re-derived and
    its call re-executed."""
    evidence_set = run_with_invalid_evidence(fixture_bundle)
    assert evidence_set.trajectory.steps[0].admission is StepAdmission.REJECTED_INVALID_EVIDENCE
    forged_set = rewrite_a_backend_request(evidence_set, 0, query="anything a forger likes")

    replay_outcome = replay_evidence_set(
        forged_set, build_replay_deployment(fixture_bundle, "inventing")
    )

    assert replay_outcome == ReplayCompleted((ReplayDifference(1, "backend_requests"),))


def test_failed_fight_response_relabelled_as_served_passes_the_audit_but_not_replay(
    fixture_bundle: FixtureBundle, topic_registry: TopicRegistry
) -> None:
    """The reviewer's forgery: on a deployment whose pinned FiGHT backend is down, the topic
    step keeps the failed response's real hash, while its summary and the answer are
    rewritten to the five catalog techniques a serving backend returns, and the set is
    resealed. Every part agrees with every other and with the catalog, so the validator and
    the decision-path audit accept it; only the re-run against the source contradicts it."""
    failed_set = run_with_failing_fight(fixture_bundle)
    served_set = run_protocol_context(fixture_bundle)
    assert failed_set.stop_reason is StopReason.SOURCE_UNAVAILABLE
    assert len(served_set.protocol_context) == 5
    forged_set = rewrite_step(
        served_set, 1, result_sha256=failed_set.trajectory.steps[0].result_sha256
    )
    failing_fight_source, pinned_fight_snapshot = choose_fight_source("failing")
    verify_as_sealed(
        forged_set,
        pinned_fight_snapshot,
        build_evidence_catalog(fixture_bundle, failing_fight_source),
        failed_set.source_capabilities,
        topic_registry,
    )

    replay_outcome = replay_evidence_set(
        forged_set, build_replay_deployment(fixture_bundle, "failing")
    )

    assert replay_outcome == ReplayCompleted(
        (
            ReplayDifference(1, "status"),
            ReplayDifference(1, "source_outcomes"),
            ReplayDifference(1, "topic_warnings"),
            ReplayDifference(1, "answer_ids"),
            ReplayDifference(1, "evidence_ids"),
            ReplayDifference(1, "context_bytes"),
            ReplayDifference(None, "status"),
            ReplayDifference(None, "stop_reason"),
            ReplayDifference(None, "protocol_context"),
            ReplayDifference(None, "claims"),
            ReplayDifference(None, "evidence"),
            ReplayDifference(None, "trajectory.transitions"),
            ReplayDifference(None, "trajectory.evidence_ids"),
            ReplayDifference(None, "trajectory.budget_used.context_bytes"),
            ReplayDifference(None, "coverage.source_outcomes"),
            ReplayDifference(None, "coverage.basis"),
        )
    )


def test_admitted_response_relabelled_over_the_byte_cap_passes_the_audit_but_not_replay(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
    topic_registry: TopicRegistry,
) -> None:
    """The reviewer's forgery: a real 2,513-byte response admitted under the default caps
    is recorded as 200,001 bytes discarded over the byte cap, with the ``budget_exhausted``
    stop, ``context_bytes`` breach, warning and empty answer that discard gives, and the set
    is resealed. The validator only sees that 200,001 bytes exceed the cap, and the audit
    re-derives the stop from the recorded discard, so both accept it."""
    genuine_set = run_exact_id(fixture_bundle)
    genuine_bytes = genuine_set.trajectory.steps[0].context_bytes
    assert genuine_bytes == 2513
    discarded_set = investigate(
        fixture_bundle,
        "CVE-9999-0003",
        "implementation_only",
        budget={"max_context_bytes": genuine_bytes - 1},
    )
    discarded_step = discarded_set.trajectory.steps[0].model_copy(
        update={"context_bytes": OVER_THE_SERVER_BYTE_CAP}
    )
    forged_set = reseal_evidence_set(
        discarded_set,
        request=genuine_set.request,
        investigation_id=derive_investigation_id(genuine_set.request),
        trajectory=discarded_set.trajectory.model_copy(update={"steps": (discarded_step,)}),
    )
    assert forged_set.stop_reason is StopReason.BUDGET_EXHAUSTED
    verify_as_sealed(
        forged_set,
        pinned_fight_snapshot,
        packaged_evidence_catalog,
        genuine_set.source_capabilities,
        topic_registry,
    )

    replay_outcome = replay_evidence_set(forged_set, build_test_deployment(fixture_bundle))

    assert replay_outcome == ReplayCompleted(
        (
            ReplayDifference(1, "admission"),
            ReplayDifference(1, "context_bytes"),
            ReplayDifference(None, "status"),
            ReplayDifference(None, "stop_reason"),
            ReplayDifference(None, "implementation_candidates"),
            ReplayDifference(None, "claims"),
            ReplayDifference(None, "evidence"),
            ReplayDifference(None, "warnings"),
            ReplayDifference(None, "trajectory.transitions"),
            ReplayDifference(None, "trajectory.evidence_ids"),
            ReplayDifference(None, "trajectory.budget_used.context_bytes"),
            ReplayDifference(None, "trajectory.budget_used.breach"),
            ReplayDifference(None, "coverage.source_outcomes"),
            ReplayDifference(None, "coverage.basis"),
        )
    )


@pytest.mark.parametrize(
    ("run", "field_name", "forged_value"),
    [
        (run_five_g_aka, "call_key", FORGED_SHA256),
        (run_five_g_aka, "charged_tool_calls", 2),
        (run_five_g_aka, "sources", (KnowledgeSource.MITRE_FIGHT,)),
        (run_five_g_aka, "admission", StepAdmission.DISCARDED_OVER_CONTEXT_BUDGET),
        (run_five_g_aka, "status", ResultStatus.NO_MATCH),
        (run_five_g_aka, "channels_executed", ()),
        (
            run_five_g_aka,
            "source_outcomes",
            (SourceOutcome(source=KnowledgeSource.CVE_SEARCH, status=ResultStatus.NO_MATCH),),
        ),
        (run_five_g_aka, "search_warnings", (UNCONFIGURED_SEMANTIC_WARNING,)),
        (
            run_five_g_aka_mixed,
            "topic_warnings",
            (
                TopicContextWarning(
                    code=TopicContextWarningCode.ADDITIONAL_TOPIC_NOT_EXPLORED, subject="5g-aka"
                ),
            ),
        ),
        (run_five_g_aka, "answer_ids", ("CVE-9999-0003",)),
        (run_five_g_aka, "evidence_ids", ()),
        (run_five_g_aka, "result_sha256", FORGED_SHA256),
        (run_five_g_aka, "context_bytes", 1),
    ],
    ids=[
        "call_key",
        "charged_tool_calls",
        "sources",
        "admission",
        "status",
        "channels_executed",
        "source_outcomes",
        "search_warnings",
        "topic_warnings",
        "answer_ids",
        "evidence_ids",
        "result_sha256",
        "context_bytes",
    ],
)
def test_replay_names_each_rewritten_step_field(
    fixture_bundle: FixtureBundle, run: Run, field_name: str, forged_value: Any
) -> None:
    evidence_set = run(fixture_bundle)
    forged_set = rewrite_step(evidence_set, 1, **{field_name: forged_value})

    replay_outcome = replay_evidence_set(forged_set, build_test_deployment(fixture_bundle))

    assert replay_outcome == ReplayCompleted((ReplayDifference(1, field_name),))


@pytest.mark.parametrize(
    ("run", "code", "subject"),
    [
        (
            run_dropping_an_unrelated_candidate,
            InvestigationWarningCode.UNRELATED_CANDIDATES_DROPPED,
            "2",
        ),
        (
            run_dropping_an_unrelated_candidate,
            InvestigationWarningCode.UNRELATED_CANDIDATES_DROPPED,
            None,
        ),
        (run_five_g_aka, InvestigationWarningCode.UNRELATED_CANDIDATES_DROPPED, "1"),
        (run_truncating_the_answer, InvestigationWarningCode.ANSWER_TRUNCATED, "3"),
        (run_truncating_the_answer, InvestigationWarningCode.ANSWER_TRUNCATED, None),
        (run_five_g_aka, InvestigationWarningCode.ANSWER_TRUNCATED, "1"),
    ],
    ids=[
        "dropped_count_raised",
        "dropped_warning_removed",
        "dropped_warning_invented",
        "truncated_count_raised",
        "truncated_warning_removed",
        "truncated_warning_invented",
    ],
)
def test_rewritten_drop_or_truncation_count_passes_the_audit_but_not_replay(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
    topic_registry: TopicRegistry,
    run: Run,
    code: InvestigationWarningCode,
    subject: str | None,
) -> None:
    evidence_set = run(fixture_bundle)
    forged_set = rewrite_answer_warning(evidence_set, code, subject)
    verify_as_sealed(
        forged_set,
        pinned_fight_snapshot,
        packaged_evidence_catalog,
        evidence_set.source_capabilities,
        topic_registry,
    )

    replay_outcome = replay_evidence_set(forged_set, build_test_deployment(fixture_bundle))

    assert replay_outcome == ReplayCompleted((ReplayDifference(None, "warnings"),))
