"""Relevance changes presentation and one sourced search, while needs keep their basis."""

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.adapters.lexical.bm25_index import Bm25LexicalIndex
from cve_kgrag.application.decision_path_audit import audit_decision_path
from cve_kgrag.application.trajectory_replay import ReplayCompleted, replay_evidence_set
from cve_kgrag.domain.investigation import NeedOutcome, StopReason
from cve_kgrag.domain.investigation_validation import validate_knowledge_evidence_set
from cve_kgrag.domain.planning import ModelReply
from cve_kgrag.domain.relevance import RelevanceLabel
from cve_kgrag.domain.validation import EvidenceValidationError
from cve_kgrag.interfaces.investigation_summary import render_investigation_summary
from tests.support.clocks import SteppingClock
from tests.support.fakes import SlowRetriever
from tests.support.investigation import (
    build_investigation_request,
    build_test_deployment,
    build_test_investigation_service,
    reseal_evidence_set,
    update_trajectory,
)
from tests.support.planners import UNAVAILABLE_REPLY, ScriptedModelPort, build_text_reply
from tests.support.relevance import (
    NEW_CVE_ID,
    QUESTION,
    build_assessment_reply,
    build_loop_model,
    build_refinement_proposal,
    build_relevance_bundle,
    run_relevance_loop,
)


@pytest.fixture
def relevance_bundle(fixture_bundle: FixtureBundle) -> FixtureBundle:
    return build_relevance_bundle(fixture_bundle)


def test_relevant_round_two_candidate_precedes_noise_inside_the_final_cap(
    relevance_bundle: FixtureBundle,
) -> None:
    # Arrange
    request = build_investigation_request(QUESTION, "implementation_only")
    model = build_loop_model(relevance_bundle, request)
    service = build_test_investigation_service(relevance_bundle, model_port=model)

    # Act
    evidence_set = service.investigate(request)
    summary = render_investigation_summary(evidence_set)

    # Assert
    assert len(evidence_set.implementation_candidates) == 20
    assert evidence_set.implementation_candidates[1].candidate.record.cve_id == NEW_CVE_ID
    assert evidence_set.implementation_candidates[1].relevance_label is RelevanceLabel.RELEVANT
    assert evidence_set.implementation_candidates[2].relevance_label is RelevanceLabel.CANNOT_TELL
    assert len(model.assessment_inputs) == 2
    assert len(model.assessment_inputs[1].candidates) == 1
    assert evidence_set.trajectory.budget_used.rounds == 2
    assert evidence_set.stop_reason is StopReason.NEEDS_UNMET
    assert evidence_set.status.value == "partial"
    assert evidence_set.coverage.needs[0].outcome is NeedOutcome.MATCHES_UNASSESSED
    assert "not assessed" not in summary
    assert (
        summary.index("Relevant:") < summary.index("Cannot tell:") < summary.index("Not relevant:")
    )
    assert "The model assessed the candidates' relevance;" in summary
    assert any(warning.code == "answer_truncated" for warning in evidence_set.warnings)


@pytest.mark.parametrize(
    ("query", "component", "expected_issue", "expected_rounds"),
    [
        ("sourced component", QUESTION, None, 2),
        ("inventedterm", QUESTION, "unsourced_term:inventedterm", 1),
        ("sourced component", "imaginary component", "component_outside_question", 1),
        (QUESTION, QUESTION, None, 1),
    ],
    ids=[
        "candidate_product_accepted",
        "nowhere_term_rejected",
        "foreign_gap_rejected",
        "repeat_rejected",
    ],
)
def test_only_a_question_gap_and_sourced_unrepeated_search_execute(
    relevance_bundle: FixtureBundle,
    query: str,
    component: str,
    expected_issue: str | None,
    expected_rounds: int,
) -> None:
    # Arrange
    request = build_investigation_request(QUESTION, "implementation_only")
    labels = ("not_relevant",) * 20
    reply = build_assessment_reply(
        request,
        relevance_bundle.records[:20],
        labels,
        **build_refinement_proposal(query, component),
    )
    model = ScriptedModelPort([], assessment_replies=[reply, UNAVAILABLE_REPLY])
    service = build_test_investigation_service(relevance_bundle, model_port=model)

    # Act
    evidence_set = service.investigate(request)

    # Assert
    assessment = evidence_set.trajectory.rounds[0].relevance_assessment
    assert assessment is not None
    assert evidence_set.trajectory.budget_used.rounds == expected_rounds
    if expected_issue is not None:
        assert expected_issue in assessment.issues
    if expected_rounds == 2:
        assert assessment.term_sources[0].cve_id == "CVE-9999-0100"
        assert assessment.term_sources[0].field == "product"
    if query == QUESTION:
        assert assessment.rejections[0].code.value == "repeated_call"


@pytest.mark.parametrize(
    "reply",
    [UNAVAILABLE_REPLY, build_text_reply("not json"), build_text_reply("[" * 1100 + "]" * 1100)],
    ids=["failed", "malformed", "excessive_nesting"],
)
def test_assessor_failure_keeps_every_round_one_candidate(
    relevance_bundle: FixtureBundle,
    reply: ModelReply,
) -> None:
    # Arrange
    request = build_investigation_request(QUESTION, "implementation_only")
    model = ScriptedModelPort([], assessment_replies=[reply])
    service = build_test_investigation_service(relevance_bundle, model_port=model)
    baseline = build_test_investigation_service(relevance_bundle).investigate(request)

    # Act
    evidence_set = service.investigate(request)

    # Assert
    assert evidence_set.implementation_candidates == baseline.implementation_candidates
    assert evidence_set.coverage.needs == baseline.coverage.needs
    assert evidence_set.stop_reason == baseline.stop_reason
    assessment = evidence_set.trajectory.rounds[0].relevance_assessment
    assert assessment is not None and assessment.issues
    assert evidence_set.trajectory.budget_used.rounds == 1


@pytest.mark.parametrize("retrieval_seconds", [2.0, 5.0], ids=["both_fit", "second_late"])
def test_both_assessor_calls_share_the_existing_deadline(
    relevance_bundle: FixtureBundle,
    retrieval_seconds: float,
) -> None:
    # Arrange
    clock = SteppingClock()
    request = build_investigation_request(
        QUESTION, "implementation_only", budget={"max_wall_time_seconds": 15}
    )
    model = build_loop_model(relevance_bundle, request)
    model.clock = clock
    model.seconds_per_call = 4
    lexical = SlowRetriever(Bm25LexicalIndex(relevance_bundle.records), clock, retrieval_seconds)
    service = build_test_investigation_service(
        relevance_bundle,
        model_port=model,
        monotonic_clock=clock.read,
        lexical_retriever=lexical,
    )
    deployment = build_test_deployment(relevance_bundle)

    # Act
    evidence_set = service.investigate(request)
    replay = replay_evidence_set(evidence_set, deployment)

    # Assert
    assert len(model.assessment_inputs) == 2
    assert model.timeouts == ([5, 5] if retrieval_seconds == 2 else [5, 1])
    assert evidence_set.trajectory.budget_used.planner_calls == 2
    assessment = evidence_set.trajectory.rounds[1].relevance_assessment
    assert assessment is not None
    assert assessment.deadline == (None if retrieval_seconds == 2 else "at_finish")
    assert evidence_set.stop_reason == (
        StopReason.NEEDS_UNMET if retrieval_seconds == 2 else StopReason.BUDGET_EXHAUSTED
    )
    assert replay == ReplayCompleted(())


def test_recorded_replies_reproduce_the_relevance_loop(relevance_bundle: FixtureBundle) -> None:
    # Arrange
    evidence_set = run_relevance_loop(relevance_bundle)
    deployment = build_test_deployment(relevance_bundle)

    # Act
    replay = replay_evidence_set(evidence_set, deployment)

    # Assert
    assert replay == ReplayCompleted(())


@pytest.mark.parametrize("forgery", ["order", "term", "third_round"])
def test_validator_rejects_forged_relevance_order_sources_and_third_round(
    relevance_bundle: FixtureBundle,
    forgery: str,
) -> None:
    # Arrange
    evidence_set = run_relevance_loop(relevance_bundle)
    deployment = build_test_deployment(relevance_bundle)
    if forgery == "order":
        candidates = list(evidence_set.implementation_candidates)
        candidates[0], candidates[-1] = candidates[-1], candidates[0]
        for position, candidate in enumerate(candidates):
            candidates[position] = candidate.model_copy(update={"rank": position + 1})
        forged = reseal_evidence_set(evidence_set, implementation_candidates=tuple(candidates))
    elif forgery == "term":
        rounds = list(evidence_set.trajectory.rounds)
        assessment = rounds[0].relevance_assessment
        assert assessment is not None and assessment.accepted_search is not None
        assessment = assessment.model_copy(
            update={
                "accepted_search": assessment.accepted_search.model_copy(
                    update={"query": "invented"}
                )
            }
        )
        rounds[0] = rounds[0].model_copy(update={"relevance_assessment": assessment})
        forged = update_trajectory(evidence_set, rounds=tuple(rounds))
    else:
        third = evidence_set.trajectory.rounds[-1].model_copy(update={"round_number": 3})
        forged = update_trajectory(evidence_set, rounds=(*evidence_set.trajectory.rounds, third))

    # Act / Assert
    with pytest.raises(EvidenceValidationError):
        validate_knowledge_evidence_set(
            forged,
            deployment.pinned_fight_snapshot,
            deployment.evidence_catalog,
            evidence_set.source_capabilities,
        )


def test_audit_rejects_a_rewritten_gate_verdict(relevance_bundle: FixtureBundle) -> None:
    # Arrange
    evidence_set = run_relevance_loop(relevance_bundle)
    deployment = build_test_deployment(relevance_bundle)
    rounds = list(evidence_set.trajectory.rounds)
    assessment = rounds[0].relevance_assessment
    assert assessment is not None
    rounds[0] = rounds[0].model_copy(
        update={"relevance_assessment": assessment.model_copy(update={"issues": ("forged",)})}
    )
    forged = update_trajectory(evidence_set, rounds=tuple(rounds))

    # Act / Assert
    with pytest.raises(EvidenceValidationError, match="parsed and gated"):
        audit_decision_path(forged, deployment.topic_registry, deployment.evidence_catalog)


def test_unassessed_candidates_follow_every_label_group_in_their_existing_order(
    relevance_bundle: FixtureBundle,
) -> None:
    # Arrange
    request = build_investigation_request(QUESTION, "implementation_only")
    baseline = build_test_investigation_service(relevance_bundle).investigate(request)
    reply = build_assessment_reply(
        request,
        relevance_bundle.records[:20],
        ("invalid", "not_relevant", "cannot_tell", "relevant") + ("invalid",) * 16,
    )
    model = ScriptedModelPort([], assessment_replies=[reply])
    service = build_test_investigation_service(relevance_bundle, model_port=model)

    # Act
    evidence_set = service.investigate(request)

    # Assert
    candidate_ids = []
    for candidate in evidence_set.implementation_candidates:
        candidate_ids.append(candidate.candidate.record.cve_id)
    assert candidate_ids[:4] == ["CVE-9999-0103", "CVE-9999-0102", "CVE-9999-0101", "CVE-9999-0100"]
    assert evidence_set.implementation_candidates[3].relevance_label is None
    baseline_tail = []
    for candidate in baseline.implementation_candidates[4:]:
        baseline_tail.append(candidate.candidate.record.cve_id)
    assert candidate_ids[4:] == baseline_tail
