"""Evidence needs decide when an investigation stops (docs/rebuild/m7b-b-evidence-needs.md)."""

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.domain.investigation import (
    DecisionBasis,
    EvidenceNeed,
    EvidenceNeedKind,
    FightBlock,
    FightBlockReason,
    InvestigationWarningCode,
    NeedOutcome,
    StepReason,
    StopReason,
)
from cve_kgrag.domain.planning import CveSearchCall, ToolName
from cve_kgrag.domain.taxonomy import ResultStatus
from tests.support.evaluation import run_deterministically, run_with_replies
from tests.support.investigation import list_need_outcomes, list_step_reasons
from tests.support.planners import UNAVAILABLE_REPLY, build_plan_reply

SEARCH_GATEWAY = {"tool": "cve_search", "query": "zzqx gateway"}
TOPIC_5G_AKA = {"tool": "topic_context", "topic_id": "3gpp:5g-aka"}
# A severity no fixture record carries: every CVE search and topic call answers nothing.
NO_RECORD_FILTERS = {"severities": ["LOW"]}


def test_answer_beside_a_word_no_record_holds_stops_needs_unmet_and_keeps_the_answer(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_deterministically(fixture_bundle, "zzqx gateway", "implementation_only")

    assert evidence_set.stop_reason is StopReason.NEEDS_UNMET
    assert evidence_set.status is ResultStatus.PARTIAL
    assert evidence_set.implementation_candidates
    assert list_need_outcomes(evidence_set) == [
        (EvidenceNeedKind.IMPLEMENTATION_CVES, None, NeedOutcome.NOT_FOUND)
    ]


def test_open_need_without_a_policy_refinement_consults_no_model_in_round_two(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_with_replies(
        fixture_bundle,
        "5gaka zzqx gateway",
        "implementation_only",
        build_plan_reply(TOPIC_5G_AKA, {"tool": "cve_search", "query": "5gaka zzqx gateway"}),
        build_plan_reply(SEARCH_GATEWAY),
    )

    assert evidence_set.stop_reason is StopReason.NEEDS_UNMET
    assert evidence_set.coverage.basis is DecisionBasis.NO_REFINEMENT_AVAILABLE
    assert evidence_set.trajectory.budget_used.planner_calls == 1
    assert len(evidence_set.trajectory.rounds) == 1


def test_question_naming_only_a_cve_id_needs_only_that_cve(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_deterministically(fixture_bundle, "What is CVE-9999-0001", "mixed")

    assert evidence_set.stop_reason is StopReason.SUFFICIENT
    assert list_need_outcomes(evidence_set) == [
        (EvidenceNeedKind.NAMED_CVE, "CVE-9999-0001", NeedOutcome.FOUND)
    ]
    assert len(evidence_set.trajectory.rounds) == 1


def test_found_cve_id_beside_a_resolved_topic_explores_the_topic_for_its_needs(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_deterministically(fixture_bundle, "CVE-9999-0001 and 5G-AKA", "mixed")

    assert list_step_reasons(evidence_set) == [
        StepReason.QUERY_CVE_IDS,
        StepReason.TOPIC_FOR_OPEN_NEED,
    ]
    assert evidence_set.stop_reason is StopReason.SUFFICIENT
    assert list_need_outcomes(evidence_set) == [
        (EvidenceNeedKind.NAMED_CVE, "CVE-9999-0001", NeedOutcome.FOUND),
        (EvidenceNeedKind.IMPLEMENTATION_CVES, None, NeedOutcome.FOUND),
        (EvidenceNeedKind.PROTOCOL_CONTEXT, None, NeedOutcome.FOUND),
    ]


def test_mixed_free_text_naming_an_excluded_term_stops_with_protocol_context_unsupported(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_deterministically(fixture_bundle, "EPS AKA crash", "mixed")

    assert evidence_set.interpretation.fight_block == FightBlock(
        reason=FightBlockReason.EXCLUDED_TERM, subject="EPS AKA"
    )
    assert list_step_reasons(evidence_set) == [StepReason.QUERY_TERMS]
    assert evidence_set.stop_reason is StopReason.NEEDS_UNMET
    assert list_need_outcomes(evidence_set) == [
        (EvidenceNeedKind.IMPLEMENTATION_CVES, None, NeedOutcome.FOUND),
        (EvidenceNeedKind.PROTOCOL_CONTEXT, None, NeedOutcome.UNSUPPORTED),
    ]


def test_question_whether_a_product_version_is_affected_leaves_its_applicability_unknown(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_deterministically(
        fixture_bundle, "Is f5gc 1.2.3 affected", "implementation_only"
    )

    assert evidence_set.interpretation.affectedness_mentions == ("f5gc 1.2.3",)
    assert evidence_set.stop_reason is StopReason.SOURCE_UNAVAILABLE
    assert evidence_set.coverage.basis is DecisionBasis.AFFECTEDNESS_UNAVAILABLE
    assert list_need_outcomes(evidence_set) == [
        (EvidenceNeedKind.IMPLEMENTATION_CVES, None, NeedOutcome.FOUND),
        (EvidenceNeedKind.AFFECTEDNESS, "f5gc 1.2.3", NeedOutcome.SOURCE_UNAVAILABLE),
    ]
    assert evidence_set.product_applicability[0].product_kind == "product_version"
    assert any(
        warning.code is InvestigationWarningCode.APPLICABILITY_UNKNOWN
        and warning.subject == "f5gc 1.2.3"
        for warning in evidence_set.warnings
    )


def test_product_version_without_an_affectedness_word_is_a_search_not_a_need(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_deterministically(fixture_bundle, "f5gc 1.2.3 AUSF", "implementation_only")

    assert evidence_set.interpretation.affectedness_mentions == ()
    assert evidence_set.product_applicability == ()


def test_alias_spelling_no_record_holds_still_meets_the_need_through_the_topic(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_deterministically(fixture_bundle, "5gaka", "implementation_only")

    assert evidence_set.stop_reason is StopReason.SUFFICIENT
    assert evidence_set.coverage.needs == (
        EvidenceNeed(
            kind=EvidenceNeedKind.IMPLEMENTATION_CVES, subject=None, outcome=NeedOutcome.FOUND
        ),
    )


def test_version_after_a_word_no_record_names_as_a_product_is_no_affectedness_question(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_deterministically(
        fixture_bundle, "Is release 1.2.3 of f5gc affected", "implementation_only"
    )

    assert evidence_set.interpretation.affectedness_mentions == ()


def test_model_search_that_dropped_a_word_is_followed_by_the_search_of_every_term(
    fixture_bundle: FixtureBundle,
) -> None:
    """The model explores the topic and searches one of the query's four words. A filter no
    record matches leaves both without an answer, so the implementation need is open after
    round 1 and R3 searches every term."""
    evidence_set = run_with_replies(
        fixture_bundle,
        "5gaka sql injection gateway",
        "implementation_only",
        build_plan_reply(TOPIC_5G_AKA, {"tool": "cve_search", "query": "5gaka"}),
        UNAVAILABLE_REPLY,
        filters=NO_RECORD_FILTERS,
    )

    assert list_step_reasons(evidence_set) == [
        StepReason.MODEL_PROPOSAL,
        StepReason.MODEL_PROPOSAL,
        StepReason.QUERY_TERMS_FOR_OPEN_NEED,
    ]
    assert evidence_set.trajectory.steps[2].call == CveSearchCall(
        tool=ToolName.CVE_SEARCH, query="5gaka sql injection gateway"
    )
    assert evidence_set.coverage.basis is DecisionBasis.NEEDS_OPEN_AFTER_REFINEMENT
    assert list_need_outcomes(evidence_set) == [
        (EvidenceNeedKind.IMPLEMENTATION_CVES, None, NeedOutcome.NOT_FOUND)
    ]


def test_word_no_record_holds_vetoes_the_search_of_every_term(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_with_replies(
        fixture_bundle,
        "5gaka zzqx gateway",
        "implementation_only",
        build_plan_reply(TOPIC_5G_AKA, {"tool": "cve_search", "query": "zzqx"}),
        build_plan_reply(SEARCH_GATEWAY),
    )

    assert evidence_set.coverage.basis is DecisionBasis.NO_REFINEMENT_AVAILABLE
    assert len(evidence_set.trajectory.rounds) == 1
    assert evidence_set.trajectory.budget_used.planner_calls == 1
    assert list_need_outcomes(evidence_set) == [
        (EvidenceNeedKind.IMPLEMENTATION_CVES, None, NeedOutcome.NOT_FOUND)
    ]


def test_last_part_of_a_hyphenated_name_is_no_product_the_question_names(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_deterministically(
        fixture_bundle, "Is acme-f5gc 1.2.3 affected", "implementation_only"
    )

    assert evidence_set.interpretation.affectedness_mentions == ()


@pytest.mark.parametrize(
    "query",
    ["What is CVE-9999-4242", "Details of CVE-9999-4242"],
    ids=["what_is", "details_of"],
)
def test_unknown_id_beside_plain_text_ends_after_its_lookup_without_a_second_planner_call(
    fixture_bundle: FixtureBundle, query: str
) -> None:
    lookup_unknown_id = {"tool": "cve_exact_lookup", "cve_ids": ["CVE-9999-4242"]}

    evidence_set = run_with_replies(
        fixture_bundle,
        query,
        "implementation_only",
        build_plan_reply(lookup_unknown_id),
        build_plan_reply(SEARCH_GATEWAY),
    )

    assert list_step_reasons(evidence_set) == [StepReason.MODEL_PROPOSAL]
    assert evidence_set.trajectory.budget_used.planner_calls == 1
    assert evidence_set.implementation_candidates == ()
    assert evidence_set.stop_reason is StopReason.NO_EVIDENCE
    assert list_need_outcomes(evidence_set) == [
        (EvidenceNeedKind.NAMED_CVE, "CVE-9999-4242", NeedOutcome.NOT_FOUND)
    ]


def test_unknown_id_beside_a_resolved_topic_still_explores_the_topic(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_deterministically(fixture_bundle, "CVE-9999-4242 5gaka", "mixed")

    assert list_step_reasons(evidence_set) == [
        StepReason.QUERY_CVE_IDS,
        StepReason.TOPIC_AFTER_UNKNOWN_IDS,
    ]
    assert list_need_outcomes(evidence_set) == [
        (EvidenceNeedKind.NAMED_CVE, "CVE-9999-4242", NeedOutcome.NOT_FOUND),
        (EvidenceNeedKind.IMPLEMENTATION_CVES, None, NeedOutcome.FOUND),
        (EvidenceNeedKind.PROTOCOL_CONTEXT, None, NeedOutcome.FOUND),
    ]
