"""An investigation searches FiGHT with the question's own words when no topic resolved
(docs/rebuild/m7b-c-fight-direct-search.md): once per run, all of the words or none, never
past a resolved topic, an excluded term, a CVE ID or a word the registry reads alone."""

import threading
from collections.abc import Sequence

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.domain.budget import BudgetBreach
from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.investigation import (
    DecisionBasis,
    EvidenceNeedKind,
    FightBackendRequest,
    FightBlock,
    FightBlockReason,
    InvestigationWarning,
    KnowledgeEvidenceSet,
    NeedOutcome,
    PlannerOutcome,
    StepAdmission,
    StepReason,
    StopReason,
)
from cve_kgrag.domain.planning import PlanRejection, PlanRejectionCode, QueryIntent, ToolName
from cve_kgrag.domain.taxonomy import ResultStatus
from cve_kgrag.domain.threat_context import KnownFightSnapshot
from cve_kgrag.domain.topic_context import (
    KnowledgeSource,
    TopicContextWarning,
    TopicContextWarningCode,
)
from cve_kgrag.topics.registry import TopicRegistry
from tests.support.collect import list_technique_ids
from tests.support.evaluation import run_deterministically, run_with_replies
from tests.support.investigation import (
    FIGHT_FREE_TEXT_QUERY,
    FIVE_G_AKA_TOPIC_ID,
    build_blocking_investigation_service,
    build_investigation_request,
    build_test_investigation_service,
    list_need_outcomes,
    list_step_reasons,
    list_step_tools,
    list_warning_codes,
    verify_as_sealed,
)
from tests.support.investigation_runs import (
    run_fight_direct_search,
    run_fight_direct_search_fight_failing,
    run_fight_direct_search_of_an_unindexed_word,
    run_fight_direct_search_over_the_byte_cap,
    run_mixed_fight_direct_search,
    run_mixed_free_text_over_the_source_budget,
)
from tests.support.planners import (
    UNAVAILABLE_REPLY,
    FailingModelPort,
    ScriptedModelPort,
    build_plan_reply,
)

FIGHT_DIRECT_SEARCH = {"tool": "fight_direct_search"}


def describe_warnings(warnings: Sequence[TopicContextWarning | InvestigationWarning]) -> list[str]:
    warning_descriptions: list[str] = []
    for warning in warnings:
        warning_descriptions.append(f"{warning.code.value}:{warning.subject}")
    return warning_descriptions


def count_fight_steps(evidence_set: KnowledgeEvidenceSet) -> int:
    fight_step_count = 0
    for step in evidence_set.trajectory.steps:
        if KnowledgeSource.MITRE_FIGHT in step.sources:
            fight_step_count += 1
    return fight_step_count


def test_protocol_free_text_searches_fight_with_its_own_words(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_fight_direct_search(fixture_bundle)

    step = evidence_set.trajectory.steps[0]
    assert list_step_reasons(evidence_set) == [StepReason.QUERY_TERMS_FIGHT]
    assert step.backend_requests == (
        FightBackendRequest(
            source=KnowledgeSource.MITRE_FIGHT, terms=("suci", "discovery"), limit=20
        ),
    )
    assert step.charged_tool_calls == 1
    assert list_technique_ids(evidence_set.protocol_context) == list(step.answer_ids)
    assert evidence_set.protocol_context != ()
    assert evidence_set.interpretation.resolution.matches == ()
    assert not any(
        warning.code is TopicContextWarningCode.TERM_NOT_INDEXED for warning in step.topic_warnings
    )
    assert (evidence_set.stop_reason, evidence_set.status) == (
        StopReason.SUFFICIENT,
        ResultStatus.OK,
    )
    assert list_need_outcomes(evidence_set) == [
        (EvidenceNeedKind.PROTOCOL_CONTEXT, None, NeedOutcome.FOUND)
    ]


def test_direct_search_of_a_word_no_technique_holds_keeps_its_techniques_and_leaves_the_need_unmet(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_fight_direct_search_of_an_unindexed_word(fixture_bundle)

    assert describe_warnings(evidence_set.trajectory.steps[0].topic_warnings) == [
        "topic_not_resolved:suci threats",
        "source_snapshot_is_excerpt:mitre_fight: excerpt of 6 techniques",
        "term_not_indexed:threats",
    ]
    assert list_technique_ids(evidence_set.protocol_context) == list(
        evidence_set.trajectory.steps[0].answer_ids
    )
    assert evidence_set.protocol_context != ()
    assert list_need_outcomes(evidence_set) == [
        (EvidenceNeedKind.PROTOCOL_CONTEXT, None, NeedOutcome.NOT_FOUND)
    ]
    assert (evidence_set.stop_reason, evidence_set.status, evidence_set.coverage.basis) == (
        StopReason.NEEDS_UNMET,
        ResultStatus.PARTIAL,
        DecisionBasis.NO_REFINEMENT_AVAILABLE,
    )


def test_unheld_word_the_affectedness_question_explains_leaves_the_protocol_need_found(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_deterministically(
        fixture_bundle, "Is f5gc 1.2.3 affected by suci discovery", "mixed"
    )

    assert evidence_set.interpretation.affectedness_mentions == ("f5gc 1.2.3",)
    fight_warning_descriptions = describe_warnings(evidence_set.trajectory.steps[1].topic_warnings)
    assert "term_not_indexed:f5gc" in fight_warning_descriptions
    assert "term_not_indexed:affected" in fight_warning_descriptions
    assert list_need_outcomes(evidence_set)[1] == (
        EvidenceNeedKind.PROTOCOL_CONTEXT,
        None,
        NeedOutcome.FOUND,
    )


@pytest.mark.parametrize(
    ("query", "expected_outcomes"),
    [
        (
            # Only the CVE index lacks ``discovery``.
            "SUCI discovery",
            [
                (EvidenceNeedKind.IMPLEMENTATION_CVES, None, NeedOutcome.NOT_FOUND),
                (EvidenceNeedKind.PROTOCOL_CONTEXT, None, NeedOutcome.FOUND),
            ],
        ),
        (
            # Only the FiGHT excerpt lacks ``gateway``.
            "SUCI gateway",
            [
                (EvidenceNeedKind.IMPLEMENTATION_CVES, None, NeedOutcome.FOUND),
                (EvidenceNeedKind.PROTOCOL_CONTEXT, None, NeedOutcome.NOT_FOUND),
            ],
        ),
    ],
    ids=["unindexed_only_in_cves", "unindexed_only_in_fight"],
)
def test_word_one_source_holds_no_record_of_leaves_only_that_source_s_need_unmet(
    fixture_bundle: FixtureBundle,
    query: str,
    expected_outcomes: list[tuple[EvidenceNeedKind, str | None, NeedOutcome]],
) -> None:
    evidence_set = run_deterministically(fixture_bundle, query, "mixed")

    assert list_step_tools(evidence_set) == ["cve_search", "fight_direct_search"]
    assert list_need_outcomes(evidence_set) == expected_outcomes
    assert evidence_set.stop_reason is StopReason.NEEDS_UNMET


def test_direct_search_cut_at_the_result_cap_is_counted_in_answer_truncated(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_deterministically(
        fixture_bundle,
        FIGHT_FREE_TEXT_QUERY,
        "protocol_context_only",
        budget={"max_results_per_call": 1},
    )

    assert list_step_tools(evidence_set) == ["fight_direct_search"]
    assert "protocol_context_truncated:3" in describe_warnings(
        evidence_set.trajectory.steps[0].topic_warnings
    )
    assert "answer_truncated:3" in describe_warnings(evidence_set.warnings)


def test_technique_found_without_a_topic_is_explained_only_by_the_question_s_words(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_fight_direct_search(fixture_bundle)

    explaining_terms: set[str] = set()
    for item in evidence_set.protocol_context:
        explaining_terms.update(item.matched_terms)
    assert explaining_terms == {"suci", "discovery"}
    assert "topic_pending_review" not in list_warning_codes(evidence_set)
    assert len(evidence_set.claims) == 4
    for claim in evidence_set.claims:
        assert "MITRE FiGHT lists" in claim.statement
        assert FIVE_G_AKA_TOPIC_ID not in claim.statement


def test_mixed_free_text_searches_cves_then_fight_in_round_one(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_mixed_fight_direct_search(fixture_bundle)

    assert list_step_reasons(evidence_set) == [
        StepReason.QUERY_TERMS,
        StepReason.QUERY_TERMS_FIGHT,
    ]
    assert len(evidence_set.trajectory.rounds) == 1
    assert evidence_set.implementation_candidates != ()
    assert evidence_set.protocol_context != ()
    assert list_need_outcomes(evidence_set) == [
        (EvidenceNeedKind.IMPLEMENTATION_CVES, None, NeedOutcome.NOT_FOUND),
        (EvidenceNeedKind.PROTOCOL_CONTEXT, None, NeedOutcome.FOUND),
    ]
    assert evidence_set.stop_reason is StopReason.NEEDS_UNMET


def test_direct_search_whose_fight_source_failed_stops_source_unavailable(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_fight_direct_search_fight_failing(fixture_bundle)

    assert list_step_tools(evidence_set) == ["fight_direct_search"]
    assert (evidence_set.stop_reason, evidence_set.coverage.basis) == (
        StopReason.SOURCE_UNAVAILABLE,
        DecisionBasis.ANSWER_SOURCE_FAILED,
    )
    assert list_need_outcomes(evidence_set) == [
        (EvidenceNeedKind.PROTOCOL_CONTEXT, None, NeedOutcome.SOURCE_UNAVAILABLE)
    ]


@pytest.mark.parametrize(
    ("query", "scope", "expected_block", "expected_protocol_outcomes"),
    [
        (
            "aka attacks",
            "mixed",
            FightBlock(reason=FightBlockReason.EXCLUDED_TERM, subject="aka"),
            [NeedOutcome.UNSUPPORTED],
        ),
        (
            "EPS AKA crash",
            "mixed",
            FightBlock(reason=FightBlockReason.EXCLUDED_TERM, subject="EPS AKA"),
            [NeedOutcome.UNSUPPORTED],
        ),
        (
            "EPS AKA crash",
            "protocol_context_only",
            FightBlock(reason=FightBlockReason.EXCLUDED_TERM, subject="EPS AKA"),
            [NeedOutcome.UNSUPPORTED],
        ),
        (
            "EAP-AKA' threats",
            "mixed",
            FightBlock(reason=FightBlockReason.EXCLUDED_TERM, subject="EAP-AKA'"),
            [NeedOutcome.UNSUPPORTED],
        ),
        (
            "5G, aka NR GTP threats",
            "mixed",
            FightBlock(reason=FightBlockReason.EXCLUDED_TERM, subject="aka"),
            [NeedOutcome.UNSUPPORTED],
        ),
        (
            "5Géaka threats",
            "mixed",
            FightBlock(reason=FightBlockReason.EXCLUDED_TERM, subject="aka"),
            [NeedOutcome.UNSUPPORTED],
        ),
        (
            "CVE-9999-0003 GTP threats",
            "mixed",
            FightBlock(reason=FightBlockReason.CVE_ID_NAMED, subject="CVE-9999-0003"),
            [],
        ),
    ],
    ids=[
        "bare_aka",
        "eps_aka_mixed",
        "eps_aka_protocol",
        "eap_aka_prime",
        "aka_as_also_known_as",
        "aka_written_against_a_non_ascii_letter",
        "cve_id_named",
    ],
)
def test_query_the_exclusion_table_bars_issues_no_fight_search(
    fixture_bundle: FixtureBundle,
    query: str,
    scope: str,
    expected_block: FightBlock,
    expected_protocol_outcomes: list[NeedOutcome],
) -> None:
    evidence_set = run_deterministically(fixture_bundle, query, scope)

    assert evidence_set.interpretation.fight_block == expected_block
    assert evidence_set.interpretation.fight_terms == ()
    assert count_fight_steps(evidence_set) == 0
    protocol_outcomes: list[NeedOutcome] = []
    for need in evidence_set.coverage.needs:
        if need.kind is EvidenceNeedKind.PROTOCOL_CONTEXT:
            protocol_outcomes.append(need.outcome)
    assert protocol_outcomes == expected_protocol_outcomes


@pytest.mark.parametrize("scope", ["implementation_only", "mixed"])
def test_excluded_alias_written_against_a_non_ascii_letter_is_stripped_warned_and_kept_from_fight(
    fixture_bundle: FixtureBundle, scope: str
) -> None:
    """``5Géaka`` reads as the words ``5g``, ``é`` and ``aka``: the CVE search sends the
    other words, the excluded ``aka`` is warned, and FiGHT is not searched."""
    evidence_set = run_deterministically(fixture_bundle, "5Géaka threats", scope)

    interpretation = evidence_set.interpretation
    assert interpretation.search_terms == ("5g", "threats")
    assert interpretation.intent is QueryIntent.FREE_TEXT
    assert interpretation.fight_block == FightBlock(
        reason=FightBlockReason.EXCLUDED_TERM, subject="aka"
    )
    assert interpretation.fight_terms == ()
    assert list_step_tools(evidence_set) == ["cve_search"]
    assert evidence_set.trajectory.steps[0].backend_requests[0].query == "5g threats"
    assert count_fight_steps(evidence_set) == 0
    assert "excluded_term:aka" in describe_warnings(evidence_set.warnings)


def test_excluded_alias_written_against_a_non_ascii_letter_stops_protocol_scope_with_its_warning(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_deterministically(fixture_bundle, "5Géaka threats", "protocol_context_only")

    assert evidence_set.trajectory.steps == ()
    assert (evidence_set.stop_reason, evidence_set.coverage.basis) == (
        StopReason.NO_EVIDENCE,
        DecisionBasis.PROTOCOL_SCOPE_NEEDS_TOPIC,
    )
    assert "excluded_term:aka" in describe_warnings(evidence_set.warnings)


@pytest.mark.parametrize(
    "query",
    [
        "CVE-9999-0003 EPS AKA crash",
        "CVE-9999-0003 5Géaka threats",
        "CVE-9999-0003 GTP threats",
        "5G-AKA threats",
    ],
    ids=[
        "excluded_term",
        "excluded_term_written_against_a_non_ascii_letter",
        "cve_id_named",
        "topic_resolved",
    ],
)
def test_model_plan_adding_a_direct_fight_search_the_interpretation_bars_is_rejected(
    fixture_bundle: FixtureBundle, query: str
) -> None:
    evidence_set = run_with_replies(
        fixture_bundle,
        query,
        "mixed",
        build_plan_reply(FIGHT_DIRECT_SEARCH),
        UNAVAILABLE_REPLY,
    )

    round_one = evidence_set.trajectory.rounds[0]
    assert round_one.planner_outcome is PlannerOutcome.MODEL_REJECTED
    assert (
        PlanRejection(step_position=0, code=PlanRejectionCode.FIGHT_DIRECT_SEARCH_BLOCKED)
        in round_one.rejections
    )
    assert ToolName.FIGHT_DIRECT_SEARCH.value not in list_step_tools(evidence_set)


def test_mixed_free_text_under_one_source_stops_over_budget_without_a_model_call(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_with_replies(
        fixture_bundle, FIGHT_FREE_TEXT_QUERY, "mixed", budget={"max_sources": 1}
    )

    assert evidence_set.trajectory.rounds[0].planner_outcome is PlannerOutcome.MODEL_NOT_CONSULTED
    assert evidence_set.trajectory.budget_used.planner_calls == 0
    assert evidence_set.trajectory.steps == ()
    assert evidence_set.trajectory.budget_used.breach is BudgetBreach.SOURCES
    assert (evidence_set.stop_reason, evidence_set.coverage.basis) == (
        StopReason.BUDGET_EXHAUSTED,
        DecisionBasis.PLAN_OVER_BUDGET,
    )
    assert evidence_set.has_answer() is False


def test_mixed_free_text_under_one_tool_call_stops_over_budget_without_a_model_call(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
    topic_registry: TopicRegistry,
) -> None:
    service = build_test_investigation_service(fixture_bundle, model_port=FailingModelPort())

    evidence_set = service.investigate(
        build_investigation_request(FIGHT_FREE_TEXT_QUERY, "mixed", budget={"max_tool_calls": 1})
    )

    round_one = evidence_set.trajectory.rounds[0]
    assert round_one.planner_outcome is PlannerOutcome.MODEL_NOT_CONSULTED
    assert round_one.rejections == (PlanRejection(code=PlanRejectionCode.OVER_TOOL_CALL_BUDGET),)
    assert evidence_set.trajectory.budget_used.planner_calls == 0
    assert evidence_set.trajectory.steps == ()
    assert evidence_set.trajectory.budget_used.breach is BudgetBreach.TOOL_CALLS
    assert (evidence_set.stop_reason, evidence_set.coverage.basis) == (
        StopReason.BUDGET_EXHAUSTED,
        DecisionBasis.PLAN_OVER_BUDGET,
    )
    verify_as_sealed(
        evidence_set,
        pinned_fight_snapshot,
        packaged_evidence_catalog,
        evidence_set.source_capabilities,
        topic_registry,
    )


def test_mixed_free_text_under_one_tool_call_runs_nothing_deterministically(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_deterministically(
        fixture_bundle, FIGHT_FREE_TEXT_QUERY, "mixed", budget={"max_tool_calls": 1}
    )

    assert evidence_set.trajectory.rounds[0].rejections == (
        PlanRejection(code=PlanRejectionCode.OVER_TOOL_CALL_BUDGET),
    )
    assert evidence_set.trajectory.steps == ()
    assert evidence_set.stop_reason is StopReason.BUDGET_EXHAUSTED
    assert evidence_set.has_answer() is False


@pytest.mark.parametrize(
    "query",
    ["CVE-9999-0003 EPS AKA crash", "CVE-9999-0003 GTP threats", "5G-AKA threats"],
    ids=["excluded_term", "cve_id_named", "topic_resolved"],
)
def test_planner_is_never_offered_the_direct_search(
    fixture_bundle: FixtureBundle, query: str
) -> None:
    """Only free text may search FiGHT with its own words, and the policy plans free text
    without the model; every question the model plans has a block that bars the search."""
    model_port = ScriptedModelPort([UNAVAILABLE_REPLY, UNAVAILABLE_REPLY])
    service = build_test_investigation_service(fixture_bundle, model_port=model_port)

    evidence_set = service.investigate(build_investigation_request(query, "mixed"))

    planning_input = model_port.planning_inputs[0]
    assert evidence_set.interpretation.fight_block is not None
    assert ToolName.FIGHT_DIRECT_SEARCH not in planning_input.allowed_tools
    assert ToolName.FIGHT_DIRECT_SEARCH not in planning_input.required_tools


def test_needs_of_a_round_one_plan_over_the_source_budget_are_not_evaluated(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_mixed_free_text_over_the_source_budget(fixture_bundle)

    assert list_need_outcomes(evidence_set) == [
        (EvidenceNeedKind.IMPLEMENTATION_CVES, None, NeedOutcome.NOT_EVALUATED),
        (EvidenceNeedKind.PROTOCOL_CONTEXT, None, NeedOutcome.NOT_EVALUATED),
    ]


def test_need_of_a_discarded_direct_search_is_not_evaluated(fixture_bundle: FixtureBundle) -> None:
    evidence_set = run_fight_direct_search_over_the_byte_cap(fixture_bundle)

    assert evidence_set.trajectory.steps[0].admission is StepAdmission.DISCARDED_OVER_CONTEXT_BUDGET
    assert evidence_set.stop_reason is StopReason.BUDGET_EXHAUSTED
    assert list_need_outcomes(evidence_set) == [
        (EvidenceNeedKind.PROTOCOL_CONTEXT, None, NeedOutcome.NOT_EVALUATED)
    ]


def test_need_of_a_timed_out_direct_search_is_not_evaluated(
    fixture_bundle: FixtureBundle, blocked_call_release: threading.Event
) -> None:
    service = build_blocking_investigation_service(fixture_bundle, "fight", blocked_call_release)

    evidence_set = service.investigate(
        build_investigation_request(
            FIGHT_FREE_TEXT_QUERY, "protocol_context_only", budget={"max_wall_time_seconds": 1}
        )
    )

    assert evidence_set.trajectory.steps[0].admission is StepAdmission.TIMED_OUT
    assert evidence_set.stop_reason is StopReason.BUDGET_EXHAUSTED
    assert list_need_outcomes(evidence_set) == [
        (EvidenceNeedKind.PROTOCOL_CONTEXT, None, NeedOutcome.NOT_EVALUATED)
    ]


def test_needs_left_by_a_round_cap_after_named_ids_are_not_evaluated(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_deterministically(
        fixture_bundle, "CVE-9999-0003 5gaka", "mixed", budget={"max_rounds": 1}
    )

    assert list_step_tools(evidence_set) == ["cve_exact_lookup"]
    assert (evidence_set.stop_reason, evidence_set.coverage.basis) == (
        StopReason.BUDGET_EXHAUSTED,
        DecisionBasis.ROUND_CAP_REACHED,
    )
    assert list_need_outcomes(evidence_set) == [
        (EvidenceNeedKind.NAMED_CVE, "CVE-9999-0003", NeedOutcome.FOUND),
        (EvidenceNeedKind.IMPLEMENTATION_CVES, None, NeedOutcome.NOT_EVALUATED),
        (EvidenceNeedKind.PROTOCOL_CONTEXT, None, NeedOutcome.NOT_EVALUATED),
    ]


def test_need_of_an_admitted_step_whose_source_failed_is_source_unavailable_not_unevaluated(
    fixture_bundle: FixtureBundle,
) -> None:
    service = build_test_investigation_service(fixture_bundle, fight="failing")

    evidence_set = service.investigate(build_investigation_request(FIGHT_FREE_TEXT_QUERY, "mixed"))

    assert evidence_set.trajectory.steps[1].admission is StepAdmission.ADMITTED
    assert list_need_outcomes(evidence_set)[1] == (
        EvidenceNeedKind.PROTOCOL_CONTEXT,
        None,
        NeedOutcome.SOURCE_UNAVAILABLE,
    )
