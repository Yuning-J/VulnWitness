"""The deterministic policy m7b.4: interpretation, stops, round-1 plans, refinement and cost."""

from typing import Any

import pytest

from cve_kgrag.application.investigation_policy import (
    PlannedStep,
    build_fight_direct_search_call,
    count_tool_calls,
    find_fight_block,
    find_interpretation_stop,
    interpret_request,
    list_allowed_terms,
    list_fight_terms,
    plan_first_round,
    plan_refinement,
)
from cve_kgrag.domain.evidence_needs import judge_needs
from cve_kgrag.domain.investigation import (
    DecisionBasis,
    EvidenceNeed,
    FightBlock,
    FightBlockReason,
    Interpretation,
    InvestigationRequest,
    StepReason,
    StopReason,
    ToolStep,
)
from cve_kgrag.domain.planning import (
    QueryIntent,
    ToolCall,
    compute_call_key,
)
from cve_kgrag.domain.search import SearchWarning, SearchWarningCode
from cve_kgrag.domain.topic_context import QueryScope
from cve_kgrag.topics.registry import TopicRegistry
from tests.support.builders import build_recorded_step, build_topic
from tests.support.investigation import (
    FIVE_G_AKA_TOPIC_ID,
    TWENTY_ONE_IDS,
    build_exact_lookup_call,
    build_investigation_request,
    build_productless_catalog,
    build_search_call,
    build_topic_call,
)


def describe_planned_steps(planned_steps: list[PlannedStep]) -> list[tuple[ToolCall, StepReason]]:
    described_steps: list[tuple[ToolCall, StepReason]] = []
    for planned_step in planned_steps:
        described_steps.append((planned_step.call, planned_step.reason))
    return described_steps


def judge_round_one(
    request: InvestigationRequest, interpretation: Interpretation, round_one_steps: list[ToolStep]
) -> tuple[EvidenceNeed, ...]:
    """The needs round 1 left, judged from its recorded steps alone (the answer lists
    what they returned, and these steps returned nothing)."""
    return judge_needs(request, interpretation, round_one_steps, (), ())


@pytest.mark.parametrize(
    ("query", "expected_intent", "expected_cve_ids", "expected_terms"),
    [
        ("CVE-9999-0003", QueryIntent.EXACT_ID, ("CVE-9999-0003",), ()),
        ("cve-9999-4242 AUSF", QueryIntent.EXACT_ID, ("CVE-9999-4242",), ("ausf",)),
        ("5gaka", QueryIntent.TOPIC, (), ("5gaka",)),
        ("5G-AKA", QueryIntent.TOPIC, (), ("5g", "aka")),
        (
            "5G Authentication and Key Agreement",
            QueryIntent.TOPIC,
            (),
            ("5g", "authentication", "key", "agreement"),
        ),
        ("aka", QueryIntent.EXCLUDED_TERMS_ONLY, (), ()),
        ("EPS AKA crash", QueryIntent.FREE_TEXT, (), ("crash",)),
        ("aka bug in amf", QueryIntent.FREE_TEXT, (), ("bug", "amf")),
        ("crash crash CRASH", QueryIntent.FREE_TEXT, (), ("crash",)),
        ("the", QueryIntent.UNSEARCHABLE, (), ()),
        ("CVE-2024-1234567890123456789012345678 crash", QueryIntent.FREE_TEXT, (), ("crash",)),
        ("ausf crash cve in 2021 and 2022", QueryIntent.FREE_TEXT, (), ("ausf", "crash")),
        ("crash nvdcve EPS AKA 2021 2022", QueryIntent.FREE_TEXT, (), ("crash",)),
        ("ausf nvdcve cves 2021 2022", QueryIntent.FREE_TEXT, (), ("ausf",)),
        ("CVE of 2021-44228", QueryIntent.UNSEARCHABLE, (), ()),
        ("cve", QueryIntent.UNSEARCHABLE, (), ()),
        ("CVEs", QueryIntent.UNSEARCHABLE, (), ()),
        ("cve ausf crash", QueryIntent.FREE_TEXT, (), ("ausf", "crash")),
        ("CVE 2022 log4j", QueryIntent.FREE_TEXT, (), ("2022", "log4j")),
        ("CVE-9999-0003 cve", QueryIntent.EXACT_ID, ("CVE-9999-0003",), ()),
        ("cves 5G-AKA", QueryIntent.TOPIC, (), ("5g", "aka")),
        ("5G\u00e9aka threats", QueryIntent.FREE_TEXT, (), ("5g", "threats")),
        ("EAP-AKA\u02bc threats", QueryIntent.FREE_TEXT, (), ("threats",)),
        ("\u00e9aka", QueryIntent.EXCLUDED_TERMS_ONLY, (), ()),
    ],
    ids=[
        "exact_id",
        "exact_id_with_terms",
        "compact_alias",
        "hyphenated_alias",
        "canonical_name",
        "bare_excluded_alias",
        "excluded_alias_stripped",
        "excluded_token_stripped",
        "terms_deduplicated",
        "stopword_only",
        "overlong_id_is_no_cve_id",
        "id_likeness_formed_once_stopwords_drop",
        "id_likeness_formed_once_excluded_tokens_drop",
        "id_likeness_formed_once_low_signal_words_drop",
        "id_likeness_with_a_stopword_after_the_word_cve",
        "low_signal_word_alone",
        "low_signal_plural_alone",
        "low_signal_word_before_terms",
        "low_signal_word_before_a_year",
        "low_signal_word_beside_an_id",
        "low_signal_word_beside_a_topic",
        "excluded_alias_written_against_a_non_ascii_letter_stripped",
        "excluded_phrase_with_a_modifier_letter_apostrophe_stripped",
        "excluded_alias_alone_after_a_non_ascii_letter",
    ],
)
def test_query_is_interpreted_into_intent_ids_and_searchable_terms(
    topic_registry: TopicRegistry,
    query: str,
    expected_intent: QueryIntent,
    expected_cve_ids: tuple[str, ...],
    expected_terms: tuple[str, ...],
) -> None:
    interpretation = interpret_request(
        build_investigation_request(query, "mixed"), topic_registry, build_productless_catalog()
    )

    assert interpretation.intent is expected_intent
    assert interpretation.cve_ids == expected_cve_ids
    assert interpretation.search_terms == expected_terms


@pytest.mark.parametrize(
    ("query", "expected_block"),
    [
        ("aka attacks", FightBlock(reason=FightBlockReason.EXCLUDED_TERM, subject="aka")),
        ("EPS AKA crash", FightBlock(reason=FightBlockReason.EXCLUDED_TERM, subject="EPS AKA")),
        ("EAP-AKA' threats", FightBlock(reason=FightBlockReason.EXCLUDED_TERM, subject="EAP-AKA'")),
        (
            "5G, aka NR GTP threats",
            FightBlock(reason=FightBlockReason.EXCLUDED_TERM, subject="aka"),
        ),
        ("5Géaka threats", FightBlock(reason=FightBlockReason.EXCLUDED_TERM, subject="aka")),
        (
            "EAP-AKA\u02bc threats",
            FightBlock(reason=FightBlockReason.EXCLUDED_TERM, subject="EAP-AKA'"),
        ),
        (
            "CVE-9999-0003 GTP threats",
            FightBlock(reason=FightBlockReason.CVE_ID_NAMED, subject="CVE-9999-0003"),
        ),
        (
            "5G-AKA threats",
            FightBlock(reason=FightBlockReason.TOPIC_RESOLVED, subject=FIVE_G_AKA_TOPIC_ID),
        ),
        ("gtp threats", None),
    ],
    ids=[
        "bare_excluded_alias",
        "excluded_phrase",
        "excluded_phrase_with_an_apostrophe",
        "excluded_alias_among_other_words",
        "excluded_alias_written_against_a_non_ascii_letter",
        "excluded_phrase_with_a_modifier_letter_apostrophe",
        "cve_id_named",
        "topic_resolved",
        "free_text_without_a_block",
    ],
)
def test_fight_block_names_the_first_reason_the_words_may_not_go_to_fight(
    topic_registry: TopicRegistry, query: str, expected_block: FightBlock | None
) -> None:
    assert find_fight_block(query, topic_registry) == expected_block


@pytest.mark.parametrize(
    ("excluded_term", "query", "expected_search_term", "expected_cve_query"),
    [
        ("NAS", "na\u00df\u0301 threats", "nas", "nas threats"),
        ("h", "x H\u0302\u0331 attacks", "h", "x h attacks"),
    ],
    ids=["sharp_s_and_combining_acute", "h_circumflex_and_macron_below"],
)
def test_excluded_word_only_double_normalization_produces_is_kept_from_fight_not_cve_search(
    excluded_term: str, query: str, expected_search_term: str, expected_cve_query: str
) -> None:
    """The registry reads the query once and reports no exclusion; the search terms,
    normalized twice, hold the excluded word. ``term_reads_as_topic`` keeps it from FiGHT,
    and the CVE search still sends it (ADR 0002 §8, a known limit)."""
    topic_registry = TopicRegistry(
        [build_topic(exclusions=[{"term": excluded_term, "reason": "a test exclusion"}])]
    )
    request = build_investigation_request(query, "mixed")

    interpretation = interpret_request(request, topic_registry, build_productless_catalog())
    planned_steps = plan_first_round(request, interpretation)

    assert interpretation.resolution.excluded_terms == ()
    assert interpretation.fight_block == FightBlock(
        reason=FightBlockReason.TERM_READS_AS_TOPIC, subject=expected_search_term
    )
    assert interpretation.fight_terms == ()
    assert describe_planned_steps(planned_steps) == [
        (build_search_call(expected_cve_query), StepReason.QUERY_TERMS)
    ]


@pytest.mark.parametrize(
    ("query", "expected_fight_terms"),
    [
        ("GTP threats in the mobile core", ("gtp", "threats", "mobile", "core")),
        ("5G, aka NR GTP threats", ()),
        ("5Géaka threats", ()),
        ("CVE-9999-0003 GTP threats", ()),
        ("5G-AKA threats", ()),
    ],
    ids=[
        "every_word",
        "excluded_term",
        "excluded_term_written_against_a_non_ascii_letter",
        "cve_id",
        "topic",
    ],
)
def test_fight_terms_are_every_search_term_or_none(
    topic_registry: TopicRegistry, query: str, expected_fight_terms: tuple[str, ...]
) -> None:
    interpretation = interpret_request(
        build_investigation_request(query, "mixed"), topic_registry, build_productless_catalog()
    )

    fight_terms = list_fight_terms(query, topic_registry)

    assert fight_terms == expected_fight_terms
    assert interpretation.fight_terms == expected_fight_terms
    assert interpretation.fight_block == find_fight_block(query, topic_registry)


def test_overlong_normalized_token_is_dropped_rather_than_searched(
    topic_registry: TopicRegistry,
) -> None:
    # NFKC turns each ligature into three letters: one 1536-character token.
    interpretation = interpret_request(
        build_investigation_request("ﬃ" * 512, "implementation_only"),
        topic_registry,
        build_productless_catalog(),
    )

    assert interpretation.search_terms == ()
    assert interpretation.intent is QueryIntent.UNSEARCHABLE


@pytest.mark.parametrize(
    ("query", "scope", "filters", "expected_stop"),
    [
        (
            "CVE-9999-0003",
            "protocol_context_only",
            {},
            (StopReason.POLICY_BLOCKED, DecisionBasis.CVE_IDS_OUTSIDE_SCOPE),
        ),
        (
            "5gaka",
            "protocol_context_only",
            {"vendors": ["fictional5g"]},
            (StopReason.POLICY_BLOCKED, DecisionBasis.FILTERS_OUTSIDE_SCOPE),
        ),
        (
            "5gaka",
            "protocol_context_only",
            {"severities": ["HIGH"]},
            (StopReason.POLICY_BLOCKED, DecisionBasis.FILTERS_OUTSIDE_SCOPE),
        ),
        ("aka", "mixed", {}, (StopReason.NO_EVIDENCE, DecisionBasis.EXCLUDED_TERMS_ONLY)),
        (
            "\u00e9aka",
            "mixed",
            {},
            (StopReason.NO_EVIDENCE, DecisionBasis.EXCLUDED_TERMS_ONLY),
        ),
        (
            "the",
            "implementation_only",
            {},
            (StopReason.NO_EVIDENCE, DecisionBasis.NO_SEARCHABLE_TERMS),
        ),
        (
            "EPS AKA crash",
            "protocol_context_only",
            {},
            (StopReason.NO_EVIDENCE, DecisionBasis.PROTOCOL_SCOPE_NEEDS_TOPIC),
        ),
        (
            "5Géaka threats",
            "protocol_context_only",
            {},
            (StopReason.NO_EVIDENCE, DecisionBasis.PROTOCOL_SCOPE_NEEDS_TOPIC),
        ),
        (
            TWENTY_ONE_IDS,
            "implementation_only",
            {},
            (StopReason.POLICY_BLOCKED, DecisionBasis.CVE_IDS_OVER_LOOKUP_CAP),
        ),
        ("5gaka", "protocol_context_only", {}, None),
        ("crash", "protocol_context_only", {}, None),
        ("crash", "mixed", {}, None),
        ("CVE-9999-0003", "mixed", {"products": ["f5gc"]}, None),
    ],
    ids=[
        "cve_ids_under_protocol",
        "product_filter_under_protocol",
        "any_filter_under_protocol",
        "excluded_terms_only",
        "excluded_alias_alone_after_a_non_ascii_letter",
        "unsearchable",
        "free_text_with_an_excluded_term_under_protocol",
        "free_text_with_an_excluded_term_written_against_a_non_ascii_letter_under_protocol",
        "more_ids_than_one_lookup_takes",
        "topic_under_protocol",
        "free_text_under_protocol_searches_fight_directly",
        "free_text_mixed",
        "exact_id_with_product",
    ],
)
def test_interpretation_stop_is_decided_before_any_call(
    topic_registry: TopicRegistry,
    query: str,
    scope: str,
    filters: dict[str, Any],
    expected_stop: tuple[StopReason, DecisionBasis] | None,
) -> None:
    request = build_investigation_request(query, scope, filters=filters)
    interpretation = interpret_request(request, topic_registry, build_productless_catalog())

    stop = find_interpretation_stop(request, interpretation)

    assert stop == expected_stop


@pytest.mark.parametrize(
    ("query", "scope", "expected_steps"),
    [
        (
            "CVE-9999-0003",
            "implementation_only",
            [(build_exact_lookup_call("CVE-9999-0003"), StepReason.QUERY_CVE_IDS)],
        ),
        (
            "CVE-9999-0003",
            "mixed",
            [(build_exact_lookup_call("CVE-9999-0003"), StepReason.QUERY_CVE_IDS)],
        ),
        ("5gaka", "implementation_only", [(build_topic_call(), StepReason.REVIEWED_TOPIC)]),
        ("5G-AKA", "implementation_only", [(build_topic_call(), StepReason.REVIEWED_TOPIC)]),
        ("5gaka", "mixed", [(build_topic_call(), StepReason.REVIEWED_TOPIC)]),
        ("5gaka", "protocol_context_only", [(build_topic_call(), StepReason.REVIEWED_TOPIC)]),
        (
            "EPS AKA crash",
            "implementation_only",
            [(build_search_call("crash"), StepReason.QUERY_TERMS)],
        ),
        ("aka bug in amf", "mixed", [(build_search_call("bug amf"), StepReason.QUERY_TERMS)]),
        (
            "gtp threats",
            "protocol_context_only",
            [(build_fight_direct_search_call(), StepReason.QUERY_TERMS_FIGHT)],
        ),
        (
            "gtp threats",
            "mixed",
            [
                (build_search_call("gtp threats"), StepReason.QUERY_TERMS),
                (build_fight_direct_search_call(), StepReason.QUERY_TERMS_FIGHT),
            ],
        ),
        (
            "gtp threats",
            "implementation_only",
            [(build_search_call("gtp threats"), StepReason.QUERY_TERMS)],
        ),
    ],
    ids=[
        "exact_id_implementation",
        "exact_id_mixed",
        "topic_implementation",
        "topic_implementation_spelled_out",
        "topic_mixed",
        "topic_protocol",
        "free_text_implementation",
        "free_text_mixed_whose_words_may_not_go_to_fight",
        "free_text_protocol_searches_fight_directly",
        "free_text_mixed_searches_cves_then_fight",
        "free_text_implementation_never_searches_fight",
    ],
)
def test_round_one_plans_calls_by_intent_and_scope(
    topic_registry: TopicRegistry,
    query: str,
    scope: str,
    expected_steps: list[tuple[ToolCall, StepReason]],
) -> None:
    request = build_investigation_request(query, scope)
    interpretation = interpret_request(request, topic_registry, build_productless_catalog())

    planned_steps = plan_first_round(request, interpretation)

    assert describe_planned_steps(planned_steps) == expected_steps


def build_unknown_id_lookup(*cve_ids: str, warning_code: SearchWarningCode) -> ToolStep:
    """A round-1 exact lookup whose every ID drew ``warning_code``."""
    search_warnings: list[SearchWarning] = []
    for cve_id in cve_ids:
        search_warnings.append(SearchWarning(code=warning_code, subject=cve_id))
    return build_recorded_step(
        call=build_exact_lookup_call(*cve_ids),
        reason="query_cve_ids",
        search_warnings=search_warnings,
    )


@pytest.mark.parametrize(
    ("query", "warning_code", "expected_steps"),
    [
        (
            "CVE-9999-4242 5gaka",
            SearchWarningCode.UNKNOWN_CVE_ID,
            [(build_topic_call(), StepReason.TOPIC_AFTER_UNKNOWN_IDS)],
        ),
        ("CVE-9999-4242 AUSF resynchronization crash", SearchWarningCode.UNKNOWN_CVE_ID, []),
        ("CVE-9999-4242", SearchWarningCode.UNKNOWN_CVE_ID, []),
        ("CVE-9999-0003 AUSF crash", SearchWarningCode.EXCLUDED_BY_FILTERS, []),
    ],
    ids=[
        "unknown_id_with_topic_explores_topic",
        "unknown_id_with_plain_text_has_no_refinement",
        "unknown_id_alone_has_no_refinement",
        "id_excluded_by_filters_is_known_so_no_refinement",
    ],
)
def test_r1_refines_only_when_every_requested_id_is_unknown(
    topic_registry: TopicRegistry,
    query: str,
    warning_code: SearchWarningCode,
    expected_steps: list[tuple[ToolCall, StepReason]],
) -> None:
    request = build_investigation_request(query, "implementation_only")
    interpretation = interpret_request(request, topic_registry, build_productless_catalog())
    round_one_step = build_unknown_id_lookup(*interpretation.cve_ids, warning_code=warning_code)

    planned_steps = plan_refinement(
        interpretation, [round_one_step], judge_round_one(request, interpretation, [round_one_step])
    )

    assert describe_planned_steps(planned_steps) == expected_steps


def test_r1_does_not_refine_when_only_some_requested_ids_are_unknown(
    topic_registry: TopicRegistry,
) -> None:
    request = build_investigation_request(
        "CVE-9999-0003 CVE-9999-4242 crash", "implementation_only"
    )
    interpretation = interpret_request(request, topic_registry, build_productless_catalog())
    round_one_step = build_recorded_step(
        call=build_exact_lookup_call("CVE-9999-0003", "CVE-9999-4242"),
        reason="query_cve_ids",
        search_warnings=[{"code": "unknown_cve_id", "subject": "CVE-9999-4242"}],
    )

    assert (
        plan_refinement(
            interpretation,
            [round_one_step],
            judge_round_one(request, interpretation, [round_one_step]),
        )
        == []
    )


def test_r2_explores_the_topic_after_a_literal_search_for_it(
    topic_registry: TopicRegistry,
) -> None:
    request = build_investigation_request("5gaka", "implementation_only")
    interpretation = interpret_request(request, topic_registry, build_productless_catalog())
    round_one_step = build_recorded_step(call=build_search_call("5gaka"))

    planned_steps = plan_refinement(
        interpretation, [round_one_step], judge_round_one(request, interpretation, [round_one_step])
    )

    assert describe_planned_steps(planned_steps) == [
        (build_topic_call(), StepReason.TOPIC_AFTER_LITERAL_MISS)
    ]


def test_refinement_is_not_planned_when_round_one_already_issued_its_call(
    topic_registry: TopicRegistry,
) -> None:
    request = build_investigation_request("5gaka", "implementation_only")
    interpretation = interpret_request(request, topic_registry, build_productless_catalog())
    literal_search = build_search_call("5gaka")
    topic_call = build_topic_call()
    round_one_steps = [
        build_recorded_step(call=literal_search, call_key=compute_call_key(literal_search)),
        build_recorded_step(
            step_index=2,
            call=topic_call,
            reason="model_proposal",
            planned_by="model",
            call_key=compute_call_key(topic_call),
        ),
    ]

    assert (
        plan_refinement(
            interpretation,
            round_one_steps,
            judge_round_one(request, interpretation, round_one_steps),
        )
        == []
    )


def test_no_rule_fires_once_round_one_searched_every_term(
    topic_registry: TopicRegistry,
) -> None:
    request = build_investigation_request("crash", "mixed")
    interpretation = interpret_request(request, topic_registry, build_productless_catalog())
    round_one_step = build_recorded_step(call=build_search_call("crash"))

    assert (
        plan_refinement(
            interpretation,
            [round_one_step],
            judge_round_one(request, interpretation, [round_one_step]),
        )
        == []
    )


def test_r3_searches_the_query_terms_when_the_explored_topic_answered_nothing(
    topic_registry: TopicRegistry,
) -> None:
    request = build_investigation_request("5gaka", "mixed")
    interpretation = interpret_request(request, topic_registry, build_productless_catalog())
    topic_call = build_topic_call()
    round_one_step = build_recorded_step(call=topic_call, call_key=compute_call_key(topic_call))

    planned_steps = plan_refinement(
        interpretation, [round_one_step], judge_round_one(request, interpretation, [round_one_step])
    )

    assert describe_planned_steps(planned_steps) == [
        (build_search_call("5gaka"), StepReason.QUERY_TERMS_FOR_OPEN_NEED)
    ]


@pytest.mark.parametrize(
    ("call", "scope", "expected_cost"),
    [
        (build_topic_call(), QueryScope.PROTOCOL_CONTEXT_ONLY, 5),
        (build_topic_call(), QueryScope.MIXED, 5),
        (build_topic_call(), QueryScope.IMPLEMENTATION_ONLY, 4),
        (build_search_call("crash"), QueryScope.MIXED, 1),
        (build_fight_direct_search_call(), QueryScope.PROTOCOL_CONTEXT_ONLY, 1),
        (
            build_exact_lookup_call("CVE-9999-0001", "CVE-9999-0002"),
            QueryScope.IMPLEMENTATION_ONLY,
            1,
        ),
    ],
    ids=[
        "topic_protocol",
        "topic_mixed",
        "topic_implementation",
        "search",
        "fight_direct_search",
        "exact_lookup",
    ],
)
def test_call_costs_every_backend_query_it_fans_out_to(
    topic_registry: TopicRegistry, call: ToolCall, scope: QueryScope, expected_cost: int
) -> None:
    assert count_tool_calls(call, scope, topic_registry) == expected_cost


def test_allowed_terms_are_the_query_terms_plus_the_resolved_card_terms(
    topic_registry: TopicRegistry,
) -> None:
    interpretation = interpret_request(
        build_investigation_request("5gaka", "mixed"), topic_registry, build_productless_catalog()
    )
    registered_topic = topic_registry.get_topic(FIVE_G_AKA_TOPIC_ID)
    assert registered_topic is not None

    allowed_terms = list_allowed_terms(interpretation, registered_topic.topic)

    assert {"5gaka", "ausf", "suci", "authentication"} <= allowed_terms
    assert "ignore" not in allowed_terms
