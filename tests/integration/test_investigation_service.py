"""Investigation end to end: observations steer the trajectory, failures stay typed, and a
final claim traces back to the bytes of its source."""

import json
import re

import pytest
import yaml
from pydantic import ValidationError

from cve_kgrag.adapters.fixture.fight_fixture import default_fight_fixture_dir
from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle, default_fixture_dir
from cve_kgrag.application.investigation_policy import describe_deterministic_planner
from cve_kgrag.composition import load_packaged_fight_source
from cve_kgrag.domain.affectedness import AffectednessDetail, AffectednessFailure
from cve_kgrag.domain.evidence import EvidenceAnchor
from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.hashing import canonical_sha256, sha256_hex
from cve_kgrag.domain.investigation import (
    DecisionBasis,
    InvestigationWarning,
    InvestigationWarningCode,
    KnowledgeEvidenceSet,
    PlannerOutcome,
    SourceCapabilityState,
    StepAdmission,
    StepReason,
    StopReason,
)
from cve_kgrag.domain.investigation_validation import validate_knowledge_evidence_set
from cve_kgrag.domain.planning import QueryIntent
from cve_kgrag.domain.search import (
    RetrievalOutcome,
    SearchWarning,
    SearchWarningCode,
    UnsupportedFilter,
)
from cve_kgrag.domain.taxonomy import BackendStatus, ResultStatus, SourceType
from cve_kgrag.domain.threat_context import KnownFightSnapshot
from cve_kgrag.domain.topic_context import (
    KnowledgeSource,
    TopicContextWarning,
    TopicContextWarningCode,
)
from cve_kgrag.domain.validation import index_anchors
from tests.support.builders import build_bundle_with
from tests.support.clocks import read_fixed_clock
from tests.support.fakes import (
    CannedRetriever,
    InMemoryTrustifyPort,
    InventingRetriever,
    RecordingRetriever,
    build_failure,
    build_lexical_match,
)
from tests.support.investigation import (
    DISGUISED_LOW_SIGNAL_WORDS,
    TWENTY_ONE_IDS,
    build_investigation_request,
    build_reviewed_investigation_service,
    build_test_investigation_service,
    list_implementation_ids,
    list_step_reasons,
    list_step_tools,
    list_transitions,
    list_warning_codes,
)
from tests.support.investigation_runs import (
    investigate,
    run_fight_direct_search_of_an_unindexed_word,
)
from tests.support.services import build_purl_free_structured_index

OPEN5GS_CVE_ID = "CVE-9999-0101"
BOTH_NAMED_IDS = ["CVE-9999-0003", "CVE-9999-0004"]


def find_claim_anchors(evidence_set: KnowledgeEvidenceSet, claim_id: str) -> list[EvidenceAnchor]:
    """The anchors the claim cites, looked up in the set's own evidence."""
    anchors_by_id = index_anchors(evidence_set.evidence)
    claim_anchors: list[EvidenceAnchor] = []
    for claim in evidence_set.claims:
        if claim.claim_id == claim_id:
            for evidence_id in claim.evidence_ids:
                claim_anchors.append(anchors_by_id[evidence_id])
    return claim_anchors


def describe_outcomes(evidence_set: KnowledgeEvidenceSet) -> list[tuple[str, str]]:
    outcomes: list[tuple[str, str]] = []
    for source_outcome in evidence_set.coverage.source_outcomes:
        outcomes.append((source_outcome.source.value, source_outcome.status.value))
    return outcomes


def test_product_named_by_a_topic_record_still_has_unknown_applicability(
    fixture_bundle: FixtureBundle,
) -> None:
    bundle = build_bundle_with(
        fixture_bundle,
        OPEN5GS_CVE_ID,
        "[SYNTHETIC] Open5GS AUSF mishandles 5G-AKA resynchronization",
        affected=[{"vendor": "open5gs", "product": "open5gs", "status": "affected"}],
    )
    service = build_reviewed_investigation_service(bundle)

    evidence_set = service.investigate(
        build_investigation_request(
            "5gaka", "implementation_only", filters={"products": ["open5gs"]}
        )
    )

    assert list_step_tools(evidence_set) == ["topic_context"]
    assert list_implementation_ids(evidence_set) == [OPEN5GS_CVE_ID]
    assert evidence_set.implementation_candidates[0].found_by_steps == (1,)
    assert (evidence_set.stop_reason, evidence_set.status) == (
        StopReason.SOURCE_UNAVAILABLE,
        ResultStatus.PARTIAL,
    )
    assert evidence_set.product_applicability[0].product == "open5gs"
    assert evidence_set.product_applicability[0].status.value == "unknown"
    assert describe_outcomes(evidence_set) == [
        ("cve_search", "ok"),
        ("affectedness", "source_unavailable"),
    ]


def test_product_question_reports_the_server_sentence_for_the_port_reason(
    fixture_bundle: FixtureBundle,
) -> None:
    trustify_port = InMemoryTrustifyPort(
        failure=AffectednessFailure.SOURCE_UNAVAILABLE,
        described_failure=AffectednessFailure.AUTH_FAILED,
    )
    service = build_reviewed_investigation_service(fixture_bundle, trustify_port=trustify_port)

    evidence_set = service.investigate(
        build_investigation_request("5G-AKA", "implementation_only", filters={"products": ["f5gc"]})
    )

    affectedness_details: list[str | None] = []
    for source_outcome in evidence_set.coverage.source_outcomes:
        if source_outcome.source is KnowledgeSource.AFFECTEDNESS:
            affectedness_details.append(source_outcome.detail)
    assert (evidence_set.stop_reason, evidence_set.status) == (
        StopReason.SOURCE_UNAVAILABLE,
        ResultStatus.PARTIAL,
    )
    assert evidence_set.coverage.basis is DecisionBasis.AFFECTEDNESS_UNAVAILABLE
    assert affectedness_details == [AffectednessDetail.AUTH_FAILED]
    assert evidence_set.product_applicability[0].status.value == "unknown"


@pytest.mark.parametrize("query", ["5gaka", "5G-AKA", "5G AKA"])
def test_topic_question_under_implementation_only_explores_the_topic_without_fight(
    fixture_bundle: FixtureBundle, query: str
) -> None:
    service = build_test_investigation_service(fixture_bundle)

    evidence_set = service.investigate(build_investigation_request(query, "implementation_only"))

    backend_sources: set[KnowledgeSource] = set()
    for backend_request in evidence_set.trajectory.steps[0].backend_requests:
        backend_sources.add(backend_request.source)
    assert list_step_reasons(evidence_set) == [
        StepReason.REVIEWED_TOPIC,
        StepReason.QUERY_TERMS_FOR_OPEN_NEED,
    ]
    assert backend_sources == {KnowledgeSource.CVE_SEARCH}
    assert evidence_set.trajectory.budget_used.sources == (KnowledgeSource.CVE_SEARCH,)
    assert list_implementation_ids(evidence_set) == ["CVE-9999-0003", "CVE-9999-0004"]
    assert evidence_set.stop_reason is StopReason.NEEDS_UNMET


def test_failed_lexical_source_stops_the_run_without_refining(
    fixture_bundle: FixtureBundle,
) -> None:
    service = build_test_investigation_service(
        fixture_bundle, lexical_retriever=CannedRetriever(build_failure(BackendStatus.UNAVAILABLE))
    )

    evidence_set = service.investigate(build_investigation_request("5gaka", "implementation_only"))

    assert list_step_tools(evidence_set) == ["topic_context"]
    assert list_transitions(evidence_set)[-2] == ["assess", "validate", "answer_source_failed"]
    assert evidence_set.stop_reason is StopReason.SOURCE_UNAVAILABLE
    assert evidence_set.status is ResultStatus.SOURCE_UNAVAILABLE
    assert evidence_set.coverage.refinement_applied is False


def test_source_inventing_a_record_ends_in_invalid_evidence_with_an_empty_answer(
    fixture_bundle: FixtureBundle,
) -> None:
    service = build_test_investigation_service(
        fixture_bundle, lexical_retriever=InventingRetriever()
    )

    evidence_set = service.investigate(build_investigation_request("crash", "implementation_only"))

    step = evidence_set.trajectory.steps[0]
    assert (evidence_set.stop_reason, evidence_set.status) == (
        StopReason.INVALID_EVIDENCE,
        ResultStatus.BACKEND_ERROR,
    )
    assert step.admission is StepAdmission.REJECTED_INVALID_EVIDENCE
    assert step.result_sha256 is None
    assert evidence_set.implementation_candidates == ()
    assert evidence_set.claims == ()
    assert evidence_set.evidence == ()
    assert evidence_set.trajectory.budget_used.tool_calls == 1


@pytest.mark.parametrize(
    ("query", "scope", "expected_tools", "expected_outcomes"),
    [
        ("crash", "implementation_only", ["cve_search"], [("cve_search", "partial")]),
        (
            "5gaka",
            "mixed",
            ["topic_context"],
            [("cve_search", "partial"), ("mitre_fight", "ok")],
        ),
    ],
    ids=["cve_search", "topic_context"],
)
def test_semantic_search_without_an_adapter_reports_a_partial_answer(
    fixture_bundle: FixtureBundle,
    query: str,
    scope: str,
    expected_tools: list[str],
    expected_outcomes: list[tuple[str, str]],
) -> None:
    service = build_test_investigation_service(fixture_bundle)

    evidence_set = service.investigate(build_investigation_request(query, scope, semantic=True))

    assert list_step_tools(evidence_set) == expected_tools
    assert (evidence_set.stop_reason, evidence_set.status) == (
        StopReason.SOURCE_UNAVAILABLE,
        ResultStatus.PARTIAL,
    )
    assert list_implementation_ids(evidence_set) != []
    assert describe_outcomes(evidence_set) == expected_outcomes


@pytest.mark.parametrize(
    ("query", "scope", "expected_ids"),
    [
        (
            "CVE-9999-0007 5gaka",
            "implementation_only",
            ["CVE-9999-0007", "CVE-9999-0003", "CVE-9999-0004"],
        ),
        (
            "CVE-9999-0007 5gaka",
            "mixed",
            ["CVE-9999-0007", "CVE-9999-0003", "CVE-9999-0004"],
        ),
        (
            "CVE-9999-0001 5G-AKA",
            "implementation_only",
            ["CVE-9999-0001", "CVE-9999-0003", "CVE-9999-0004"],
        ),
        (
            "CVE-9999-0004 CVE-9999-0007 5gaka",
            "implementation_only",
            ["CVE-9999-0007", "CVE-9999-0004", "CVE-9999-0003"],
        ),
    ],
    ids=["unrelated_id_implementation", "unrelated_id_mixed", "hyphenated_alias", "two_ids"],
)
def test_cve_named_by_id_is_answered_first_and_the_named_topic_is_then_called_for_its_cves(
    fixture_bundle: FixtureBundle, query: str, scope: str, expected_ids: list[str]
) -> None:
    service = build_test_investigation_service(fixture_bundle)

    evidence_set = service.investigate(build_investigation_request(query, scope))

    assert list_step_tools(evidence_set) == ["cve_exact_lookup", "topic_context"]
    assert list_step_reasons(evidence_set) == [
        StepReason.QUERY_CVE_IDS,
        StepReason.TOPIC_FOR_OPEN_NEED,
    ]
    assert (evidence_set.stop_reason, evidence_set.status) == (
        StopReason.NEEDS_UNMET,
        ResultStatus.PARTIAL,
    )
    assert list_implementation_ids(evidence_set) == expected_ids
    assert "unrelated_candidates_dropped" not in list_warning_codes(evidence_set)


@pytest.mark.parametrize(
    ("query", "scope", "expected_ids"),
    [
        ("CVE-9999-0003和CVE-9999-0004的影响", "implementation_only", BOTH_NAMED_IDS),
        ("CVE-9999-0003和CVE-9999-0004的影响", "mixed", BOTH_NAMED_IDS),
        ("请查CVE-9999-0003", "implementation_only", ["CVE-9999-0003"]),
        ("CVE-9999-0003の脆弱性", "mixed", ["CVE-9999-0003"]),
        ("CVE-9999-0003เป็นช่องโหว่ อะไร", "implementation_only", ["CVE-9999-0003"]),
        ("ช่องโหว่CVE-9999-0003", "implementation_only", ["CVE-9999-0003"]),
        ("CVE-9999-0003ｾｷｭﾘﾃｨ", "implementation_only", ["CVE-9999-0003"]),
        ("CVE-9999-0003\u200b漏洞", "implementation_only", ["CVE-9999-0003"]),
        ("CVE\u20109999\u20100003", "implementation_only", ["CVE-9999-0003"]),
        ("CVE\u20119999\u20110003", "implementation_only", ["CVE-9999-0003"]),
        ("CVE\u20139999\u20130003", "mixed", ["CVE-9999-0003"]),
        ("CVE\u22129999\u22120003", "implementation_only", ["CVE-9999-0003"]),
    ],
    ids=[
        "chinese_two_ids",
        "chinese_two_ids_mixed",
        "chinese_before_the_id",
        "japanese_mixed",
        "thai_after_the_id",
        "thai_before_the_id",
        "halfwidth_katakana_after_the_id",
        "zero_width_space_then_chinese",
        "unicode_hyphen",
        "non_breaking_hyphen",
        "en_dash_mixed",
        "minus_sign",
    ],
)
def test_cve_id_written_against_non_latin_text_or_with_any_dash_is_looked_up(
    fixture_bundle: FixtureBundle, query: str, scope: str, expected_ids: list[str]
) -> None:
    service = build_test_investigation_service(fixture_bundle)

    evidence_set = service.investigate(build_investigation_request(query, scope))

    assert evidence_set.interpretation.intent is QueryIntent.EXACT_ID
    assert list(evidence_set.interpretation.cve_ids) == expected_ids
    assert list_step_tools(evidence_set) == ["cve_exact_lookup"]
    assert list_implementation_ids(evidence_set) == expected_ids


@pytest.mark.parametrize(
    "query",
    [
        "CVE-9999-0003\u0664",
        "CVE-9999-0003\u0967\u0968",
        "CVE-9999-0003\u3007",
        "CVE-9999-0003\u00b2",
        "CVE-2024-\u3251\u3251\u3251",
        "CVE-9999-000\u034f3",
        "CVE-9999-000\ufe0f3",
        "CVE-9999-000\u180b3",
        "CVE 9999 0003",
        "CVE_9999_0003",
        "\u0421VE-9999-0003",
        "CVE.9999.0003",
        "CVE:9999:0003",
        "CVE#9999-0003",
        "CVE--9999--0003",
        "CVE\u30fc9999\u30fc0003",
        "CVE-\u0669\u0669\u0669\u0669-\u0660\u0660\u0660\u0663",
        "CVE-\u096f\u096f\u096f\u096f-\u0966\u0966\u0966\u0969",
        "CVE-9999-000\u0663",
        "CVE ID 9999-0003",
        "CVE number 9999-0003",
        "CVE-9999-000 3",
        "CVE-9999-0,003",
        "CVE-999-0003",
        "\u1d04\u1d20\u1d07-9999-0003",
        "\u00c7VE-9999-0003",
        "\u03f9VE-9999-0003",
        "CVE-9999-0003\u200b4",
        "CVE-9999-0003\u00ad4",
        "CVE-9999-0003\ufeff4",
        "CVE-9999-0003\u20604",
        "CVE\u200b-9999-0003",
        "CVE-9999-0003\u00bc",
    ],
    ids=[
        "arabic_indic_digit",
        "devanagari_digits",
        "ideographic_zero",
        "superscript_two",
        "circled_number_digits",
        "combining_grapheme_joiner_inside",
        "variation_selector_inside",
        "mongolian_variation_selector_inside",
        "spaces_for_dashes",
        "underscores_for_dashes",
        "cyrillic_es_for_c",
        "full_stops_for_dashes",
        "colons_for_dashes",
        "number_sign_for_a_dash",
        "doubled_dashes",
        "katakana_prolonged_sound_marks_for_dashes",
        "arabic_indic_digits",
        "devanagari_digits",
        "arabic_indic_last_digit",
        "id_word_before_the_number",
        "number_word_before_the_number",
        "space_inside_the_number",
        "comma_grouped_number",
        "short_year",
        "latin_small_capitals_for_cve",
        "precomposed_c_cedilla_for_c",
        "greek_lunate_sigma_for_c",
        "zero_width_space_between_digits",
        "soft_hyphen_between_digits",
        "byte_order_mark_between_digits",
        "word_joiner_between_digits",
        "zero_width_space_before_a_dash",
        "vulgar_fraction_folding_into_digits",
    ],
)
@pytest.mark.parametrize("scope", ["implementation_only", "mixed"])
def test_malformed_id_is_neither_looked_up_nor_searched(
    fixture_bundle: FixtureBundle, query: str, scope: str
) -> None:
    service = build_test_investigation_service(fixture_bundle)

    evidence_set = service.investigate(build_investigation_request(query, scope))

    assert evidence_set.interpretation.cve_ids == ()
    assert evidence_set.interpretation.search_terms == ()
    assert list_step_tools(evidence_set) == []
    assert (evidence_set.stop_reason, evidence_set.coverage.basis) == (
        StopReason.NO_EVIDENCE,
        DecisionBasis.NO_SEARCHABLE_TERMS,
    )
    assert list_implementation_ids(evidence_set) == []


@pytest.mark.parametrize(
    "query",
    [
        "ausf crash cve in 2021 and 2022",
        "ausf crash nvdcve in 2021 and 2022",
        "ausf crash nvdcve cves 2021 2022",
        "ausf crash, cve: 2021, 2022",
        "ausf crash CVE.9999.0007",
    ],
    ids=[
        "stopword_between_cve_and_numbers",
        "stopword_between_a_word_ending_in_cve_and_numbers",
        "low_signal_word_between_a_word_ending_in_cve_and_numbers",
        "punctuation_between_parts",
        "near_id_beside_terms",
    ],
)
@pytest.mark.parametrize(
    ("scope", "expected_tools", "expected_stop"),
    [
        # A search on the question's own words leaves its matches unassessed.
        ("implementation_only", ["cve_search"], StopReason.NEEDS_UNMET),
        # No technique of the excerpt holds ``crash``, so the protocol need is not found.
        ("mixed", ["cve_search", "fight_direct_search"], StopReason.NEEDS_UNMET),
    ],
    ids=["implementation_only", "mixed_also_searching_fight_directly"],
)
def test_query_words_beside_an_id_likeness_are_searched_without_it(
    fixture_bundle: FixtureBundle,
    query: str,
    scope: str,
    expected_tools: list[str],
    expected_stop: StopReason,
) -> None:
    service = build_test_investigation_service(fixture_bundle)

    evidence_set = service.investigate(build_investigation_request(query, scope))

    assert evidence_set.interpretation.search_terms == ("ausf", "crash")
    assert evidence_set.interpretation.fight_terms == ("ausf", "crash")
    assert list_step_tools(evidence_set) == expected_tools
    assert evidence_set.trajectory.steps[0].backend_requests[0].query == "ausf crash"
    assert list_implementation_ids(evidence_set) == ["CVE-9999-0003"]
    assert evidence_set.stop_reason is expected_stop


@pytest.mark.parametrize(
    "query",
    ["CVE of 2021-44228", "the CVE is 2021-44228", "cve for 2021 44228"],
    ids=["of", "is", "for"],
)
@pytest.mark.parametrize("scope", ["implementation_only", "mixed"])
def test_near_id_with_a_stopword_after_the_word_cve_is_not_searched_for_its_numbers(
    fixture_bundle: FixtureBundle, query: str, scope: str
) -> None:
    citing_bundle = build_bundle_with(
        fixture_bundle,
        "CVE-2021-45046",
        "[SYNTHETIC] The fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete.",
    )
    service = build_test_investigation_service(citing_bundle)

    evidence_set = service.investigate(build_investigation_request(query, scope))

    assert evidence_set.interpretation.search_terms == ()
    assert list_step_tools(evidence_set) == []
    assert (evidence_set.stop_reason, evidence_set.coverage.basis) == (
        StopReason.NO_EVIDENCE,
        DecisionBasis.NO_SEARCHABLE_TERMS,
    )
    assert list_implementation_ids(evidence_set) == []


@pytest.mark.parametrize("query", ["cve", "CVEs", "CVE, cves"], ids=["word", "plural", "both"])
@pytest.mark.parametrize("scope", ["implementation_only", "mixed"])
def test_query_of_only_low_signal_words_stops_without_a_call(
    fixture_bundle: FixtureBundle, query: str, scope: str
) -> None:
    service = build_test_investigation_service(fixture_bundle)

    evidence_set = service.investigate(build_investigation_request(query, scope))

    assert evidence_set.interpretation.intent is QueryIntent.UNSEARCHABLE
    assert list_step_tools(evidence_set) == []
    assert (evidence_set.stop_reason, evidence_set.coverage.basis) == (
        StopReason.NO_EVIDENCE,
        DecisionBasis.NO_SEARCHABLE_TERMS,
    )
    assert list_implementation_ids(evidence_set) == []


@pytest.mark.parametrize(
    ("query", "expected_search_text", "expected_excluded_term"),
    [
        ("5G\u00e9aka threats", "5g threats", "aka"),
        ("\u00e9aka attacks", "attacks", "aka"),
        ("\u03b1aka attacks", "attacks", "aka"),
        ("\u3164aka attacks", "attacks", "aka"),
        ("\uffa0aka attacks", "attacks", "aka"),
        ("\u0665aka attacks", "attacks", "aka"),
        ("EAP-AKA\u02bc threats", "threats", "EAP-AKA'"),
        ("x\u200baka attacks", "x attacks", "aka"),
        ("5g\u200baka threats", "5g threats", "aka"),
        ("EAP\u200b-AKA' threats", "eap threats", "aka"),
    ],
    ids=[
        "accented_letter",
        "accented_letter_with_nothing_before",
        "greek_letter",
        "hangul_filler",
        "halfwidth_hangul_filler",
        "arabic_indic_digit",
        "modifier_letter_apostrophe",
        "zero_width_space",
        "zero_width_space_inside_the_topic_alias",
        "zero_width_space_splits_an_excluded_phrase",
    ],
)
def test_excluded_term_beside_a_non_ascii_or_format_character_is_left_out_of_the_search_sent(
    fixture_bundle: FixtureBundle,
    query: str,
    expected_search_text: str,
    expected_excluded_term: str,
) -> None:
    """Each of these spellings leaves the excluded word a registry word, so the excluded
    term is reported, warned and stripped before the search is built (not every spelling
    does; ADR 0002 §8)."""
    service = build_test_investigation_service(fixture_bundle)

    evidence_set = service.investigate(build_investigation_request(query, "implementation_only"))

    assert list_step_tools(evidence_set) == ["cve_search"]
    assert evidence_set.trajectory.steps[0].backend_requests[0].query == expected_search_text
    assert (
        InvestigationWarning(
            code=InvestigationWarningCode.EXCLUDED_TERM, subject=expected_excluded_term
        )
        in evidence_set.warnings
    )


@pytest.mark.parametrize("scope", ["implementation_only", "mixed"])
def test_excluded_alias_alone_after_a_non_ascii_letter_stops_with_its_warning_and_no_call(
    fixture_bundle: FixtureBundle, scope: str
) -> None:
    service = build_test_investigation_service(fixture_bundle)

    evidence_set = service.investigate(build_investigation_request("\u00e9aka", scope))

    assert list_step_tools(evidence_set) == []
    assert (evidence_set.stop_reason, evidence_set.coverage.basis) == (
        StopReason.NO_EVIDENCE,
        DecisionBasis.EXCLUDED_TERMS_ONLY,
    )
    assert (
        InvestigationWarning(code=InvestigationWarningCode.EXCLUDED_TERM, subject="aka")
        in evidence_set.warnings
    )


@pytest.mark.parametrize(
    ("query", "expected_search_text", "expected_cve_ids"),
    [
        ("cve ausf crash", "ausf crash", ["CVE-9999-0003"]),
        ("CVE 2022 log4j", "2022 log4j", []),
    ],
    ids=["before_terms", "before_a_year"],
)
@pytest.mark.parametrize(
    ("scope", "expected_tools"),
    [
        ("implementation_only", ["cve_search"]),
        ("mixed", ["cve_search", "fight_direct_search"]),
    ],
    ids=["implementation_only", "mixed"],
)
def test_low_signal_words_are_left_out_of_the_search_a_run_sends(
    fixture_bundle: FixtureBundle,
    query: str,
    expected_search_text: str,
    expected_cve_ids: list[str],
    scope: str,
    expected_tools: list[str],
) -> None:
    service = build_test_investigation_service(fixture_bundle)

    evidence_set = service.investigate(build_investigation_request(query, scope))

    assert list_step_tools(evidence_set) == expected_tools
    assert evidence_set.trajectory.steps[0].backend_requests[0].query == expected_search_text
    assert list_implementation_ids(evidence_set) == expected_cve_ids


@pytest.mark.parametrize(
    ("query", "budget", "expected_stop", "expected_basis"),
    [
        (TWENTY_ONE_IDS, {}, StopReason.POLICY_BLOCKED, DecisionBasis.CVE_IDS_OVER_LOOKUP_CAP),
        (
            "CVE-9999-0003 CVE-9999-0004",
            {"max_results_per_call": 1},
            StopReason.POLICY_BLOCKED,
            DecisionBasis.CVE_IDS_OVER_LOOKUP_CAP,
        ),
        (
            "CVE-2024-1234567890123456789012345678",
            {},
            StopReason.NO_EVIDENCE,
            DecisionBasis.NO_SEARCHABLE_TERMS,
        ),
    ],
    ids=[
        "more_ids_than_one_lookup",
        "more_ids_than_the_per_call_cap",
        "overlong_id",
    ],
)
def test_ids_one_lookup_cannot_carry_stop_the_run_before_any_call(
    fixture_bundle: FixtureBundle,
    query: str,
    budget: dict[str, int],
    expected_stop: StopReason,
    expected_basis: DecisionBasis,
) -> None:
    service = build_test_investigation_service(fixture_bundle)

    evidence_set = service.investigate(
        build_investigation_request(query, "implementation_only", budget=budget)
    )

    assert evidence_set.stop_reason is expected_stop
    assert evidence_set.coverage.basis is expected_basis
    assert evidence_set.trajectory.steps == ()


def test_exact_lookup_runs_under_the_request_filters(fixture_bundle: FixtureBundle) -> None:
    service = build_test_investigation_service(fixture_bundle)

    evidence_set = service.investigate(
        build_investigation_request(
            "CVE-9999-0003", "implementation_only", filters={"products": ["open5gs"]}
        )
    )

    step = evidence_set.trajectory.steps[0]
    search_warning_codes: list[str] = []
    for search_warning in step.search_warnings:
        search_warning_codes.append(search_warning.code.value)
    assert list_step_tools(evidence_set) == ["cve_exact_lookup"]
    assert step.answer_ids == ()
    assert search_warning_codes == ["excluded_by_filters"]
    assert evidence_set.implementation_candidates == ()
    assert (evidence_set.stop_reason, evidence_set.status) == (
        StopReason.SOURCE_UNAVAILABLE,
        ResultStatus.PARTIAL,
    )
    assert describe_outcomes(evidence_set) == [
        ("cve_search", "no_match"),
        ("affectedness", "source_unavailable"),
    ]


def test_threat_context_claim_traces_to_the_pinned_excerpt_bytes(
    fixture_bundle: FixtureBundle,
) -> None:
    service = build_test_investigation_service(fixture_bundle)
    _, pinned_fight_snapshot = load_packaged_fight_source(read_fixed_clock)
    assert pinned_fight_snapshot is not None
    excerpt_bytes = default_fight_fixture_dir().joinpath("fight-excerpt.yaml").read_bytes()

    evidence_set = service.investigate(
        build_investigation_request("5gaka", "protocol_context_only")
    )

    claim_anchors = find_claim_anchors(evidence_set, "fight:FGT5040")
    anchor = claim_anchors[0]
    techniques_by_id: dict[str, object] = {}
    for technique in yaml.safe_load(excerpt_bytes.decode("utf-8"))["techniques"]:
        techniques_by_id[technique["id"]] = technique
    assert len(claim_anchors) == 1
    assert anchor.source_type is SourceType.MITRE_FIGHT_YAML
    assert anchor.authoritative_record_id == "FGT5040"
    assert anchor.source_version == pinned_fight_snapshot.source_version
    assert sha256_hex(excerpt_bytes) == pinned_fight_snapshot.snapshot_sha256
    assert anchor.locator == "techniques[id=FGT5040]"
    assert anchor.content_sha256 == canonical_sha256(techniques_by_id["FGT5040"])


def test_implementation_claim_traces_to_the_fixture_record_bytes(
    fixture_bundle: FixtureBundle,
) -> None:
    service = build_test_investigation_service(fixture_bundle)
    records_document = json.loads(
        default_fixture_dir().joinpath("records.json").read_bytes().decode("utf-8")
    )

    evidence_set = service.investigate(
        build_investigation_request("CVE-9999-0003", "implementation_only")
    )

    claim_anchors = find_claim_anchors(evidence_set, "cve:CVE-9999-0003")
    anchor = claim_anchors[0]
    locator_match = re.fullmatch(r"records\.json#/records/(\d+)", anchor.locator)
    assert locator_match is not None
    record_entry = records_document["records"][int(locator_match.group(1))]
    assert len(claim_anchors) == 1
    assert anchor.authoritative_record_id == "CVE-9999-0003"
    assert record_entry["cve_id"] == "CVE-9999-0003"
    assert anchor.content_sha256 == canonical_sha256(record_entry)


def test_without_a_model_planner_every_round_is_planned_deterministically(
    fixture_bundle: FixtureBundle,
) -> None:
    service = build_test_investigation_service(fixture_bundle)

    evidence_set = service.investigate(
        build_investigation_request("CVE-9999-0003 5gaka", "implementation_only")
    )

    round_outcomes: list[PlannerOutcome] = []
    for round_record in evidence_set.trajectory.rounds:
        round_outcomes.append(round_record.planner_outcome)
    capability_states: dict[str, SourceCapabilityState] = {}
    for capability in evidence_set.source_capabilities:
        capability_states[str(capability.source)] = capability.state
    assert evidence_set.trajectory.planner == describe_deterministic_planner()
    assert round_outcomes == [PlannerOutcome.DETERMINISTIC, PlannerOutcome.DETERMINISTIC]
    assert evidence_set.trajectory.budget_used.planner_calls == 0
    assert capability_states["model_planner"] is SourceCapabilityState.NOT_CONFIGURED
    assert capability_states[KnowledgeSource.AFFECTEDNESS] is SourceCapabilityState.UNAVAILABLE


def build_semantic_channel_matching_anything() -> RecordingRetriever:
    """A semantic channel that answers CVE-9999-0003 whatever it is asked."""
    return RecordingRetriever(
        RetrievalOutcome(status=BackendStatus.OK, matches=(build_lexical_match("CVE-9999-0003"),))
    )


@pytest.mark.parametrize(
    "spelling", DISGUISED_LOW_SIGNAL_WORDS.values(), ids=DISGUISED_LOW_SIGNAL_WORDS.keys()
)
@pytest.mark.parametrize("scope", ["implementation_only", "mixed"])
def test_disguised_low_signal_word_stops_without_calling_a_wired_semantic_channel(
    fixture_bundle: FixtureBundle, spelling: str, scope: str
) -> None:
    semantic_channel = build_semantic_channel_matching_anything()
    service = build_test_investigation_service(fixture_bundle, semantic_retriever=semantic_channel)

    evidence_set = service.investigate(build_investigation_request(spelling, scope, semantic=True))

    assert semantic_channel.query_texts == []
    assert list_step_tools(evidence_set) == []
    assert (evidence_set.stop_reason, evidence_set.coverage.basis) == (
        StopReason.NO_EVIDENCE,
        DecisionBasis.NO_SEARCHABLE_TERMS,
    )
    assert list_implementation_ids(evidence_set) == []


@pytest.mark.parametrize(
    "spelling", DISGUISED_LOW_SIGNAL_WORDS.values(), ids=DISGUISED_LOW_SIGNAL_WORDS.keys()
)
def test_search_beside_a_disguised_low_signal_word_sends_only_the_other_words(
    fixture_bundle: FixtureBundle, spelling: str
) -> None:
    semantic_channel = build_semantic_channel_matching_anything()
    service = build_test_investigation_service(fixture_bundle, semantic_retriever=semantic_channel)

    evidence_set = service.investigate(
        build_investigation_request(f"{spelling} ausf", "implementation_only", semantic=True)
    )

    assert evidence_set.interpretation.search_terms == ("ausf",)
    assert semantic_channel.query_texts == ["ausf"]


@pytest.mark.parametrize(
    "query",
    ["CVE-9999-000\x073", "CVE-9999-000\x7f3", "CVE-9999-0003\u202e4", "CVE-9999-\u202e3000"],
    ids=[
        "bell_between_digits",
        "delete_between_digits",
        "direction_override_after_the_id",
        "direction_override_reversing_the_number",
    ],
)
@pytest.mark.parametrize("scope", ["implementation_only", "mixed"])
def test_id_with_a_hidden_character_inside_is_refused_before_any_run(
    query: str, scope: str
) -> None:
    with pytest.raises(ValidationError):
        build_investigation_request(query, scope)


# --- What the answer repeats from its steps -------------------------------------------


def describe_answer_warnings(evidence_set: KnowledgeEvidenceSet) -> list[tuple[str, str]]:
    answer_warnings: list[tuple[str, str]] = []
    for warning in evidence_set.warnings:
        answer_warnings.append((warning.code.value, warning.subject))
    return answer_warnings


def test_search_filling_the_per_call_limit_warns_at_the_top_that_the_limit_was_reached(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = investigate(
        fixture_bundle, "gateway", "implementation_only", budget={"max_results_per_call": 1}
    )

    assert describe_answer_warnings(evidence_set) == [("result_limit_reached", "1")]
    # The free-text match is listed, its relevance unassessed.
    assert (evidence_set.status, evidence_set.stop_reason) == (
        ResultStatus.PARTIAL,
        StopReason.NEEDS_UNMET,
    )


def test_protocol_context_only_topic_filling_the_per_call_limit_gives_no_top_level_limit_warning(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
) -> None:
    """The topic card's CVE searches reach the limit, but none of their CVEs can be in a
    protocol_context_only answer, so only the topic step says so."""
    evidence_set = investigate(
        fixture_bundle, "5gaka", "protocol_context_only", budget={"max_results_per_call": 1}
    )

    validate_knowledge_evidence_set(
        evidence_set,
        pinned_fight_snapshot,
        packaged_evidence_catalog,
        evidence_set.source_capabilities,
    )
    assert "result_limit_reached" not in list_warning_codes(evidence_set)
    topic_step_warnings: list[TopicContextWarning] = []
    for step in evidence_set.trajectory.steps:
        topic_step_warnings.extend(step.topic_warnings)
    assert (
        TopicContextWarning(code=TopicContextWarningCode.RESULT_LIMIT_REACHED, subject="1")
        in topic_step_warnings
    )


def test_search_within_the_per_call_limit_gives_no_limit_warning(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = investigate(fixture_bundle, "gateway", "implementation_only")

    assert len(evidence_set.trajectory.steps[0].answer_ids) == 2
    assert "result_limit_reached" not in list_warning_codes(evidence_set)


def test_cve_search_term_no_record_holds_is_named_at_the_top(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = investigate(fixture_bundle, "gatewy crash", "implementation_only")

    assert describe_answer_warnings(evidence_set) == [("term_not_indexed", "gatewy")]
    assert evidence_set.stop_reason is StopReason.NEEDS_UNMET


def test_direct_fight_search_term_no_technique_holds_is_named_at_the_top(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = run_fight_direct_search_of_an_unindexed_word(fixture_bundle)

    assert ("term_not_indexed", "threats") in describe_answer_warnings(evidence_set)
    assert evidence_set.stop_reason is StopReason.NEEDS_UNMET


def test_term_both_the_cve_and_the_fight_search_warn_about_is_named_once_at_the_top(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = investigate(fixture_bundle, "SUCI threats", "mixed")

    unindexed_terms: list[str] = []
    for code, subject in describe_answer_warnings(evidence_set):
        if code == "term_not_indexed":
            unindexed_terms.append(subject)
    cve_step, fight_step = evidence_set.trajectory.steps
    cve_side_warning = SearchWarning(code=SearchWarningCode.TERM_NOT_INDEXED, subject="threats")
    fight_side_warning = TopicContextWarning(
        code=TopicContextWarningCode.TERM_NOT_INDEXED, subject="threats"
    )
    assert cve_side_warning in cve_step.search_warnings
    assert fight_side_warning in fight_step.topic_warnings
    assert unindexed_terms == ["threats"]


# --- Filters the served dataset cannot execute ----------------------------------------


def test_purl_filter_over_records_naming_no_package_url_is_refused_naming_the_filter(
    fixture_bundle: FixtureBundle,
) -> None:
    service = build_test_investigation_service(
        fixture_bundle, structured_retriever=build_purl_free_structured_index(fixture_bundle)
    )
    request = build_investigation_request(
        "suci memory",
        "implementation_only",
        filters={"purls": ["pkg:generic/fictional5g/f5gc"]},
    )

    with pytest.raises(UnsupportedFilter) as raised:
        service.investigate(request)

    assert raised.value.filter_name == "purls"
    assert "pkg:generic" not in str(raised.value)
