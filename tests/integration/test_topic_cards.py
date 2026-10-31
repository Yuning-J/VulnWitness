"""Packaged topic cards load as validated, pending-review knowledge; bad cards fail loudly."""

import json
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.adapters.topics.yaml_cards import (
    TopicCardError,
    default_topic_dir,
    load_topic_cards,
)
from cve_kgrag.composition import build_topic_context_service
from cve_kgrag.domain.investigation import (
    InvestigationWarningCode,
    PlannerOutcome,
    StopReason,
)
from cve_kgrag.domain.planning import PlanRejectionCode
from cve_kgrag.domain.taxonomy import RetrievalChannel
from cve_kgrag.domain.text import tokenize
from cve_kgrag.domain.topic import RelevanceTier, ReviewStatus
from cve_kgrag.domain.topic_context import TopicContextRequest
from cve_kgrag.interfaces.investigation_summary import render_investigation_summary
from cve_kgrag.topics.registry import TopicRegistry
from cve_kgrag.topics.relevance import assess_relevance
from tests.support.builders import build_bundle_with
from tests.support.evaluation import run_deterministically
from tests.support.investigation import (
    build_investigation_request,
    build_test_investigation_service,
)
from tests.support.planners import ScriptedModelPort, build_plan_reply, build_text_reply


def test_packaged_5g_aka_card_is_pending_human_review() -> None:
    topics = load_topic_cards(default_topic_dir())

    card = topics[0]
    assert len(topics) == 2
    assert card.topic_id == "3gpp:5g-aka"
    assert card.review.status is ReviewStatus.PENDING_REVIEW
    assert card.review.reviewer is None
    assert card.exact_aliases == ("5G-AKA", "5G AKA", "5gaka")


def test_packaged_cards_validate_against_the_published_schema() -> None:
    schema_path = Path(__file__).parents[2] / "schemas/v2/protocol_topic.schema.json"
    validator = Draft202012Validator(json.loads(schema_path.read_text()))

    for card in load_topic_cards(default_topic_dir()):
        validator.validate(card.model_dump(mode="json"))
        assert card.review.status is ReviewStatus.PENDING_REVIEW
        assert card.review.reviewer is None
        assert card.review.reviewed_on is None


@pytest.mark.parametrize(
    ("query", "topic_id", "matched_alias"),
    [
        ("5G-AKA vulnerabilities", "3gpp:5g-aka", "5G-AKA"),
        ("GTP-U vulnerabilities in UPF", "3gpp:gtp", "GTP-U"),
        ("GTP-C vulnerabilities in mobile core", "3gpp:gtp", "GTP-C"),
        ("GTPv1-C flaws in SGSN", "3gpp:gtp", "GTPv1-C"),
        ("GTPv2-C flaws in PGW", "3gpp:gtp", "GTPv2-C"),
        ("GTPv1_U flaws in UPF", "3gpp:gtp", "GTPv1-U"),
        ("GTPv1", "3gpp:gtp", "GTPv1"),
        ("GTPv2", "3gpp:gtp", "GTPv2"),
        ("gtp2", "3gpp:gtp", "gtp2"),
        ("GTP vulnerabilities in mobile core", "3gpp:gtp", "GTP"),
    ],
)
def test_protocol_questions_record_the_alias_spelling(
    topic_registry: TopicRegistry, query: str, topic_id: str, matched_alias: str
) -> None:
    resolution = topic_registry.resolve(query)

    assert len(resolution.matches) == 1
    assert resolution.matches[0].topic_id == topic_id
    assert resolution.matches[0].matched_alias == matched_alias
    assert resolution.matches[0].review_status is ReviewStatus.PENDING_REVIEW


@pytest.mark.parametrize(
    "query",
    [
        "SMF vulnerabilities",
        "AMF Flash PyAMF vulnerabilities",
        "AMF",
        "PDU",
        "UDM",
        "SEAF",
        "TEID",
        "Wireshark dissector vulnerabilities",
        "5G authentication vulnerabilities in open-source cores",
    ],
)
def test_context_and_collisions_do_not_resolve_a_protocol(
    topic_registry: TopicRegistry, query: str
) -> None:
    assert topic_registry.resolve(query).matches == ()


@pytest.mark.parametrize(
    ("query", "description"),
    [
        ("5G AKA", "[SYNTHETIC] Open5GS Nausf_UEAuthentication_Authenticate crashes."),
        ("5G AKA", "[SYNTHETIC] AUSF compares RES* with XRES* incorrectly."),
        ("5G AKA", "[SYNTHETIC] SIDF SUCI de-concealment leaks memory."),
        ("GTP-C", "[SYNTHETIC] Open5GS ogs_gtp2_parse_tft mishandles a field."),
        ("GTP-C", "[SYNTHETIC] Open5GS ogs_gtp2_parse_bearer_qos mishandles a field."),
        ("GTP-C", "[SYNTHETIC] SGW mishandles CreateSessionRequest."),
        ("GTP-C", "[SYNTHETIC] GGSN mishandles CreatePDPContextRequest."),
        ("GTP-C", "[SYNTHETIC] osmo-ggsn gtp_decode_pdp_ctx corrupts PDP context memory."),
        ("GTP-U", "[SYNTHETIC] UPF mishandles the PDU Session Container."),
    ],
)
def test_evidence_forms_retrieve_candidates_with_pending_review_status(
    fixture_bundle: FixtureBundle, query: str, description: str
) -> None:
    cve_id = "CVE-9999-0901"
    bundle = build_bundle_with(fixture_bundle, cve_id, description)
    service = build_topic_context_service(bundle)

    response = service.explore(TopicContextRequest(query=query, scope="implementation_only"))

    assert any(
        candidate.candidate.record.cve_id == cve_id
        for candidate in response.implementation_candidates
    )
    assert response.resolution.matches[0].review_status is ReviewStatus.PENDING_REVIEW


@pytest.mark.parametrize(
    ("description", "tier"),
    [
        ("Open5GS EAP-AKA Authentication Response crashes.", "telecom_ecosystem_adjacent"),
        ("Open5GS Nudm_UEAuthentication_Get crashes in EAP-AKA.", "telecom_ecosystem_adjacent"),
        ("Open5GS Nausf_UEAuthentication_Authenticate crashes.", "telecom_ecosystem_adjacent"),
        (
            "Open5GS 5G-AKA and EAP-AKA Authentication Response crashes.",
            "explicit_protocol_mention",
        ),
        (
            "Open5GS checks HXRES* incorrectly during EAP-AKA fallback.",
            "protocol_component_implementation",
        ),
        ("Open5GS AUSF RES*/XRES* handling crashes.", "telecom_ecosystem_adjacent"),
    ],
)
def test_authentication_candidates_need_method_specific_evidence_to_confirm_5g_aka(
    fixture_bundle: FixtureBundle, description: str, tier: str
) -> None:
    empty_bundle = replace(fixture_bundle, records=(), evidence=())
    bundle = build_bundle_with(empty_bundle, "CVE-9999-0901", "[SYNTHETIC] " + description)
    service = build_topic_context_service(bundle)

    response = service.explore(TopicContextRequest(query="5G AKA", scope="implementation_only"))

    assert len(response.implementation_candidates) == 1
    candidate = response.implementation_candidates[0]
    assert candidate.candidate.record.cve_id == "CVE-9999-0901"
    assert candidate.relevance.tier is RelevanceTier(tier)


@pytest.mark.parametrize("query", ["GTP vulnerabilities", "GTP-U"])
@pytest.mark.parametrize(
    ("description", "tier"),
    [
        ("GTP iCommerce has a cross-site scripting flaw.", None),
        ("Open5GS GTP iCommerce has a cross-site scripting flaw.", None),
        ("Open5GS GTP-C Create Session Request crashes.", "explicit_protocol_mention"),
        ("Wireshark GTPv2 dissector crashes.", "explicit_protocol_mention"),
        ("GTP Echo Request crashes.", "explicit_protocol_mention"),
        ("GTP SGW handling crashes.", "explicit_protocol_mention"),
        ("Open5GS SMF overflows on a crafted GTP packet.", "explicit_protocol_mention"),
        ("GTP S11 handling crashes.", "explicit_protocol_mention"),
        ("GTP ogs_gtp2_parse_tft crashes.", "explicit_protocol_mention"),
    ],
)
def test_gtp_family_candidates_require_protocol_context_without_a_dissector_blacklist(
    fixture_bundle: FixtureBundle, query: str, description: str, tier: str | None
) -> None:
    empty_bundle = replace(fixture_bundle, records=(), evidence=())
    bundle = build_bundle_with(empty_bundle, "CVE-9999-0901", "[SYNTHETIC] " + description)
    service = build_topic_context_service(bundle)

    response = service.explore(TopicContextRequest(query=query, scope="implementation_only"))
    investigation = run_deterministically(bundle, query, "implementation_only")

    expected_alias = "GTP-U" if query == "GTP-U" else "GTP"
    assert response.resolution.matches[0].matched_alias == expected_alias
    if tier is None:
        assert response.implementation_candidates == ()
        assert investigation.implementation_candidates == ()
        assert any(warning.code == "unrelated_candidates_dropped" for warning in response.warnings)
        assert response.status.value == "no_match"
        assert investigation.stop_reason.value == "no_evidence"
    else:
        assert len(response.implementation_candidates) == 1
        assert response.implementation_candidates[0].relevance.tier is RelevanceTier(tier)
        assert investigation.stop_reason.value == "needs_unmet"


@pytest.mark.parametrize("function", ["SMF", "PGW", "SGW", "MME", "UPF", "GGSN", "SGSN"])
def test_explicit_gtp_with_network_function_context_is_retained(
    fixture_bundle: FixtureBundle, topic_registry: TopicRegistry, function: str
) -> None:
    empty_bundle = replace(fixture_bundle, records=(), evidence=())
    bundle = build_bundle_with(
        empty_bundle,
        "CVE-2026-37198",
        f"[SYNTHETIC REPRODUCTION] Open5GS {function} overflows on a crafted GTP packet.",
    )
    topic = topic_registry.get_topic("3gpp:gtp")
    assert topic is not None

    relevance = assess_relevance(bundle.records[0], topic.topic, {RetrievalChannel.LEXICAL})
    response = build_topic_context_service(bundle).explore(
        TopicContextRequest(query="GTP vulnerabilities", scope="implementation_only")
    )
    investigation = run_deterministically(bundle, "GTP vulnerabilities", "implementation_only")

    assert relevance is not None
    assert relevance.tier is RelevanceTier.EXPLICIT_PROTOCOL_MENTION
    assert function in relevance.matched_terms
    assert len(response.implementation_candidates) == 1
    assert response.implementation_candidates[0].candidate.record.cve_id == "CVE-2026-37198"
    assert response.implementation_candidates[0].relevance == relevance
    assert not any(warning.code == "unrelated_candidates_dropped" for warning in response.warnings)
    assert investigation.implementation_candidates[0].relevance == relevance
    assert investigation.stop_reason.value == "needs_unmet"


def test_smf_without_gtp_has_no_gtp_relevance(
    fixture_bundle: FixtureBundle, topic_registry: TopicRegistry
) -> None:
    bundle = build_bundle_with(
        fixture_bundle,
        "CVE-9999-0901",
        "[SYNTHETIC] Open5GS SMF overflows on a crafted packet.",
    )
    topic = topic_registry.get_topic("3gpp:gtp")
    assert topic is not None

    assert assess_relevance(bundle.records[-1], topic.topic, {RetrievalChannel.LEXICAL}) is None
    assert topic_registry.resolve("SMF vulnerabilities").matches == ()


@pytest.mark.parametrize(
    ("alias", "other_branch"),
    [("GTP-U", "GTP-C"), ("GTP-C", "GTP-U"), ("GTPv1-U", "GTPv2-C"), ("GTPv2-C", "GTP-U")],
)
def test_branch_questions_show_family_scope_in_the_answer_and_keep_other_branches(
    fixture_bundle: FixtureBundle, alias: str, other_branch: str
) -> None:
    empty_bundle = replace(fixture_bundle, records=(), evidence=())
    bundle = build_bundle_with(
        empty_bundle,
        "CVE-9999-0901",
        f"[SYNTHETIC] Open5GS {other_branch} packet handling crashes.",
    )
    query = f"{alias} vulnerabilities"

    response = build_topic_context_service(bundle).explore(
        TopicContextRequest(query=query, scope="implementation_only")
    )
    investigation = run_deterministically(bundle, query, "implementation_only")
    summary = " ".join(render_investigation_summary(investigation).split())

    assert response.resolution.matches[0].matched_alias == alias
    assert len(response.implementation_candidates) == 1
    assert len(investigation.implementation_candidates) == 1
    for answer in (response, investigation):
        notes = []
        for warning in answer.warnings:
            if warning.code == "topic_family_scope":
                notes.append(warning.subject)
        assert len(notes) == 1
        assert f"matched_alias={alias}" in notes[0]
        assert "GTP-C and GTP-U" in notes[0]
        assert "not limited" in notes[0]
    assert "GTP family" in summary
    assert "not limited to GTP-C or GTP-U" in summary


@pytest.mark.parametrize("query", ["5G AKA", "GTP-U"])
def test_investigation_answers_keep_the_pending_review_warning(
    fixture_bundle: FixtureBundle, query: str
) -> None:
    evidence_set = run_deterministically(fixture_bundle, query, "implementation_only")

    assert any(
        warning.code is InvestigationWarningCode.TOPIC_PENDING_REVIEW
        for warning in evidence_set.warnings
    )


@pytest.mark.parametrize("alias", ["GTP", "GTP-U"])
def test_gtp_malformed_round_two_without_budget_keeps_the_answer_and_stops_budget_exhausted(
    fixture_bundle: FixtureBundle, alias: str
) -> None:
    """Six CVE templates and FiGHT spend seven calls; the extra round-one search uses the
    eighth, so the fallback for a malformed round-two plan does not fit (a known limit)."""
    bundle = build_bundle_with(
        fixture_bundle, "CVE-9999-0901", "[SYNTHETIC] Open5GS GTP-C packet handling crashes."
    )
    query = f"{alias} vulnerabilities in mobile core"
    model_port = ScriptedModelPort(
        [
            build_plan_reply(
                {"tool": "topic_context", "topic_id": "3gpp:gtp"},
                {"tool": "cve_search", "query": "GTP"},
            ),
            build_text_reply("malformed round-two plan"),
        ]
    )
    service = build_test_investigation_service(bundle, model_port=model_port)

    evidence_set = service.investigate(build_investigation_request(query, "mixed"))

    first_round, second_round = evidence_set.trajectory.rounds
    assert first_round.planner_outcome is PlannerOutcome.MODEL_ACCEPTED
    assert second_round.planner_outcome is PlannerOutcome.MODEL_REJECTED
    rejection_codes = []
    for rejection in second_round.rejections:
        rejection_codes.append(rejection.code)
    assert PlanRejectionCode.MALFORMED_PLAN in rejection_codes
    assert PlanRejectionCode.OVER_TOOL_CALL_BUDGET in rejection_codes
    topic_step, extra_search = evidence_set.trajectory.steps
    assert topic_step.charged_tool_calls == 7
    assert extra_search.round_number == 1
    assert evidence_set.trajectory.budget_used.tool_calls == 8
    assert evidence_set.stop_reason is StopReason.BUDGET_EXHAUSTED
    answer_ids = []
    for candidate in evidence_set.implementation_candidates:
        answer_ids.append(candidate.candidate.record.cve_id)
    assert "CVE-9999-0901" in answer_ids
    assert evidence_set.interpretation.resolution.matches[0].matched_alias == alias
    family_notes = []
    for warning in evidence_set.warnings:
        if warning.code is InvestigationWarningCode.TOPIC_FAMILY_SCOPE:
            family_notes.append(warning.subject)
    assert len(family_notes) == 1
    assert f"matched_alias={alias}" in family_notes[0]
    assert "GTP-C and GTP-U" in family_notes[0]
    assert "not limited" in family_notes[0]
    summary = " ".join(render_investigation_summary(evidence_set).split())
    assert "not limited to GTP-C or GTP-U" in summary


@pytest.mark.parametrize(
    "description",
    [
        "[SYNTHETIC] Flash AMF deserialization in PyAMF.",
        "[SYNTHETIC] SMF vulnerabilities in a forum package.",
        "[SYNTHETIC] PDU power controller crashes.",
        "[SYNTHETIC] TEID in a processor fault diagnostic.",
    ],
)
def test_colliding_records_have_no_topic_relevance(
    fixture_bundle: FixtureBundle, topic_registry: TopicRegistry, description: str
) -> None:
    bundle = build_bundle_with(fixture_bundle, "CVE-9999-0901", description)
    record = bundle.records[-1]

    for registered in topic_registry.list_topics():
        assert assess_relevance(record, registered.topic, {RetrievalChannel.LEXICAL}) is None


@pytest.mark.parametrize(
    ("identifier", "expected"),
    [
        ("Nausf_UEAuthentication_Authenticate", ["nausf", "ueauthentication", "authenticate"]),
        ("ogs_gtp2_parse_tft", ["ogs", "gtp2", "parse", "tft"]),
        ("GTPv2", ["gtpv2"]),
    ],
)
def test_evidence_identifiers_use_the_existing_tokenizer_forms(
    topic_registry: TopicRegistry, identifier: str, expected: list[str]
) -> None:
    query_tokens: set[str] = set()
    for registered in topic_registry.list_topics():
        for template in registered.topic.query_templates:
            query_tokens.update(tokenize(template))

    assert tokenize(identifier) == expected
    assert set(expected) <= query_tokens


@pytest.mark.parametrize(
    "card_text",
    [
        "topic_id: [unclosed",
        "topic_id: 'not a valid id'\n",
        (default_topic_dir() / "3gpp-5g-aka.yaml").read_text(encoding="utf-8") + "exclusions: []\n",
    ],
    ids=["invalid_yaml", "contract_violation", "duplicate_key_hiding_a_reviewed_field"],
)
def test_invalid_card_fails_the_whole_load(tmp_path: Path, card_text: str) -> None:
    (tmp_path / "broken.yaml").write_text(card_text, encoding="utf-8")

    with pytest.raises(TopicCardError, match=r"broken\.yaml"):
        load_topic_cards(tmp_path)


def test_files_without_the_card_suffix_are_ignored(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("not a card", encoding="utf-8")

    assert load_topic_cards(tmp_path) == []


def test_card_that_is_not_utf8_fails_with_its_file_name(tmp_path: Path) -> None:
    (tmp_path / "latin1.yaml").write_bytes(b"topic_id: 'caf\xe9'\n")

    with pytest.raises(TopicCardError, match=r"latin1\.yaml"):
        load_topic_cards(tmp_path)


def test_pending_card_naming_a_reviewer_is_rejected(tmp_path: Path) -> None:
    card_text = (default_topic_dir() / "3gpp-5g-aka.yaml").read_text(encoding="utf-8")
    (tmp_path / "card.yaml").write_text(
        card_text.replace("reviewer: null", "reviewer: someone"), encoding="utf-8"
    )

    with pytest.raises(TopicCardError, match="reviewer"):
        load_topic_cards(tmp_path)


def test_only_yaml_suffixed_files_are_cards(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("topic_id: [unclosed", encoding="utf-8")

    assert load_topic_cards(tmp_path) == []


def test_no_packaged_card_has_a_contextual_alias() -> None:
    """A contextual alias written without its context is reported neither as a match nor
    as an excluded term, so ``find_fight_block`` cannot see it and the query's words would
    reach a direct FiGHT search. A card that gains one must revisit that rule first
    (docs/rebuild/m7b-c-fight-direct-search.md §3)."""
    topics = load_topic_cards(default_topic_dir())

    cards_with_contextual_aliases: list[str] = []
    for topic in topics:
        if topic.contextual_aliases:
            cards_with_contextual_aliases.append(topic.topic_id)

    assert topics != []
    assert cards_with_contextual_aliases == []
