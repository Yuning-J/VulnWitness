"""The published v2 schemas refuse what the server refuses for every rule they state:
each model's parse rules, the shape of every timestamp and date, and the evidence-set
validator's single-payload rules (the planner kind, each round's reply and rejections,
the stop reason's statuses, the scopes and the capabilities). The rules no JSON Schema
can state stay server-side and their fields say so: recomputed hashes and IDs, the
deployment's catalog and capabilities, and the trajectory's re-derivation.

Each rejected case starts from a genuine payload, which validates, and breaks one rule.
"""

import json
from collections.abc import Callable
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, TypeAdapter, ValidationError

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.adapters.topics.yaml_cards import default_topic_dir, load_topic_cards
from cve_kgrag.adapters.trustify.disabled_trustify_adapter import DisabledTrustifyAdapter
from cve_kgrag.application.affectedness import check_affectedness
from cve_kgrag.application.evidence_set_verification import check_evidence_set
from cve_kgrag.composition import (
    build_search_service,
    build_topic_context_service,
    build_topic_registry,
    load_packaged_fight_source,
)
from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.evidence_set_verification_report import MAX_VIOLATION_CHARS
from cve_kgrag.domain.http_rejection import (
    HTTP_REJECTION_MESSAGES,
    HttpRejectionCode,
    build_http_rejection,
)
from cve_kgrag.domain.investigation import FightUnavailableDetail, KnowledgeEvidenceSet
from cve_kgrag.domain.investigation_validation import validate_knowledge_evidence_set
from cve_kgrag.domain.planning import ModelPlannerUnavailableDetail, ModelReplyFailureDetail
from cve_kgrag.domain.search import SearchRequest, SemanticUnavailableDetail
from cve_kgrag.domain.taxonomy import BackendFailureDetail
from cve_kgrag.domain.timestamps import CalendarDate, Timestamp
from cve_kgrag.domain.tool_contracts import (
    TOOL_FAILURE_MESSAGES,
    ConceptResolution,
    EvidenceLookup,
    InvalidField,
    KnowledgeCapabilities,
    ToolFailure,
    ToolFailureCode,
)
from cve_kgrag.domain.topic import ProtocolTopic
from cve_kgrag.domain.topic_context import TopicContextRequest
from cve_kgrag.domain.validation import EvidenceValidationError
from cve_kgrag.schema_snapshots import REQUEST_CONTRACTS, RESPONSE_CONTRACTS
from tests.support.affectedness import build_affectedness_request
from tests.support.clocks import read_fixed_clock
from tests.support.investigation import (
    FightChoice,
    build_test_deployment,
    build_test_investigation_service,
    reseal_evidence_set,
)
from tests.support.investigation_runs import (
    forge_set_whose_replay_differs,
    run_cve_under_protocol_scope,
    run_exact_id,
    run_five_g_aka_mixed,
    run_free_text_under_a_model_planner,
    run_model_accepted,
    run_model_not_consulted,
    run_model_refinement_unavailable,
    run_model_rejected,
    run_model_unavailable,
    run_open5gs_product_question,
    run_planner_adapter_unusable,
    run_planner_without_a_key,
    run_policy_plan_over_budget,
    run_refinement,
    run_with_invalid_evidence,
)
from tests.support.paths import REPOSITORY_SCHEMA_DIR
from tests.support.planners import DETERMINISTIC_VERIFIER

CONTRACT_MODELS: dict[str, type[BaseModel]] = {**REQUEST_CONTRACTS, **RESPONSE_CONTRACTS}
EARLIER_SCHEMA_VERSION = "2.0.0-dev.8"
JsonObject = dict[str, Any]
PayloadBuilder = Callable[[FixtureBundle], BaseModel]
EvidenceSetRun = Callable[[FixtureBundle], KnowledgeEvidenceSet]
PayloadForgery = Callable[[JsonObject], None]


def list_schema_errors(contract_name: str, payload: JsonObject) -> list[str]:
    schema = json.loads((REPOSITORY_SCHEMA_DIR / f"{contract_name}.schema.json").read_text())
    schema_errors: list[str] = []
    for schema_error in Draft202012Validator(schema).iter_errors(payload):
        schema_errors.append(schema_error.message)
    return schema_errors


def search_ausf(fixture_bundle: FixtureBundle) -> BaseModel:
    return build_search_service(fixture_bundle).search(SearchRequest(query="ausf suci"))


def explore_five_g_aka_mixed(fixture_bundle: FixtureBundle) -> BaseModel:
    """A FiGHT outcome that names its snapshot beside the CVE search outcome."""
    topic_context_service = build_topic_context_service(fixture_bundle)
    return topic_context_service.explore(TopicContextRequest(query="5G-AKA", scope="mixed"))


def find_record(fixture_bundle: FixtureBundle, cve_id: str) -> BaseModel:
    for record in fixture_bundle.records:
        if record.cve_id == cve_id:
            return record
    raise AssertionError(f"the fixture holds no {cve_id}")


def load_record_with_exact_version(fixture_bundle: FixtureBundle) -> BaseModel:
    return find_record(fixture_bundle, "CVE-9999-0003")


def load_record_with_upper_bound(fixture_bundle: FixtureBundle) -> BaseModel:
    return find_record(fixture_bundle, "CVE-9999-0001")


def load_first_anchor(fixture_bundle: FixtureBundle) -> BaseModel:
    return fixture_bundle.evidence[0]


def load_pending_topic_card(fixture_bundle: FixtureBundle) -> BaseModel:
    return load_topic_cards(default_topic_dir())[0]


def load_reviewed_topic_card(fixture_bundle: FixtureBundle) -> BaseModel:
    """The packaged card with a complete review: a reviewer and a review date."""
    card_fields = load_topic_cards(default_topic_dir())[0].model_dump(mode="json")
    card_fields["review"].update(
        {"status": "reviewed", "reviewer": "a reviewer", "reviewed_on": "2026-10-01"}
    )
    return ProtocolTopic.model_validate(card_fields)


def describe_capabilities_with(
    fixture_bundle: FixtureBundle, fight_choice: FightChoice
) -> KnowledgeCapabilities:
    """The capabilities of a deterministic service over the fixture and ``fight_choice``."""
    service = build_test_investigation_service(fixture_bundle, fight=fight_choice)
    return KnowledgeCapabilities(source_capabilities=service.describe_capabilities())


def describe_packaged_capabilities(fixture_bundle: FixtureBundle) -> BaseModel:
    return describe_capabilities_with(fixture_bundle, "packaged")


def describe_capabilities_without_fight(fixture_bundle: FixtureBundle) -> BaseModel:
    """An unavailable FiGHT source beside the unavailable affectedness source."""
    return describe_capabilities_with(fixture_bundle, "unavailable")


def describe_capabilities_without_a_planner_key(fixture_bundle: FixtureBundle) -> BaseModel:
    """A configured model planner without a key beside the unavailable affectedness source."""
    service = build_test_investigation_service(
        fixture_bundle, planner_unavailable_detail=ModelPlannerUnavailableDetail.MISSING_API_KEY
    )
    return KnowledgeCapabilities(source_capabilities=service.describe_capabilities())


def describe_capabilities_with_an_unusable_semantic_adapter(
    fixture_bundle: FixtureBundle,
) -> BaseModel:
    """An enabled semantic channel whose adapter could not load."""
    service = build_test_investigation_service(
        fixture_bundle, semantic_retriever=SemanticUnavailableDetail.ADAPTER_UNUSABLE
    )
    return KnowledgeCapabilities(source_capabilities=service.describe_capabilities())


def resolve_five_g_aka(fixture_bundle: FixtureBundle) -> BaseModel:
    return ConceptResolution(resolution=build_topic_registry().resolve("5G-AKA"))


def look_up_first_anchor(fixture_bundle: FixtureBundle) -> BaseModel:
    return EvidenceLookup(evidence=fixture_bundle.evidence[0])


def check_blocked_affectedness(fixture_bundle: FixtureBundle) -> BaseModel:
    return check_affectedness(
        DisabledTrustifyAdapter(), build_affectedness_request(), timeout_seconds=8.0
    )


def verify_a_genuine_set(fixture_bundle: FixtureBundle) -> BaseModel:
    return check_evidence_set(
        run_exact_id(fixture_bundle).model_dump_json().encode(),
        build_test_deployment(fixture_bundle),
        DETERMINISTIC_VERIFIER,
    )


def verify_malformed_bytes(fixture_bundle: FixtureBundle) -> BaseModel:
    return check_evidence_set(
        b'{"unknown_field": 1}', build_test_deployment(fixture_bundle), DETERMINISTIC_VERIFIER
    )


def verify_a_set_whose_replay_differs(fixture_bundle: FixtureBundle) -> BaseModel:
    return check_evidence_set(
        forge_set_whose_replay_differs(fixture_bundle).model_dump_json().encode(),
        build_test_deployment(fixture_bundle, fight="failing"),
        DETERMINISTIC_VERIFIER,
    )


def fail_with_invalid_arguments(fixture_bundle: FixtureBundle) -> BaseModel:
    return ToolFailure(
        code=ToolFailureCode.INVALID_ARGUMENTS,
        message=TOOL_FAILURE_MESSAGES[ToolFailureCode.INVALID_ARGUMENTS],
        invalid_fields=(InvalidField(location="limit", error_type="int_type"),),
        unexpected_field_count=1,
    )


def reject_a_request_without_the_token(fixture_bundle: FixtureBundle) -> BaseModel:
    return build_http_rejection(HttpRejectionCode.UNAUTHORIZED)


GENUINE_PAYLOADS: list[tuple[str, PayloadBuilder]] = [
    ("knowledge_evidence_set", run_exact_id),
    ("knowledge_evidence_set", run_five_g_aka_mixed),
    ("knowledge_evidence_set", run_refinement),
    ("knowledge_evidence_set", run_cve_under_protocol_scope),
    ("knowledge_evidence_set", run_model_accepted),
    ("knowledge_evidence_set", run_model_rejected),
    ("knowledge_evidence_set", run_model_unavailable),
    ("knowledge_evidence_set", run_model_not_consulted),
    ("knowledge_evidence_set", run_free_text_under_a_model_planner),
    ("knowledge_evidence_set", run_with_invalid_evidence),
    ("knowledge_evidence_set", run_policy_plan_over_budget),
    ("knowledge_evidence_set", run_open5gs_product_question),
    ("knowledge_evidence_set", run_planner_without_a_key),
    ("knowledge_evidence_set", run_planner_adapter_unusable),
    ("search_response", search_ausf),
    ("topic_context_response", explore_five_g_aka_mixed),
    ("cve_record", load_record_with_exact_version),
    ("cve_record", load_record_with_upper_bound),
    ("evidence_anchor", load_first_anchor),
    ("protocol_topic", load_pending_topic_card),
    ("protocol_topic", load_reviewed_topic_card),
    ("knowledge_capabilities", describe_packaged_capabilities),
    ("knowledge_capabilities", describe_capabilities_without_fight),
    ("knowledge_capabilities", describe_capabilities_without_a_planner_key),
    ("knowledge_capabilities", describe_capabilities_with_an_unusable_semantic_adapter),
    ("concept_resolution", resolve_five_g_aka),
    ("evidence_lookup", look_up_first_anchor),
    ("affectedness_check", check_blocked_affectedness),
    ("tool_failure", fail_with_invalid_arguments),
    ("http_rejection", reject_a_request_without_the_token),
    ("verification_report", verify_a_genuine_set),
    ("verification_report", verify_malformed_bytes),
    ("verification_report", verify_a_set_whose_replay_differs),
]
GENUINE_PAYLOAD_IDS: list[str] = []
for _, genuine_builder in GENUINE_PAYLOADS:
    GENUINE_PAYLOAD_IDS.append(genuine_builder.__name__)


@pytest.mark.parametrize(
    ("contract_name", "build_payload"),
    GENUINE_PAYLOADS,
    ids=GENUINE_PAYLOAD_IDS,
)
def test_genuine_payload_is_valid_under_its_published_schema(
    fixture_bundle: FixtureBundle, contract_name: str, build_payload: PayloadBuilder
) -> None:
    payload = build_payload(fixture_bundle).model_dump(mode="json")

    assert list_schema_errors(contract_name, payload) == []


def claim_an_earlier_schema_version(payload: JsonObject) -> None:
    payload["schema_version"] = EARLIER_SCHEMA_VERSION


def claim_the_product_is_not_affected(payload: JsonObject) -> None:
    payload["product_applicability"][0]["basis"] = "Not affected: open5gs 2.7.0 is fixed."


def name_a_policy_version_for_the_model(payload: JsonObject) -> None:
    payload["trajectory"]["planner"]["policy_version"] = "m4.1"


def name_a_model_for_the_policy(payload: JsonObject) -> None:
    payload["trajectory"]["planner"]["model_name"] = "gpt"


def add_detail_to_the_accepted_reply(payload: JsonObject) -> None:
    payload["trajectory"]["rounds"][0]["model_reply"]["detail"] = (
        ModelReplyFailureDetail.UNREACHABLE.value
    )


def quote_the_key_in_the_failed_reply(payload: JsonObject) -> None:
    payload["trajectory"]["rounds"][0]["model_reply"]["detail"] = "401: Bearer sk-test-key"


def claim_no_reply_was_recorded(payload: JsonObject) -> None:
    payload["trajectory"]["rounds"][0]["model_reply"]["detail"] = (
        "no reply is recorded for this round"
    )


def drop_the_endpoint_from_the_model_identity(payload: JsonObject) -> None:
    del payload["trajectory"]["planner"]["endpoint_sha256"]


def drop_the_plan_text_from_the_accepted_reply(payload: JsonObject) -> None:
    payload["trajectory"]["rounds"][0]["model_reply"]["plan_text"] = None


def add_plan_text_to_the_failed_reply(payload: JsonObject) -> None:
    payload["trajectory"]["rounds"][0]["model_reply"]["plan_text"] = '{"steps": []}'


def give_the_responseless_step_a_status(payload: JsonObject) -> None:
    payload["trajectory"]["steps"][0]["status"] = "ok"


def give_the_responseless_step_context_bytes(payload: JsonObject) -> None:
    payload["trajectory"]["steps"][0]["context_bytes"] = 1


def drop_the_admitted_step_hash(payload: JsonObject) -> None:
    payload["trajectory"]["steps"][0]["result_sha256"] = None


def keep_the_snapshot_of_a_failed_source(payload: JsonObject) -> None:
    fight_outcome = payload["source_outcomes"][0]
    assert fight_outcome["source_version"] is not None
    fight_outcome["status"] = "source_unavailable"


def add_a_bound_to_the_exact_version(payload: JsonObject) -> None:
    payload["affected"][0]["version_ranges"][0]["start_including"] = "3.0.0"


def drop_the_only_bound(payload: JsonObject) -> None:
    payload["affected"][0]["version_ranges"][0]["end_excluding"] = None


def name_an_inference_method_for_an_asserted_anchor(payload: JsonObject) -> None:
    payload["inference_method"] = "co-occurrence"


def mark_the_anchor_inferred_without_a_method(payload: JsonObject) -> None:
    payload["assertion_kind"] = "inferred"


def mark_the_card_reviewed_without_a_reviewer(payload: JsonObject) -> None:
    payload["review"]["status"] = "reviewed"


def name_a_reviewer_for_the_pending_card(payload: JsonObject) -> None:
    payload["review"]["reviewer"] = "a reviewer"


def write_a_retrieval_time_that_is_no_date(payload: JsonObject) -> None:
    payload["evidence"][0]["retrieved_at"] = "not-a-date"


def drop_the_start_time_offset(payload: JsonObject) -> None:
    payload["timings"]["started_at"] = "2026-10-01T00:00:00"


def drop_the_publication_time_offset(payload: JsonObject) -> None:
    payload["published"] = "2026-10-01T00:00:00"


def write_a_review_date_that_is_no_date(payload: JsonObject) -> None:
    payload["review"].update(
        {"status": "reviewed", "reviewer": "a reviewer", "reviewed_on": "last week"}
    )


def write_a_start_time_out_of_range(payload: JsonObject) -> None:
    payload["timings"]["started_at"] = "2026-99-99T99:99:99Z"


def write_a_review_date_out_of_range(payload: JsonObject) -> None:
    payload["review"].update(
        {"status": "reviewed", "reviewer": "a reviewer", "reviewed_on": "2026-99-99"}
    )


def write_a_review_date_on_a_day_its_year_lacks(payload: JsonObject) -> None:
    payload["review"].update(
        {"status": "reviewed", "reviewer": "a reviewer", "reviewed_on": "2026-02-29"}
    )


def end_the_start_time_with_a_newline(payload: JsonObject) -> None:
    payload["timings"]["started_at"] += "\n"


def end_the_review_date_with_a_newline(payload: JsonObject) -> None:
    payload["review"].update(
        {"status": "reviewed", "reviewer": "a reviewer", "reviewed_on": "2026-10-01\n"}
    )


def end_the_cve_id_with_a_newline(payload: JsonObject) -> None:
    payload["cve_id"] += "\n"


def claim_the_product_affected(payload: JsonObject) -> None:
    payload["applicability"] = "affected"


def drop_the_failure(payload: JsonObject) -> None:
    del payload["failure"]


def report_the_failure_ok(payload: JsonObject) -> None:
    payload["failure"] = "ok"


def list_twenty_one_invalid_fields(payload: JsonObject) -> None:
    payload["invalid_fields"] = [{"location": "query", "error_type": "string_type"}] * 21


def count_unexpected_fields_below_zero(payload: JsonObject) -> None:
    payload["unexpected_field_count"] = -1


def quote_the_input_in_the_message(payload: JsonObject) -> None:
    payload["message"] = "Traceback: KeyError 'limit' in the arguments sent"


def give_the_failure_another_code_s_message(payload: JsonObject) -> None:
    payload["message"] = TOOL_FAILURE_MESSAGES[ToolFailureCode.INTERNAL_ERROR]


def quote_the_request_in_the_rejection(payload: JsonObject) -> None:
    payload["message"] = "No route for /mcp?token=Kq3vY8xN2pL5sT7wB9dF1gH4jM6zC0aE"


def give_the_rejection_another_code_s_message(payload: JsonObject) -> None:
    payload["message"] = HTTP_REJECTION_MESSAGES[HttpRejectionCode.NOT_FOUND]


def add_the_status_to_the_rejection(payload: JsonObject) -> None:
    payload["status"] = 401


def put_a_verdict_in_the_check_detail(payload: JsonObject) -> None:
    payload["detail"] = "CONFIRMED: pkg is affected by this CVE."


def reverse_the_capabilities(payload: JsonObject) -> None:
    payload["source_capabilities"].reverse()


def drop_the_affectedness_detail(payload: JsonObject) -> None:
    payload["source_capabilities"][2]["detail"] = None


def give_the_available_cve_search_a_detail(payload: JsonObject) -> None:
    payload["source_capabilities"][0]["detail"] = FightUnavailableDetail.NOT_PINNED.value


def make_affectedness_available_without_detail(payload: JsonObject) -> None:
    payload["source_capabilities"][2].update({"state": "available", "detail": None})


def make_affectedness_unconfigured(payload: JsonObject) -> None:
    payload["source_capabilities"][2].update({"state": "not_configured", "detail": None})


def put_a_verdict_in_the_affectedness_detail(payload: JsonObject) -> None:
    payload["source_capabilities"][2]["detail"] = "Affectedness checked: not affected."


def give_the_affectedness_capability_the_fight_sentence(payload: JsonObject) -> None:
    payload["source_capabilities"][2]["detail"] = FightUnavailableDetail.NOT_PINNED.value


def put_a_verdict_in_the_affectedness_outcome(payload: JsonObject) -> None:
    find_source_outcome(payload, "affectedness")["detail"] = (
        "CONFIRMED: open5gs is affected by CVE-9999-0003."
    )


def find_source_outcome(payload: JsonObject, source: str) -> JsonObject:
    for source_outcome in payload["coverage"]["source_outcomes"]:
        if source_outcome["source"] == source:
            return source_outcome
    raise AssertionError(f"the set has no {source} outcome")


def put_a_verdict_in_a_channel_failure(payload: JsonObject) -> None:
    payload["channel_outcomes"][0].update(
        {"status": "unavailable", "detail": "CONFIRMED: demo_gateway is affected by CVE-9999-0003"}
    )


def give_the_cve_search_outcome_a_detail(payload: JsonObject) -> None:
    find_source_outcome(payload, "cve_search")["detail"] = BackendFailureDetail.UNREACHABLE.value


def give_the_affectedness_outcome_a_channel_failure(payload: JsonObject) -> None:
    find_source_outcome(payload, "affectedness")["channel_failures"] = [
        {
            "channel": "semantic",
            "status": "unavailable",
            "detail": BackendFailureDetail.UNREACHABLE.value,
        }
    ]


def list_an_answering_channel_as_failed(payload: JsonObject) -> None:
    find_source_outcome(payload, "cve_search")["channel_failures"] = [
        {"channel": "lexical", "status": "ok", "detail": None}
    ]


def fail_a_channel_without_its_sentence(payload: JsonObject) -> None:
    payload["channel_outcomes"][0].update({"status": "unavailable", "detail": None})


def give_a_verified_report_a_violation(payload: JsonObject) -> None:
    payload["violations"] = ["schema_version: Field required"]


def clear_a_malformed_report_s_violations(payload: JsonObject) -> None:
    payload["violations"] = []


def empty_a_malformed_report_s_violation(payload: JsonObject) -> None:
    payload["violations"] = [""]


def lengthen_a_malformed_report_s_violation(payload: JsonObject) -> None:
    payload["violations"] = ["x" * (MAX_VIOLATION_CHARS + 1)]


def clear_a_replay_difference_report_s_differences(payload: JsonObject) -> None:
    payload["differences"] = []


MODEL_REJECTED_PAYLOADS: list[tuple[str, PayloadBuilder, PayloadForgery, str]] = [
    ("search_response", search_ausf, put_a_verdict_in_a_channel_failure, "Input should be"),
    (
        "search_response",
        search_ausf,
        fail_a_channel_without_its_sentence,
        "carries a detail exactly when the channel failed",
    ),
    (
        "knowledge_evidence_set",
        run_open5gs_product_question,
        give_the_cve_search_outcome_a_detail,
        "a cve_search outcome cannot carry that detail",
    ),
    (
        "knowledge_evidence_set",
        run_open5gs_product_question,
        list_an_answering_channel_as_failed,
        "channel_failures holds only channels that failed",
    ),
    (
        "knowledge_evidence_set",
        run_open5gs_product_question,
        give_the_affectedness_outcome_a_channel_failure,
        "only a cve_search outcome names failing channels",
    ),
    (
        "knowledge_evidence_set",
        run_open5gs_product_question,
        put_a_verdict_in_the_affectedness_outcome,
        "Input should be",
    ),
    (
        "knowledge_evidence_set",
        run_exact_id,
        claim_an_earlier_schema_version,
        "schema_version must be",
    ),
    ("search_response", search_ausf, claim_an_earlier_schema_version, "schema_version must be"),
    (
        "topic_context_response",
        explore_five_g_aka_mixed,
        claim_an_earlier_schema_version,
        "schema_version must be",
    ),
    (
        "knowledge_evidence_set",
        run_open5gs_product_question,
        claim_the_product_is_not_affected,
        "Input should be",
    ),
    (
        "knowledge_evidence_set",
        run_model_accepted,
        name_a_policy_version_for_the_model,
        "policy_version",
    ),
    ("knowledge_evidence_set", run_exact_id, name_a_model_for_the_policy, "model_name"),
    (
        "knowledge_evidence_set",
        run_model_accepted,
        add_detail_to_the_accepted_reply,
        "a successful reply carries plan text and no detail",
    ),
    (
        "knowledge_evidence_set",
        run_model_accepted,
        drop_the_plan_text_from_the_accepted_reply,
        "a successful reply carries plan text and no detail",
    ),
    (
        "knowledge_evidence_set",
        run_model_unavailable,
        add_plan_text_to_the_failed_reply,
        "a failed reply carries detail and no plan text",
    ),
    (
        "knowledge_evidence_set",
        run_model_unavailable,
        quote_the_key_in_the_failed_reply,
        "Input should be",
    ),
    (
        "knowledge_evidence_set",
        run_model_unavailable,
        claim_no_reply_was_recorded,
        "Input should be",
    ),
    (
        "knowledge_evidence_set",
        run_model_accepted,
        drop_the_endpoint_from_the_model_identity,
        "endpoint_sha256",
    ),
    (
        "knowledge_evidence_set",
        run_with_invalid_evidence,
        give_the_responseless_step_a_status,
        "carries nothing from a response",
    ),
    (
        "knowledge_evidence_set",
        run_with_invalid_evidence,
        give_the_responseless_step_context_bytes,
        "carries nothing from a response",
    ),
    (
        "knowledge_evidence_set",
        run_exact_id,
        drop_the_admitted_step_hash,
        "records its status and hash",
    ),
    (
        "topic_context_response",
        explore_five_g_aka_mixed,
        keep_the_snapshot_of_a_failed_source,
        "a failed source outcome cannot name a snapshot",
    ),
    (
        "cve_record",
        load_record_with_exact_version,
        add_a_bound_to_the_exact_version,
        "an exact version cannot also carry range bounds",
    ),
    (
        "cve_record",
        load_record_with_upper_bound,
        drop_the_only_bound,
        "a version range needs an exact version or at least one bound",
    ),
    (
        "evidence_anchor",
        load_first_anchor,
        name_an_inference_method_for_an_asserted_anchor,
        "an asserted anchor cannot carry an inference_method",
    ),
    (
        "evidence_anchor",
        load_first_anchor,
        mark_the_anchor_inferred_without_a_method,
        "an inferred anchor must name its inference_method",
    ),
    (
        "protocol_topic",
        load_pending_topic_card,
        mark_the_card_reviewed_without_a_reviewer,
        "a reviewed card names its reviewer",
    ),
    (
        "protocol_topic",
        load_pending_topic_card,
        name_a_reviewer_for_the_pending_card,
        "a pending card names neither a reviewer",
    ),
    (
        "knowledge_evidence_set",
        run_exact_id,
        write_a_retrieval_time_that_is_no_date,
        "Input should be a valid datetime",
    ),
    (
        "knowledge_evidence_set",
        run_exact_id,
        drop_the_start_time_offset,
        "Input should have timezone info",
    ),
    (
        "cve_record",
        load_record_with_exact_version,
        drop_the_publication_time_offset,
        "Input should have timezone info",
    ),
    (
        "protocol_topic",
        load_pending_topic_card,
        write_a_review_date_that_is_no_date,
        "Input should be a valid date",
    ),
    (
        "knowledge_evidence_set",
        run_exact_id,
        write_a_start_time_out_of_range,
        "Input should be a valid datetime",
    ),
    (
        "protocol_topic",
        load_pending_topic_card,
        write_a_review_date_out_of_range,
        "Input should be a valid date",
    ),
    (
        "protocol_topic",
        load_pending_topic_card,
        write_a_review_date_on_a_day_its_year_lacks,
        "Input should be a valid date",
    ),
    (
        "knowledge_evidence_set",
        run_exact_id,
        end_the_start_time_with_a_newline,
        "Input should be a valid datetime",
    ),
    (
        "protocol_topic",
        load_pending_topic_card,
        end_the_review_date_with_a_newline,
        "Input should be a valid date",
    ),
    (
        "cve_record",
        load_record_with_exact_version,
        end_the_cve_id_with_a_newline,
        "String should match pattern",
    ),
    (
        "affectedness_check",
        check_blocked_affectedness,
        claim_an_earlier_schema_version,
        "schema_version must be",
    ),
    (
        "affectedness_check",
        check_blocked_affectedness,
        claim_the_product_affected,
        "Input should be 'unknown'",
    ),
    ("affectedness_check", check_blocked_affectedness, drop_the_failure, "Field required"),
    (
        "affectedness_check",
        check_blocked_affectedness,
        report_the_failure_ok,
        "Input should be 'blocked_unverified'",
    ),
    (
        "tool_failure",
        fail_with_invalid_arguments,
        list_twenty_one_invalid_fields,
        "at most 20 items",
    ),
    (
        "tool_failure",
        fail_with_invalid_arguments,
        count_unexpected_fields_below_zero,
        "greater than or equal to 0",
    ),
    (
        "tool_failure",
        fail_with_invalid_arguments,
        quote_the_input_in_the_message,
        "message must be the fixed sentence of the failure's code",
    ),
    (
        "tool_failure",
        fail_with_invalid_arguments,
        give_the_failure_another_code_s_message,
        "message must be the fixed sentence of the failure's code",
    ),
    (
        "http_rejection",
        reject_a_request_without_the_token,
        quote_the_request_in_the_rejection,
        "message must be the fixed sentence of the rejection's code",
    ),
    (
        "http_rejection",
        reject_a_request_without_the_token,
        give_the_rejection_another_code_s_message,
        "message must be the fixed sentence of the rejection's code",
    ),
    (
        "http_rejection",
        reject_a_request_without_the_token,
        add_the_status_to_the_rejection,
        "Extra inputs are not permitted",
    ),
    (
        "affectedness_check",
        check_blocked_affectedness,
        put_a_verdict_in_the_check_detail,
        "Input should be",
    ),
    (
        "knowledge_capabilities",
        describe_packaged_capabilities,
        put_a_verdict_in_the_affectedness_detail,
        "Input should be",
    ),
    (
        "knowledge_capabilities",
        describe_packaged_capabilities,
        give_the_affectedness_capability_the_fight_sentence,
        "the affectedness capability's detail is not one of its sentences",
    ),
    (
        "concept_resolution",
        resolve_five_g_aka,
        claim_an_earlier_schema_version,
        "schema_version must be",
    ),
    (
        "evidence_lookup",
        look_up_first_anchor,
        claim_an_earlier_schema_version,
        "schema_version must be",
    ),
    (
        "knowledge_capabilities",
        describe_packaged_capabilities,
        drop_the_affectedness_detail,
        "the affectedness capability names a detail exactly when it is unavailable",
    ),
    (
        "knowledge_capabilities",
        describe_packaged_capabilities,
        give_the_available_cve_search_a_detail,
        "the cve_search capability names a detail exactly when it is unavailable",
    ),
    (
        "knowledge_capabilities",
        describe_packaged_capabilities,
        make_affectedness_available_without_detail,
        "the affectedness capability cannot be available",
    ),
    (
        "knowledge_capabilities",
        describe_packaged_capabilities,
        make_affectedness_unconfigured,
        "the affectedness capability cannot be not_configured",
    ),
    (
        "knowledge_capabilities",
        describe_packaged_capabilities,
        reverse_the_capabilities,
        "once each, in that order",
    ),
    (
        "verification_report",
        verify_a_genuine_set,
        give_a_verified_report_a_violation,
        "a verified report has the wrong violations",
    ),
    (
        "verification_report",
        verify_malformed_bytes,
        clear_a_malformed_report_s_violations,
        "a malformed report has the wrong violations",
    ),
    (
        "verification_report",
        verify_malformed_bytes,
        empty_a_malformed_report_s_violation,
        "String should have at least 1 character",
    ),
    (
        "verification_report",
        verify_malformed_bytes,
        lengthen_a_malformed_report_s_violation,
        f"String should have at most {MAX_VIOLATION_CHARS} characters",
    ),
    (
        "verification_report",
        verify_a_set_whose_replay_differs,
        clear_a_replay_difference_report_s_differences,
        "a replay_differs report has the wrong differences",
    ),
]
MODEL_REJECTED_PAYLOAD_IDS: list[str] = []
for rejected_contract_name, _, rejected_forgery, _ in MODEL_REJECTED_PAYLOADS:
    MODEL_REJECTED_PAYLOAD_IDS.append(f"{rejected_contract_name}-{rejected_forgery.__name__}")


@pytest.mark.parametrize(
    ("contract_name", "build_payload", "forge", "server_error"),
    MODEL_REJECTED_PAYLOADS,
    ids=MODEL_REJECTED_PAYLOAD_IDS,
)
def test_payload_the_server_refuses_to_parse_is_invalid_under_its_published_schema(
    fixture_bundle: FixtureBundle,
    contract_name: str,
    build_payload: PayloadBuilder,
    forge: PayloadForgery,
    server_error: str,
) -> None:
    payload = build_payload(fixture_bundle).model_dump(mode="json")
    forge(payload)

    schema_errors = list_schema_errors(contract_name, payload)

    assert schema_errors != []
    with pytest.raises(ValidationError, match=server_error):
        CONTRACT_MODELS[contract_name].model_validate(payload)


@pytest.mark.parametrize("code", list(ToolFailureCode), ids=str)
def test_failure_carrying_its_code_s_message_is_valid_under_its_published_schema(
    code: ToolFailureCode,
) -> None:
    tool_failure = ToolFailure(
        code=code,
        message=TOOL_FAILURE_MESSAGES[code],
        invalid_fields=(),
        unexpected_field_count=0,
    )

    schema_errors = list_schema_errors("tool_failure", tool_failure.model_dump(mode="json"))

    assert schema_errors == []


@pytest.mark.parametrize("code", list(HttpRejectionCode), ids=str)
def test_rejection_carrying_its_code_s_message_is_valid_under_its_published_schema(
    code: HttpRejectionCode,
) -> None:
    http_rejection = build_http_rejection(code)

    schema_errors = list_schema_errors("http_rejection", http_rejection.model_dump(mode="json"))

    assert schema_errors == []


def drop_the_last_capability(payload: JsonObject) -> None:
    payload["source_capabilities"].pop()


def make_affectedness_available(payload: JsonObject) -> None:
    payload["source_capabilities"][2]["state"] = "available"


def name_a_version_for_the_unconfigured_planner(payload: JsonObject) -> None:
    payload["source_capabilities"][4]["version"] = "gpt"


def drop_the_coverage_of_available_fight(payload: JsonObject) -> None:
    payload["source_capabilities"][1]["coverage"] = None


def drop_the_planner_detail(payload: JsonObject) -> None:
    payload["source_capabilities"][4]["detail"] = None


def give_the_planner_the_fight_sentence(payload: JsonObject) -> None:
    payload["source_capabilities"][4]["detail"] = FightUnavailableDetail.NOT_PINNED.value


def give_the_unconfigured_semantic_channel_a_detail(payload: JsonObject) -> None:
    payload["source_capabilities"][3]["detail"] = SemanticUnavailableDetail.ADAPTER_UNUSABLE.value


def give_the_unconfigured_planner_a_detail(payload: JsonObject) -> None:
    payload["source_capabilities"][4]["detail"] = (
        ModelPlannerUnavailableDetail.MISSING_API_KEY.value
    )


def drop_the_accepted_reply(payload: JsonObject) -> None:
    payload["trajectory"]["rounds"][0].update({"model_reply": None, "model_reply_sha256": None})


def add_a_reply_to_the_policy_round(payload: JsonObject) -> None:
    payload["trajectory"]["rounds"][0].update(
        {
            "model_reply": {"status": "ok", "plan_text": '{"steps": []}', "detail": None},
            "model_reply_sha256": "0" * 64,
        }
    )


def credit_the_policy_round_to_the_model(payload: JsonObject) -> None:
    payload["trajectory"]["rounds"][0]["planner_outcome"] = "model_skipped_at_deadline"


def credit_the_model_round_to_the_policy(payload: JsonObject) -> None:
    payload["trajectory"]["rounds"][0].update(
        {"planner_outcome": "deterministic", "model_reply": None, "model_reply_sha256": None}
    )


def blame_a_malformed_reply_for_the_policy_plan(payload: JsonObject) -> None:
    payload["trajectory"]["rounds"][0]["rejections"].append(
        {"step_position": None, "code": "malformed_plan"}
    )


def drop_the_model_rejections(payload: JsonObject) -> None:
    payload["trajectory"]["rounds"][0]["rejections"] = []


def blame_the_gate_for_the_unavailable_planner(payload: JsonObject) -> None:
    payload["trajectory"]["rounds"][0]["rejections"][0]["code"] = "term_outside_vocabulary"


def credit_a_policy_step_to_the_model(payload: JsonObject) -> None:
    payload["trajectory"]["steps"][0].update({"planned_by": "model", "reason": "model_proposal"})


def reject_the_unconsulted_round_s_running_plan(payload: JsonObject) -> None:
    payload["trajectory"]["rounds"][0]["rejections"] = [
        {"step_position": None, "code": "over_tool_call_budget"}
    ]


def leave_round_two_unconsulted(payload: JsonObject) -> None:
    payload["trajectory"]["rounds"][1].update(
        {
            "planner_outcome": "model_not_consulted",
            "rejections": [],
            "model_reply": None,
            "model_reply_sha256": None,
        }
    )


def report_no_match_for_a_sufficient_stop(payload: JsonObject) -> None:
    payload["status"] = "no_match"


def apply_another_scope(payload: JsonObject) -> None:
    payload["applied_scope"] = "mixed"


VALIDATOR_REJECTED_PAYLOADS: list[tuple[EvidenceSetRun, PayloadForgery, str]] = [
    (run_exact_id, reverse_the_capabilities, "once each, in that order"),
    (run_exact_id, drop_the_last_capability, "once each, in that order"),
    (run_exact_id, make_affectedness_available, "the affectedness capability cannot be available"),
    (
        run_exact_id,
        make_affectedness_unconfigured,
        "the affectedness capability cannot be not_configured",
    ),
    (
        run_exact_id,
        drop_the_affectedness_detail,
        "the affectedness capability names a detail exactly when it is unavailable",
    ),
    (
        run_exact_id,
        give_the_available_cve_search_a_detail,
        "the cve_search capability names a detail exactly when it is unavailable",
    ),
    (run_exact_id, name_a_version_for_the_unconfigured_planner, "names a version exactly when"),
    (
        run_planner_without_a_key,
        drop_the_planner_detail,
        "the model_planner capability names a detail exactly when it is unavailable",
    ),
    (
        run_planner_without_a_key,
        give_the_planner_the_fight_sentence,
        "the model_planner capability's detail is not one of its sentences",
    ),
    (
        run_exact_id,
        give_the_unconfigured_semantic_channel_a_detail,
        "the semantic_channel capability names a detail exactly when it is unavailable",
    ),
    (
        run_exact_id,
        give_the_unconfigured_planner_a_detail,
        "the model_planner capability names a detail exactly when it is unavailable",
    ),
    (run_exact_id, drop_the_coverage_of_available_fight, "names a coverage exactly when"),
    (run_model_accepted, drop_the_accepted_reply, "does not record the model's reply"),
    (run_exact_id, add_a_reply_to_the_policy_round, "deterministic planner never gave"),
    (run_exact_id, credit_the_policy_round_to_the_model, "not one a deterministic planner"),
    (run_model_accepted, credit_the_model_round_to_the_policy, "not one a model planner"),
    (
        run_policy_plan_over_budget,
        blame_a_malformed_reply_for_the_policy_plan,
        "rejected no model reply",
    ),
    (run_model_rejected, drop_the_model_rejections, "records no rejection"),
    (
        run_model_unavailable,
        blame_the_gate_for_the_unavailable_planner,
        "so its first rejection is planner_unavailable",
    ),
    (
        run_free_text_under_a_model_planner,
        reject_the_unconsulted_round_s_running_plan,
        "round 1 is model_not_consulted and runs its plan, but records rejections",
    ),
    (
        run_model_refinement_unavailable,
        leave_round_two_unconsulted,
        "round 2 is model_not_consulted: only round 1 is",
    ),
    (run_exact_id, credit_a_policy_step_to_the_model, "step 1 is planned by model"),
    (
        run_exact_id,
        report_no_match_for_a_sufficient_stop,
        "status no_match cannot report stop reason sufficient",
    ),
    (run_exact_id, apply_another_scope, "requested and applied scope must both be"),
]
VALIDATOR_REJECTED_PAYLOAD_IDS: list[str] = []
for _, validator_forgery, _ in VALIDATOR_REJECTED_PAYLOADS:
    VALIDATOR_REJECTED_PAYLOAD_IDS.append(validator_forgery.__name__)


@pytest.mark.parametrize(
    ("run", "forge", "server_violation"),
    VALIDATOR_REJECTED_PAYLOADS,
    ids=VALIDATOR_REJECTED_PAYLOAD_IDS,
)
def test_evidence_set_the_validator_rejects_is_invalid_under_its_published_schema(
    fixture_bundle: FixtureBundle,
    packaged_evidence_catalog: EvidenceCatalog,
    run: EvidenceSetRun,
    forge: PayloadForgery,
    server_violation: str,
) -> None:
    """The model parses each forged set; the evidence-set validator rejects it, even
    resealed, and so does the published schema."""
    evidence_set = run(fixture_bundle)
    _, pinned_fight_snapshot = load_packaged_fight_source(read_fixed_clock)
    payload = evidence_set.model_dump(mode="json")
    forge(payload)

    schema_errors = list_schema_errors("knowledge_evidence_set", payload)

    assert schema_errors != []
    forged_set = reseal_evidence_set(KnowledgeEvidenceSet.model_validate(payload))
    with pytest.raises(EvidenceValidationError, match=server_violation):
        validate_knowledge_evidence_set(
            forged_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            evidence_set.source_capabilities,
        )


def list_calendar_dates_to_probe() -> list[str]:
    """Every month and day spelling from 00 to 32, in years that test the leap rule, and
    a valid date followed by a line break."""
    calendar_dates: list[str] = []
    for year in ["0000", "0001", "1900", "2000", "2024", "2026", "9999"]:
        for month in range(14):
            for day in range(33):
                calendar_dates.append(f"{year}-{month:02d}-{day:02d}")
    for line_break in ["\n", "\r\n"]:
        calendar_dates.append(f"2024-02-29{line_break}")
    return calendar_dates


def list_timestamps_to_probe() -> list[str]:
    """Edge times and offsets on a valid day, and each probed date at midnight UTC."""
    timestamps: list[str] = []
    for hour in ["00", "23", "24", "99"]:
        for minute_and_second in ["00:00", "59:59", "60:00", "00:60", "99:99"]:
            for fraction in ["", ".5", ".123456", ".1234567", "."]:
                for offset in ["Z", "+23:59", "-23:59", "+24:00", "+00:60", "z", "", "Z\n"]:
                    timestamps.append(f"2024-02-29T{hour}:{minute_and_second}{fraction}{offset}")
    for calendar_date in list_calendar_dates_to_probe():
        timestamps.append(f"{calendar_date}T00:00:00Z")
    return timestamps


def find_published_field_schema(contract_name: str, definition: str, field: str) -> JsonObject:
    schema = json.loads((REPOSITORY_SCHEMA_DIR / f"{contract_name}.schema.json").read_text())
    field_schema: JsonObject = schema["$defs"][definition]["properties"][field]
    return field_schema


def is_parsed_by_the_server(type_adapter: TypeAdapter[Any], value: str) -> bool:
    try:
        type_adapter.validate_python(value)
    except ValidationError:
        return False
    return True


@pytest.mark.parametrize(
    ("contract_name", "definition", "field", "server_type", "values"),
    [
        (
            "knowledge_evidence_set",
            "RunTimings",
            "started_at",
            Timestamp,
            list_timestamps_to_probe(),
        ),
        (
            "protocol_topic",
            "TopicReview",
            "reviewed_on",
            CalendarDate,
            list_calendar_dates_to_probe(),
        ),
    ],
    ids=["timestamp", "calendar_date"],
)
def test_published_time_pattern_admits_only_values_the_server_parses(
    contract_name: str, definition: str, field: str, server_type: Any, values: list[str]
) -> None:
    validator = Draft202012Validator(find_published_field_schema(contract_name, definition, field))
    type_adapter: TypeAdapter[Any] = TypeAdapter(server_type)

    schema_only_values: list[str] = []
    admitted_value_count = 0
    for value in values:
        if not validator.is_valid(value):
            continue
        admitted_value_count += 1
        if not is_parsed_by_the_server(type_adapter, value):
            schema_only_values.append(value)

    assert schema_only_values == []
    assert admitted_value_count > 0
