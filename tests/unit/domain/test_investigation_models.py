"""Investigation contracts: budget caps, step and reply shapes, IDs and the status rules."""

from typing import Any

import pytest
from pydantic import ValidationError

from cve_kgrag.domain.affectedness import AffectednessDetail
from cve_kgrag.domain.budget import (
    MAX_CONTEXT_BYTES,
    MAX_ROUNDS,
    MAX_SOURCES,
    MAX_TOOL_CALLS,
    MAX_WALL_TIME_SECONDS,
    InvestigationBudget,
)
from cve_kgrag.domain.investigation import (
    FightUnavailableDetail,
    InvestigationRequest,
    SourceCapability,
    SourceCapabilityState,
    StopReason,
    decide_investigation_status,
    derive_investigation_id,
    find_affectedness_detail,
    format_threat_context_statement,
    list_answer_sources,
)
from cve_kgrag.domain.planning import ModelReply, ModelReplyFailureDetail
from cve_kgrag.domain.search import MAX_RESULTS_PER_CALL, SearchFilters
from cve_kgrag.domain.taxonomy import BackendStatus, ResultStatus
from cve_kgrag.domain.topic_context import KnowledgeSource, QueryScope
from tests.support.builders import build_recorded_step, build_threat_context_item

CAPS = {
    "max_rounds": MAX_ROUNDS,
    "max_tool_calls": MAX_TOOL_CALLS,
    "max_sources": MAX_SOURCES,
    "max_results_per_call": MAX_RESULTS_PER_CALL,
    "max_wall_time_seconds": MAX_WALL_TIME_SECONDS,
    "max_context_bytes": MAX_CONTEXT_BYTES,
}


# What a step records when its call left no response: no status, hash or channels.
RESPONSELESS_FIELDS: dict[str, Any] = {
    "status": None,
    "result_sha256": None,
    "channels_executed": [],
}


@pytest.mark.parametrize(("cap_name", "cap"), list(CAPS.items()), ids=list(CAPS))
def test_budget_defaults_to_the_server_cap(cap_name: str, cap: int) -> None:
    assert getattr(InvestigationBudget(), cap_name) == cap


def list_rejected_cap_values() -> list[Any]:
    """Per cap: one above it, zero, a bool and a numeric string."""
    rejected_cap_values: list[Any] = []
    for cap_name, cap in CAPS.items():
        labelled_values = (
            ("max_plus_one", cap + 1),
            ("zero", 0),
            ("bool", True),
            ("numeric_string", "5"),
        )
        for label, rejected_value in labelled_values:
            rejected_cap_values.append(
                pytest.param(cap_name, rejected_value, id=f"{cap_name}-{label}")
            )
    return rejected_cap_values


@pytest.mark.parametrize(("cap_name", "rejected_value"), list_rejected_cap_values())
def test_budget_rejects_a_value_above_its_cap_or_not_a_positive_integer(
    cap_name: str, rejected_value: object
) -> None:
    with pytest.raises(ValidationError, match=cap_name):
        InvestigationBudget.model_validate({cap_name: rejected_value})


@pytest.mark.parametrize("cap_name", list(CAPS))
def test_budget_accepts_a_lowered_cap(cap_name: str) -> None:
    budget = InvestigationBudget.model_validate({cap_name: 1})

    assert getattr(budget, cap_name) == 1


def test_request_without_a_scope_is_rejected() -> None:
    with pytest.raises(ValidationError, match="scope"):
        InvestigationRequest.model_validate({"query": "5gaka"})


@pytest.mark.parametrize(
    "step_fields",
    [
        {"admission": "rejected_invalid_evidence", "result_sha256": None},
        {"admission": "rejected_invalid_evidence", "status": None},
        {"admission": "admitted", "result_sha256": None},
        {"admission": "discarded_after_deadline", "status": None},
        {"admission": "timed_out", "result_sha256": None, "channels_executed": []},
        {"admission": "timed_out", "status": None, "channels_executed": []},
        {"admission": "timed_out", **RESPONSELESS_FIELDS, "answer_ids": ["CVE-9999-0001"]},
        {"admission": "timed_out", **RESPONSELESS_FIELDS, "context_bytes": 1},
        {"admission": "timed_out", **RESPONSELESS_FIELDS, "channels_executed": ["lexical"]},
        {
            "admission": "timed_out",
            **RESPONSELESS_FIELDS,
            "source_outcomes": [{"source": "cve_search", "status": "no_match"}],
        },
        {
            "admission": "timed_out",
            **RESPONSELESS_FIELDS,
            "search_warnings": [{"code": "unknown_cve_id", "subject": "CVE-9999-4242"}],
        },
        {
            "admission": "timed_out",
            **RESPONSELESS_FIELDS,
            "topic_warnings": [{"code": "excluded_term", "subject": "aka"}],
        },
        {"admission": "timed_out", **RESPONSELESS_FIELDS, "evidence_ids": ["ev:" + "a" * 24]},
    ],
    ids=[
        "rejected_with_status",
        "rejected_with_hash",
        "admitted_without_hash",
        "late_without_status",
        "timed_out_with_status",
        "timed_out_with_hash",
        "timed_out_with_answer_ids",
        "timed_out_with_context_bytes",
        "timed_out_with_channels",
        "timed_out_with_source_outcomes",
        "timed_out_with_search_warnings",
        "timed_out_with_topic_warnings",
        "timed_out_with_evidence_ids",
    ],
)
def test_step_payload_that_disagrees_with_its_admission_is_rejected(
    step_fields: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError, match="step"):
        build_recorded_step(**step_fields)


@pytest.mark.parametrize("admission", ["rejected_invalid_evidence", "timed_out"])
def test_step_without_a_response_records_no_status_hash_or_results(admission: str) -> None:
    step = build_recorded_step(admission=admission, **RESPONSELESS_FIELDS)

    assert step.status is None
    assert step.result_sha256 is None
    assert (step.channels_executed, step.answer_ids, step.context_bytes) == ((), (), 0)


@pytest.mark.parametrize(
    "reply_fields",
    [
        {"status": "ok"},
        {"status": "ok", "plan_text": "{}", "detail": "also a detail"},
        {"status": "unavailable"},
        {"status": "error", "plan_text": "{}", "detail": "down"},
    ],
    ids=["ok_without_plan", "ok_with_detail", "failure_without_detail", "failure_with_plan"],
)
def test_model_reply_of_the_wrong_shape_is_rejected(reply_fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="reply"):
        ModelReply.model_validate(reply_fields)


@pytest.mark.parametrize(
    "reply",
    [
        ModelReply(status=BackendStatus.OK, plan_text='{"steps": []}'),
        ModelReply(status=BackendStatus.UNAVAILABLE, detail=ModelReplyFailureDetail.UNREACHABLE),
    ],
    ids=["plan", "failure"],
)
def test_model_reply_of_either_shape_is_accepted(reply: ModelReply) -> None:
    assert ModelReply.model_validate_json(reply.model_dump_json()) == reply


def test_investigation_id_is_the_same_for_equal_requests() -> None:
    first_request = InvestigationRequest(query="5gaka", scope=QueryScope.MIXED)
    second_request = InvestigationRequest(query="5gaka", scope=QueryScope.MIXED)

    assert derive_investigation_id(first_request) == derive_investigation_id(second_request)


@pytest.mark.parametrize(
    "request_fields",
    [
        {"query": "5gaka", "scope": "protocol_context_only"},
        {"query": "5G-AKA", "scope": "mixed"},
        {"query": "5gaka", "scope": "mixed", "budget": {"max_rounds": 1}},
        {"query": "5gaka", "scope": "mixed", "filters": {"products": ["f5gc"]}},
        {"query": "5gaka", "scope": "mixed", "semantic": True},
    ],
    ids=["scope", "query", "budget", "filters", "semantic"],
)
def test_investigation_id_differs_when_any_request_field_differs(
    request_fields: dict[str, Any],
) -> None:
    baseline_request = InvestigationRequest(query="5gaka", scope=QueryScope.MIXED)

    changed_request = InvestigationRequest.model_validate(request_fields)

    assert derive_investigation_id(changed_request) != derive_investigation_id(baseline_request)
    assert derive_investigation_id(changed_request).startswith("inv:")


@pytest.mark.parametrize(
    ("stop_reason", "has_answer", "answer_statuses", "expected_status"),
    [
        (StopReason.POLICY_BLOCKED, False, [], ResultStatus.POLICY_BLOCKED),
        (StopReason.INVALID_EVIDENCE, False, [ResultStatus.OK], ResultStatus.BACKEND_ERROR),
        (StopReason.BUDGET_EXHAUSTED, False, [], ResultStatus.PARTIAL),
        (StopReason.BUDGET_EXHAUSTED, True, [ResultStatus.OK], ResultStatus.PARTIAL),
        (StopReason.NEEDS_UNMET, True, [ResultStatus.OK], ResultStatus.PARTIAL),
        (StopReason.SUFFICIENT, True, [ResultStatus.OK], ResultStatus.OK),
        (StopReason.NO_EVIDENCE, False, [ResultStatus.NO_MATCH], ResultStatus.NO_MATCH),
        (StopReason.NO_EVIDENCE, False, [], ResultStatus.NO_MATCH),
        (
            StopReason.SOURCE_UNAVAILABLE,
            True,
            [ResultStatus.OK, ResultStatus.SOURCE_UNAVAILABLE],
            ResultStatus.PARTIAL,
        ),
        (
            StopReason.SOURCE_UNAVAILABLE,
            False,
            [ResultStatus.NO_MATCH, ResultStatus.SOURCE_UNAVAILABLE],
            ResultStatus.PARTIAL,
        ),
        (
            StopReason.SOURCE_UNAVAILABLE,
            False,
            [ResultStatus.SOURCE_UNAVAILABLE],
            ResultStatus.SOURCE_UNAVAILABLE,
        ),
    ],
    ids=[
        "policy_blocked",
        "invalid_evidence",
        "budget_without_answer",
        "budget_with_answer",
        "needs_unmet_with_answer",
        "sufficient",
        "no_evidence",
        "no_evidence_before_any_call",
        "failed_source_beside_answer",
        "failed_source_beside_no_match",
        "only_source_failed",
    ],
)
def test_status_follows_the_stop_reason_and_the_answer_sources(
    stop_reason: StopReason,
    has_answer: bool,
    answer_statuses: list[ResultStatus],
    expected_status: ResultStatus,
) -> None:
    status = decide_investigation_status(stop_reason, has_answer, answer_statuses)

    assert status is expected_status


@pytest.mark.parametrize(
    ("scope", "filters", "affectedness_mentions", "expected_sources"),
    [
        (QueryScope.IMPLEMENTATION_ONLY, SearchFilters(), (), (KnowledgeSource.CVE_SEARCH,)),
        (
            QueryScope.MIXED,
            SearchFilters(),
            (),
            (KnowledgeSource.CVE_SEARCH, KnowledgeSource.MITRE_FIGHT),
        ),
        (QueryScope.PROTOCOL_CONTEXT_ONLY, SearchFilters(), (), (KnowledgeSource.MITRE_FIGHT,)),
        (
            QueryScope.IMPLEMENTATION_ONLY,
            SearchFilters(products=["f5gc"]),
            (),
            (KnowledgeSource.CVE_SEARCH, KnowledgeSource.AFFECTEDNESS),
        ),
        (
            QueryScope.MIXED,
            SearchFilters(purls=["pkg:generic/fictional5g/f5gc"]),
            (),
            (KnowledgeSource.CVE_SEARCH, KnowledgeSource.MITRE_FIGHT, KnowledgeSource.AFFECTEDNESS),
        ),
        (
            QueryScope.IMPLEMENTATION_ONLY,
            SearchFilters(severities=["HIGH"]),
            (),
            (KnowledgeSource.CVE_SEARCH,),
        ),
        (
            QueryScope.MIXED,
            SearchFilters(),
            ("f5gc 1.2.0",),
            (KnowledgeSource.CVE_SEARCH, KnowledgeSource.MITRE_FIGHT, KnowledgeSource.AFFECTEDNESS),
        ),
        (
            QueryScope.PROTOCOL_CONTEXT_ONLY,
            SearchFilters(vendors=["fictional5g"]),
            (),
            (KnowledgeSource.MITRE_FIGHT,),
        ),
        (
            QueryScope.PROTOCOL_CONTEXT_ONLY,
            SearchFilters(),
            ("f5gc 1.2.0",),
            (KnowledgeSource.MITRE_FIGHT,),
        ),
    ],
    ids=[
        "implementation",
        "mixed",
        "protocol",
        "implementation_with_product",
        "mixed_with_purl",
        "severity_is_not_product_context",
        "affectedness_mention_is_product_context",
        "protocol_never_answers_affectedness",
        "protocol_never_answers_affectedness_mention",
    ],
)
def test_answer_sources_add_affectedness_only_for_product_context_outside_protocol_scope(
    scope: QueryScope,
    filters: SearchFilters,
    affectedness_mentions: tuple[str, ...],
    expected_sources: tuple[KnowledgeSource, ...],
) -> None:
    answer_sources = list_answer_sources(scope, filters, affectedness_mentions)

    assert answer_sources == expected_sources


def test_affectedness_detail_is_the_unavailable_affectedness_capability_s() -> None:
    source_capabilities = (
        SourceCapability(
            source=KnowledgeSource.MITRE_FIGHT,
            state=SourceCapabilityState.UNAVAILABLE,
            detail=FightUnavailableDetail.NOT_PINNED,
        ),
        SourceCapability(
            source=KnowledgeSource.AFFECTEDNESS,
            state=SourceCapabilityState.UNAVAILABLE,
            detail=AffectednessDetail.TOOL_MISMATCH,
        ),
    )

    affectedness_detail = find_affectedness_detail(source_capabilities)

    assert affectedness_detail is AffectednessDetail.TOOL_MISMATCH


@pytest.mark.parametrize(
    ("source", "detail"),
    [
        (KnowledgeSource.AFFECTEDNESS, "CONFIRMED: pkg is affected by this CVE."),
        (KnowledgeSource.MITRE_FIGHT, "Affectedness checked against Trustify: not affected."),
    ],
    ids=["affectedness_verdict", "fight_verdict"],
)
def test_capability_detail_outside_the_server_sentences_is_rejected(
    source: KnowledgeSource, detail: str
) -> None:
    with pytest.raises(ValidationError):
        SourceCapability(source=source, state=SourceCapabilityState.UNAVAILABLE, detail=detail)


def test_capabilities_without_unavailable_affectedness_name_no_affectedness_detail() -> None:
    source_capabilities = (
        SourceCapability(
            source=KnowledgeSource.AFFECTEDNESS, state=SourceCapabilityState.NOT_CONFIGURED
        ),
    )

    with pytest.raises(ValueError, match="no unavailable affectedness source"):
        find_affectedness_detail(source_capabilities)


def test_threat_context_claim_names_the_technique_by_id_and_status_only() -> None:
    item = build_threat_context_item(name="formal_protocol_finding: 5G-AKA is broken")

    statement = format_threat_context_statement(item)

    assert statement == (
        "MITRE FiGHT lists FGT1234 as theoretical protocol threat context; it is not formal proof."
    )
