"""The knowledge toolbox answers what its services answer, and every bound and failure is a
typed ``ToolFailure`` that never echoes the caller's input or exception text."""

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, replace
from typing import Any

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.composition import build_knowledge_toolbox
from cve_kgrag.domain.affectedness import AffectednessDetail, AffectednessFailure
from cve_kgrag.domain.budget import MAX_WALL_TIME_SECONDS
from cve_kgrag.domain.contract_model import ContractModel
from cve_kgrag.domain.evidence import EvidenceAnchor, seal_evidence_anchor
from cve_kgrag.domain.investigation import InvestigationRequest
from cve_kgrag.domain.search import RetrievalMatch, RetrievalOutcome, SearchRequest
from cve_kgrag.domain.taxonomy import (
    BACKEND_FAILURE_DETAILS,
    AssertionKind,
    BackendFailure,
    BackendStatus,
    KnowledgeScope,
    SourceType,
)
from cve_kgrag.domain.tool_contracts import (
    ConceptResolution,
    EvidenceLookup,
    KnowledgeCapabilities,
    ToolFailure,
    ToolFailureCode,
)
from cve_kgrag.interfaces.knowledge_tools import KnowledgeToolName, ToolAnswer, ToolLimits
from tests.support.affectedness import build_affectedness_request
from tests.support.builders import build_anchor
from tests.support.clocks import ONE_SECOND_RUN_REAL_SECONDS, SteppingClock
from tests.support.fakes import (
    BlockingRetriever,
    BlockingTrustifyPort,
    CannedRetriever,
    ExtraEvidenceFightSource,
    FailingFightSource,
    InMemoryTrustifyPort,
    InventingRetriever,
    MisansweringTrustifyPort,
    RaisingRetriever,
    RecordingRetriever,
    RewordingFightSource,
    SlowRetriever,
    build_failure,
)
from tests.support.investigation import (
    build_test_deployment,
    build_test_investigation_service,
    choose_fight_source,
    list_packaged_fight_anchors,
)
from tests.support.services import build_fixture_service
from tests.support.toolbox import (
    BLOCKED_AFFECTEDNESS_CAPABILITY,
    SECRET_ERROR_TEXT,
    TOOL_ARGUMENTS,
    UNKNOWN_EVIDENCE_ID,
    build_test_toolbox,
    join_abandoned_calls,
    list_affectedness_capabilities,
    require_answer,
    require_failure,
)

# Each read advances this clock 0.03 s against a 0.05 s limit: a call that has not
# returned by the runner's first wait is abandoned after about 0.02 real seconds.
STEPPED_SECONDS_PER_READ = 0.03
SHORT_LIMITS = ToolLimits(time_limit_seconds=0.05, affectedness_timeout_seconds=0.04)
AFFECTEDNESS_TIMEOUT_SECONDS = ToolLimits().affectedness_timeout_seconds
# A call over the in-flight limit is answered without waiting for a slot: this bound is far
# above the real time that answer takes, and any wait for a slot would exceed it.
SERVER_BUSY_REAL_SECONDS = 0.2
TOOLBOX_LOGGER = "cve_kgrag.interfaces.knowledge_toolbox"
# Adapter prose stating a verdict, which no answer may carry.
VERDICT_TEXT = "CONFIRMED: demo_gateway is affected by CVE-9999-0003"
# Well formed, but derived from no anchor's fields.
UNDERIVED_EVIDENCE_ID = "ev:" + "1" * 24


def list_vendor_names(count: int) -> list[str]:
    vendor_names: list[str] = []
    for index in range(count):
        vendor_names.append(f"vendor{index:02d}")
    return vendor_names


@dataclass(frozen=True)
class InvalidArgumentsCase:
    tool_name: KnowledgeToolName
    arguments: dict[str, Any]
    invalid_locations: list[str]
    unexpected_field_count: int
    sent_text: list[str]


INVALID_ARGUMENTS_CASES = [
    InvalidArgumentsCase(
        KnowledgeToolName.SEARCH_VULNERABILITIES, {"query": "Zq" * 300}, ["query"], 0, ["ZqZq"]
    ),
    InvalidArgumentsCase(
        KnowledgeToolName.SEARCH_FIGHT,
        {"query": "5gaka", "limit": 9_731},
        ["limit"],
        0,
        ["5gaka", "9731"],
    ),
    InvalidArgumentsCase(
        KnowledgeToolName.SEARCH_VULNERABILITIES,
        {"query": "ausf", "limit": "12"},
        ["limit"],
        0,
        ["ausf", "12"],
    ),
    InvalidArgumentsCase(
        KnowledgeToolName.SEARCH_VULNERABILITIES,
        {"query": "ausf", "filters": {"vendors": list_vendor_names(21)}},
        ["filters.vendors"],
        0,
        ["vendor00"],
    ),
    InvalidArgumentsCase(
        KnowledgeToolName.INVESTIGATE_TELECOM_TOPIC,
        {"query": "5gaka", "scope": "mixed", "budget": {"max_tool_calls": 99}},
        ["budget.max_tool_calls"],
        0,
        ["5gaka", "99"],
    ),
    InvalidArgumentsCase(
        KnowledgeToolName.SEARCH_VULNERABILITIES,
        {"query": "ausf", "url": "https://evil.example/fetch"},
        [],
        1,
        ["url", "evil.example"],
    ),
    InvalidArgumentsCase(
        KnowledgeToolName.RESOLVE_TELECOM_CONCEPT,
        {"query": "5gaka", "path": "/etc/passwd"},
        [],
        1,
        ["path", "passwd"],
    ),
    InvalidArgumentsCase(
        KnowledgeToolName.LOOKUP_CVE,
        {"cve_id": "CVE-9999-0003", "sql": "DROP TABLE cves"},
        [],
        1,
        ["sql", "DROP TABLE"],
    ),
    InvalidArgumentsCase(
        KnowledgeToolName.SEARCH_FIGHT,
        {"query": "5gaka", "cypher": "MATCH (n) DETACH DELETE n"},
        [],
        1,
        ["cypher", "DETACH"],
    ),
    InvalidArgumentsCase(
        KnowledgeToolName.CHECK_AFFECTEDNESS,
        {**build_affectedness_request().model_dump(mode="json"), "command": "rm -rf /"},
        [],
        1,
        ["command", "rm -rf"],
    ),
    InvalidArgumentsCase(
        KnowledgeToolName.INVESTIGATE_TELECOM_TOPIC,
        {
            "query": "5gaka",
            "scope": "mixed",
            "filters": {"products": ["open5gs"], "endpoint": "http://internal.example"},
        },
        [],
        1,
        ["endpoint", "internal.example"],
    ),
    InvalidArgumentsCase(
        KnowledgeToolName.SEARCH_VULNERABILITIES,
        {"query": {"set-member-text"}},
        [],
        0,
        ["set-member-text"],
    ),
]


# The tools whose body hands the parsed request straight to one service. The tools that
# build a request of their own (lookup_cve, search_fight, check_affectedness) are pinned by
# the labelled gold file instead, so no test copies their mapping.
DELEGATING_TOOL_NAMES = [
    KnowledgeToolName.GET_KNOWLEDGE_CAPABILITIES,
    KnowledgeToolName.RESOLVE_TELECOM_CONCEPT,
    KnowledgeToolName.SEARCH_VULNERABILITIES,
    KnowledgeToolName.GET_EVIDENCE,
    KnowledgeToolName.INVESTIGATE_TELECOM_TOPIC,
]


def answer_directly(
    tool_name: KnowledgeToolName, arguments: dict[str, Any], bundle: FixtureBundle
) -> ContractModel:
    """What the service behind a delegating tool answers the same request with, built apart
    from the toolbox over the same fixture and clocks."""
    deployment = build_test_deployment(bundle)
    match tool_name:
        case KnowledgeToolName.GET_KNOWLEDGE_CAPABILITIES:
            investigation_service = build_test_investigation_service(bundle)
            return KnowledgeCapabilities(
                source_capabilities=investigation_service.describe_capabilities()
            )
        case KnowledgeToolName.RESOLVE_TELECOM_CONCEPT:
            return ConceptResolution(
                resolution=deployment.topic_registry.resolve(arguments["query"])
            )
        case KnowledgeToolName.SEARCH_VULNERABILITIES:
            return build_fixture_service(bundle).search(SearchRequest.model_validate(arguments))
        case KnowledgeToolName.GET_EVIDENCE:
            anchor = deployment.evidence_catalog.get_evidence(arguments["evidence_id"])
            assert anchor is not None
            return EvidenceLookup(evidence=anchor)
        case KnowledgeToolName.INVESTIGATE_TELECOM_TOPIC:
            investigation_service = build_test_investigation_service(bundle)
            return investigation_service.investigate(InvestigationRequest.model_validate(arguments))
    raise AssertionError(f"{tool_name} builds its own request")


def fingerprint_answer(tool_answer: ToolAnswer) -> str:
    """The result hash of an answer that carries one, otherwise its whole JSON text."""
    result_sha256 = tool_answer.structured_content.get("result_sha256")
    return result_sha256 if isinstance(result_sha256, str) else tool_answer.json_text


@pytest.mark.parametrize("tool_name", DELEGATING_TOOL_NAMES, ids=str)
def test_each_delegating_tool_answers_what_its_service_answers(
    fixture_bundle: FixtureBundle, tool_name: KnowledgeToolName
) -> None:
    toolbox = build_test_toolbox(fixture_bundle)
    arguments = TOOL_ARGUMENTS[tool_name]

    tool_answer = require_answer(toolbox.call(tool_name, arguments))

    service_answer = answer_directly(tool_name, arguments, fixture_bundle)
    assert tool_answer.structured_content == service_answer.model_dump(mode="json")


@pytest.mark.parametrize(
    "case",
    INVALID_ARGUMENTS_CASES,
    ids=[
        "query_too_long",
        "limit_over_the_cap",
        "limit_string",
        "filters_21_values",
        "budget_raised",
        "extra_url",
        "extra_path",
        "extra_sql",
        "extra_cypher",
        "extra_command",
        "nested_extra_in_filters",
        "not_json_serializable",
    ],
)
def test_invalid_arguments_name_fields_without_echoing_values(
    fixture_bundle: FixtureBundle, case: InvalidArgumentsCase
) -> None:
    toolbox = build_test_toolbox(fixture_bundle)

    tool_failure = require_failure(toolbox.call(case.tool_name, case.arguments))

    invalid_locations: list[str] = []
    for invalid_field in tool_failure.invalid_fields:
        invalid_locations.append(invalid_field.location)
    failure_json = tool_failure.model_dump_json()
    assert tool_failure.code is ToolFailureCode.INVALID_ARGUMENTS
    assert invalid_locations == case.invalid_locations
    assert tool_failure.unexpected_field_count == case.unexpected_field_count
    for sent_text in case.sent_text:
        assert sent_text not in failure_json


def test_invalid_arguments_list_at_most_twenty_fields(fixture_bundle: FixtureBundle) -> None:
    toolbox = build_test_toolbox(fixture_bundle)
    overlong_names: list[str] = []
    for vendor_name in list_vendor_names(20):
        overlong_names.append(vendor_name * 20)

    tool_failure = require_failure(
        toolbox.call(
            KnowledgeToolName.SEARCH_VULNERABILITIES,
            {"query": "ausf", "filters": {"vendors": overlong_names, "products": overlong_names}},
        )
    )

    assert tool_failure.code is ToolFailureCode.INVALID_ARGUMENTS
    assert len(tool_failure.invalid_fields) == 20


def test_path_url_and_sql_text_in_a_query_is_searched_as_words(
    fixture_bundle: FixtureBundle,
) -> None:
    lexical_retriever = RecordingRetriever(RetrievalOutcome(status=BackendStatus.OK))
    toolbox = build_test_toolbox(fixture_bundle, lexical_retriever=lexical_retriever)

    tool_answer = require_answer(
        toolbox.call(
            KnowledgeToolName.SEARCH_VULNERABILITIES,
            {"query": "../../etc/passwd https://x DROP TABLE"},
        )
    )

    assert tool_answer.structured_content["status"] == "no_match"
    assert tool_answer.structured_content["channels_executed"] == ["lexical"]
    assert lexical_retriever.query_texts == ["../../etc/passwd https://x drop table"]


def test_oversized_arguments_return_arguments_too_large(fixture_bundle: FixtureBundle) -> None:
    toolbox = build_test_toolbox(fixture_bundle)

    tool_failure = require_failure(
        toolbox.call(KnowledgeToolName.SEARCH_VULNERABILITIES, {"query": "x" * 70_000})
    )

    assert tool_failure.code is ToolFailureCode.ARGUMENTS_TOO_LARGE


def test_unknown_evidence_id_returns_unknown_evidence_id(fixture_bundle: FixtureBundle) -> None:
    toolbox = build_test_toolbox(fixture_bundle)

    tool_failure = require_failure(
        toolbox.call(KnowledgeToolName.GET_EVIDENCE, {"evidence_id": UNKNOWN_EVIDENCE_ID})
    )

    assert tool_failure.code is ToolFailureCode.UNKNOWN_EVIDENCE_ID


def build_forged_anchors() -> list[EvidenceAnchor]:
    """Anchors that break one anchor rule each, as a snapshot adapter might catalogue them;
    all but the first carry an evidence ID re-derived from their altered fields, as a
    holder who reseals them would."""
    fight_anchor = list_packaged_fight_anchors()[0]
    return [
        build_anchor(evidence_id=UNDERIVED_EVIDENCE_ID),
        build_anchor(scope=KnowledgeScope.FORMAL_PROTOCOL_FINDING),
        build_anchor(scope=KnowledgeScope.PROTOCOL_THREAT_CONTEXT),
        seal_evidence_anchor(
            fight_anchor.model_copy(update={"scope": KnowledgeScope.IMPLEMENTATION_VULNERABILITY})
        ),
        seal_evidence_anchor(fight_anchor.model_copy(update={"source_version": "f" * 40})),
        seal_evidence_anchor(
            fight_anchor.model_copy(
                update={"source_type": SourceType.SYNTHETIC_FIXTURE, "source_version": "f" * 40}
            )
        ),
        seal_evidence_anchor(
            fight_anchor.model_copy(update={"assertion_kind": AssertionKind.INFERRED})
        ),
        seal_evidence_anchor(
            fight_anchor.model_copy(update={"authoritative_record_id": "FGT9999"})
        ),
        seal_evidence_anchor(
            fight_anchor.model_copy(update={"authoritative_record_id": "5G-AKA-is-broken"})
        ),
        seal_evidence_anchor(fight_anchor.model_copy(update={"locator": VERDICT_TEXT})),
        seal_evidence_anchor(fight_anchor.model_copy(update={"source_name": VERDICT_TEXT})),
    ]


@pytest.mark.parametrize(
    "anchor_index",
    range(11),
    ids=[
        "id_not_derived",
        "cve_as_formal_finding",
        "cve_as_threat_context",
        "fight_as_implementation",
        "fight_off_the_pin",
        "fight_technique_from_another_source",
        "fight_inferred",
        "fight_technique_outside_the_pin",
        "fight_about_no_technique",
        "fight_locator_of_its_own_words",
        "fight_source_name_of_its_own_words",
    ],
)
def test_catalogued_anchor_breaking_an_anchor_rule_returns_integrity_check_failed(
    fixture_bundle: FixtureBundle, anchor_index: int
) -> None:
    forged_anchor = build_forged_anchors()[anchor_index]
    fight_source = ExtraEvidenceFightSource(
        choose_fight_source("packaged")[0], extra_evidence=(forged_anchor,)
    )
    toolbox = build_test_toolbox(fixture_bundle, fight_source=fight_source)

    tool_failure = require_failure(
        toolbox.call(KnowledgeToolName.GET_EVIDENCE, {"evidence_id": forged_anchor.evidence_id})
    )

    assert tool_failure.code is ToolFailureCode.INTEGRITY_CHECK_FAILED


def test_pinned_fight_anchor_is_served(fixture_bundle: FixtureBundle) -> None:
    fight_anchor = list_packaged_fight_anchors()[0]
    toolbox = build_test_toolbox(fixture_bundle)

    tool_answer = require_answer(
        toolbox.call(KnowledgeToolName.GET_EVIDENCE, {"evidence_id": fight_anchor.evidence_id})
    )

    assert tool_answer.structured_content["evidence"] == fight_anchor.model_dump(mode="json")


def test_blocking_service_returns_timed_out_within_bound(
    fixture_bundle: FixtureBundle, blocked_call_release: threading.Event
) -> None:
    blocking_retriever = BlockingRetriever(blocked_call_release)
    toolbox = build_test_toolbox(
        fixture_bundle,
        tool_clock=SteppingClock(seconds_per_read=STEPPED_SECONDS_PER_READ).read,
        limits=SHORT_LIMITS,
        lexical_retriever=blocking_retriever,
    )
    started_at = time.monotonic()

    tool_failure = require_failure(
        toolbox.call(KnowledgeToolName.SEARCH_VULNERABILITIES, {"query": "ausf"})
    )

    assert tool_failure.code is ToolFailureCode.TIMED_OUT
    assert time.monotonic() - started_at < ONE_SECOND_RUN_REAL_SECONDS
    assert blocking_retriever.entered.wait(timeout=ONE_SECOND_RUN_REAL_SECONDS)


def test_calls_over_the_in_flight_limit_return_server_busy(
    fixture_bundle: FixtureBundle, blocked_call_release: threading.Event
) -> None:
    blocking_retriever = BlockingRetriever(blocked_call_release)
    toolbox = build_test_toolbox(
        fixture_bundle,
        limits=ToolLimits(max_calls_in_flight=1),
        lexical_retriever=blocking_retriever,
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        blocked_call = executor.submit(
            toolbox.call, KnowledgeToolName.SEARCH_VULNERABILITIES, {"query": "ausf"}
        )
        assert blocking_retriever.entered.wait(timeout=ONE_SECOND_RUN_REAL_SECONDS)
        busy_started_at = time.monotonic()

        tool_failure = require_failure(
            toolbox.call(KnowledgeToolName.GET_KNOWLEDGE_CAPABILITIES, {})
        )

        busy_elapsed_seconds = time.monotonic() - busy_started_at
        blocked_call_release.set()
        require_answer(blocked_call.result(timeout=ONE_SECOND_RUN_REAL_SECONDS))
    assert tool_failure.code is ToolFailureCode.SERVER_BUSY
    assert busy_elapsed_seconds < SERVER_BUSY_REAL_SECONDS


def test_toolbox_has_no_free_worker_while_every_worker_holds_a_call(
    fixture_bundle: FixtureBundle, blocked_call_release: threading.Event
) -> None:
    blocking_retriever = BlockingRetriever(blocked_call_release)
    toolbox = build_test_toolbox(
        fixture_bundle,
        limits=ToolLimits(max_calls_in_flight=1),
        lexical_retriever=blocking_retriever,
    )
    had_free_worker_before = toolbox.has_free_worker()
    with ThreadPoolExecutor(max_workers=1) as executor:
        blocked_call = executor.submit(
            toolbox.call, KnowledgeToolName.SEARCH_VULNERABILITIES, {"query": "ausf"}
        )
        assert blocking_retriever.entered.wait(timeout=ONE_SECOND_RUN_REAL_SECONDS)

        had_free_worker_while_blocked = toolbox.has_free_worker()

        blocked_call_release.set()
        require_answer(blocked_call.result(timeout=ONE_SECOND_RUN_REAL_SECONDS))
    assert had_free_worker_before is True
    assert had_free_worker_while_blocked is False
    assert toolbox.has_free_worker() is True


def test_longest_call_is_an_investigation_at_the_largest_budget_plus_the_seal_margin() -> None:
    limits = ToolLimits()

    longest_call_seconds = limits.find_longest_call_seconds()

    assert MAX_WALL_TIME_SECONDS == 30
    assert longest_call_seconds == 40.0


def test_investigation_runs_for_its_wall_time_budget_plus_the_seal_margin(
    fixture_bundle: FixtureBundle,
) -> None:
    # Each read of the tool clock advances it 1.5 s: past the common limit and past the
    # run's 1 s wall-time budget, but within the budget plus the 10 s seal margin. A call
    # bounded by either of the first two times out before it starts.
    toolbox = build_test_toolbox(
        fixture_bundle, tool_clock=SteppingClock(seconds_per_read=1.5).read, limits=SHORT_LIMITS
    )

    tool_answer = require_answer(
        toolbox.call(
            KnowledgeToolName.INVESTIGATE_TELECOM_TOPIC,
            {"query": "5gaka", "scope": "mixed", "budget": {"max_wall_time_seconds": 1}},
        )
    )

    assert tool_answer.structured_content["status"] == "ok"


def test_timed_out_call_keeps_its_worker_until_its_backend_returns(
    fixture_bundle: FixtureBundle, blocked_call_release: threading.Event
) -> None:
    """Three calls against a backend that never returns, under a cap of one: the first is
    abandoned, but still holds the only worker, so the next two start nothing."""
    blocking_retriever = BlockingRetriever(blocked_call_release)
    toolbox = build_test_toolbox(
        fixture_bundle,
        tool_clock=SteppingClock(seconds_per_read=STEPPED_SECONDS_PER_READ).read,
        limits=replace(SHORT_LIMITS, max_calls_in_flight=1),
        lexical_retriever=blocking_retriever,
    )

    failure_codes: list[ToolFailureCode] = []
    for query in ("ausf", "smf", "amf"):
        tool_failure = require_failure(
            toolbox.call(KnowledgeToolName.SEARCH_VULNERABILITIES, {"query": query})
        )
        failure_codes.append(tool_failure.code)

    assert failure_codes == [
        ToolFailureCode.TIMED_OUT,
        ToolFailureCode.SERVER_BUSY,
        ToolFailureCode.SERVER_BUSY,
    ]
    assert blocking_retriever.received_queries == ["ausf"]


def test_worker_is_free_again_once_the_abandoned_backend_returns(
    fixture_bundle: FixtureBundle, blocked_call_release: threading.Event
) -> None:
    toolbox = build_test_toolbox(
        fixture_bundle,
        tool_clock=SteppingClock(seconds_per_read=STEPPED_SECONDS_PER_READ).read,
        limits=replace(SHORT_LIMITS, max_calls_in_flight=1),
        lexical_retriever=BlockingRetriever(blocked_call_release),
    )
    require_failure(toolbox.call(KnowledgeToolName.SEARCH_VULNERABILITIES, {"query": "ausf"}))
    blocked_call_release.set()
    join_abandoned_calls()

    tool_outcome = toolbox.call(KnowledgeToolName.GET_KNOWLEDGE_CAPABILITIES, {})

    require_answer(tool_outcome)


def test_investigation_is_refused_while_abandoned_investigation_calls_fill_the_cap(
    fixture_bundle: FixtureBundle, blocked_call_release: threading.Event
) -> None:
    """An investigation abandons its blocked search at its own deadline and still answers,
    so the toolbox's worker is free again; the abandoned search is not, and the next
    investigation is refused while other tools are still served."""
    run_clock = SteppingClock()
    blocking_retriever = BlockingRetriever(blocked_call_release)
    toolbox = build_test_toolbox(
        fixture_bundle,
        monotonic_clock=run_clock.read,
        limits=ToolLimits(max_calls_in_flight=1),
        # The search moves the run's clock past its deadline, then blocks.
        lexical_retriever=SlowRetriever(blocking_retriever, run_clock, seconds=5.0),
    )
    investigation_arguments = {
        "query": "5gaka",
        "scope": "mixed",
        "budget": {"max_wall_time_seconds": 1},
    }
    first_investigation = require_answer(
        toolbox.call(KnowledgeToolName.INVESTIGATE_TELECOM_TOPIC, investigation_arguments)
    )

    second_investigation = require_failure(
        toolbox.call(KnowledgeToolName.INVESTIGATE_TELECOM_TOPIC, investigation_arguments)
    )
    capabilities_outcome = toolbox.call(KnowledgeToolName.GET_KNOWLEDGE_CAPABILITIES, {})

    assert first_investigation.structured_content["stop_reason"] == "budget_exhausted"
    assert second_investigation.code is ToolFailureCode.SERVER_BUSY
    require_answer(capabilities_outcome)
    assert len(blocking_retriever.received_queries) == 1


def test_response_over_cap_returns_response_too_large(fixture_bundle: FixtureBundle) -> None:
    toolbox = build_test_toolbox(fixture_bundle, limits=ToolLimits(max_response_bytes=100))

    tool_failure = require_failure(toolbox.call(KnowledgeToolName.GET_KNOWLEDGE_CAPABILITIES, {}))

    assert tool_failure.code is ToolFailureCode.RESPONSE_TOO_LARGE


def test_raising_service_returns_fixed_internal_error_and_logs_the_traceback(
    fixture_bundle: FixtureBundle, caplog: pytest.LogCaptureFixture
) -> None:
    """The client sees the fixed message only; the exception goes to the log."""
    toolbox = build_test_toolbox(
        fixture_bundle, lexical_retriever=RaisingRetriever(SECRET_ERROR_TEXT)
    )

    with caplog.at_level(logging.ERROR, logger=TOOLBOX_LOGGER):
        tool_failure = require_failure(
            toolbox.call(KnowledgeToolName.SEARCH_VULNERABILITIES, {"query": "ausf"})
        )

    logged_error_texts: list[str] = []
    for log_record in caplog.records:
        if log_record.name == TOOLBOX_LOGGER and log_record.exc_info is not None:
            logged_error_texts.append(str(log_record.exc_info[1]))
    assert tool_failure.code is ToolFailureCode.INTERNAL_ERROR
    assert "secret" not in tool_failure.model_dump_json()
    assert "/etc/passwd" not in tool_failure.model_dump_json()
    assert logged_error_texts == [SECRET_ERROR_TEXT]


def test_integrity_failure_returns_integrity_check_failed(fixture_bundle: FixtureBundle) -> None:
    toolbox = build_test_toolbox(fixture_bundle, lexical_retriever=InventingRetriever())

    tool_failure = require_failure(
        toolbox.call(KnowledgeToolName.SEARCH_VULNERABILITIES, {"query": "ausf"})
    )

    assert tool_failure.code is ToolFailureCode.INTEGRITY_CHECK_FAILED


def test_production_toolbox_reports_affectedness_blocked_unverified(
    fixture_bundle: FixtureBundle,
) -> None:
    toolbox = build_knowledge_toolbox(fixture_bundle)

    capabilities_answer = require_answer(
        toolbox.call(KnowledgeToolName.GET_KNOWLEDGE_CAPABILITIES, None)
    )
    check_answer = require_answer(
        toolbox.call(
            KnowledgeToolName.CHECK_AFFECTEDNESS,
            TOOL_ARGUMENTS[KnowledgeToolName.CHECK_AFFECTEDNESS],
        )
    )

    assert list_affectedness_capabilities(capabilities_answer.structured_content) == [
        BLOCKED_AFFECTEDNESS_CAPABILITY
    ]
    assert check_answer.structured_content["applicability"] == "unknown"
    assert check_answer.structured_content["failure"] == "blocked_unverified"
    assert check_answer.structured_content["detail"] == AffectednessDetail.BLOCKED_UNVERIFIED


def test_configured_trustify_port_describes_the_capability_and_answers_checks_in_time(
    fixture_bundle: FixtureBundle,
) -> None:
    """Each failure's sentence is the affectedness check's own unit test; here the toolbox
    hands the one configured port the request and the configured timeout, and reports the
    server's sentences for that same port's reasons."""
    trustify_port = InMemoryTrustifyPort(
        failure=AffectednessFailure.SOURCE_UNAVAILABLE,
        described_failure=AffectednessFailure.AUTH_FAILED,
    )
    toolbox = build_test_toolbox(fixture_bundle, trustify_port=trustify_port)

    capabilities_answer = require_answer(
        toolbox.call(KnowledgeToolName.GET_KNOWLEDGE_CAPABILITIES, None)
    )
    check_answer = require_answer(
        toolbox.call(
            KnowledgeToolName.CHECK_AFFECTEDNESS,
            TOOL_ARGUMENTS[KnowledgeToolName.CHECK_AFFECTEDNESS],
        )
    )

    affectedness_details: list[str] = []
    for capability in list_affectedness_capabilities(capabilities_answer.structured_content):
        affectedness_details.append(capability["detail"])
    assert affectedness_details == [AffectednessDetail.AUTH_FAILED]
    assert check_answer.structured_content == {
        "schema_version": check_answer.structured_content["schema_version"],
        "request": TOOL_ARGUMENTS[KnowledgeToolName.CHECK_AFFECTEDNESS],
        "applicability": "unknown",
        "failure": "source_unavailable",
        "detail": AffectednessDetail.SOURCE_UNAVAILABLE,
    }
    assert trustify_port.received_checks == [
        (build_affectedness_request(), AFFECTEDNESS_TIMEOUT_SECONDS)
    ]


def test_blocking_trustify_port_returns_timed_out_within_bound(
    fixture_bundle: FixtureBundle, blocked_call_release: threading.Event
) -> None:
    toolbox = build_test_toolbox(
        fixture_bundle,
        trustify_port=BlockingTrustifyPort(blocked_call_release),
        tool_clock=SteppingClock(seconds_per_read=STEPPED_SECONDS_PER_READ).read,
        limits=SHORT_LIMITS,
    )
    started_at = time.monotonic()

    tool_failure = require_failure(
        toolbox.call(
            KnowledgeToolName.CHECK_AFFECTEDNESS,
            TOOL_ARGUMENTS[KnowledgeToolName.CHECK_AFFECTEDNESS],
        )
    )

    assert tool_failure.code is ToolFailureCode.TIMED_OUT
    assert time.monotonic() - started_at < ONE_SECOND_RUN_REAL_SECONDS


def list_semantic_channel_failures(source_outcomes: list[dict[str, Any]]) -> list[Any]:
    """The semantic entries of the ``cve_search`` outcomes' channel failures."""
    semantic_details: list[Any] = []
    for source_outcome in source_outcomes:
        for channel_failure in source_outcome["channel_failures"]:
            if channel_failure["channel"] == "semantic":
                semantic_details.append(channel_failure["detail"])
    return semantic_details


@pytest.mark.parametrize("failure", list(BackendFailure), ids=str)
def test_failing_semantic_adapter_publishes_only_the_server_sentence_for_its_reason(
    fixture_bundle: FixtureBundle, failure: BackendFailure
) -> None:
    semantic_retriever = CannedRetriever(build_failure(BackendStatus.UNAVAILABLE, failure))
    toolbox = build_test_toolbox(fixture_bundle, semantic_retriever=semantic_retriever)
    expected_detail = BACKEND_FAILURE_DETAILS[failure].value

    search_answer = require_answer(
        toolbox.call(
            KnowledgeToolName.SEARCH_VULNERABILITIES, {"query": "ausf crash", "semantic": True}
        )
    )
    investigation_answer = require_answer(
        toolbox.call(
            KnowledgeToolName.INVESTIGATE_TELECOM_TOPIC,
            {
                "query": "5gaka",
                "scope": "mixed",
                "semantic": True,
                "filters": {"products": ["demo_gateway"]},
            },
        )
    )

    assert {
        "channel": "semantic",
        "status": "unavailable",
        "detail": expected_detail,
    } in search_answer.structured_content["channel_outcomes"]
    assert list_semantic_channel_failures(
        investigation_answer.structured_content["coverage"]["source_outcomes"]
    ) == [expected_detail]


@pytest.mark.parametrize("failure", list(BackendFailure), ids=str)
def test_failing_fight_source_publishes_only_the_server_sentence_for_its_reason(
    fixture_bundle: FixtureBundle, failure: BackendFailure
) -> None:
    fight_source = FailingFightSource(choose_fight_source("packaged")[0], failure=failure)
    toolbox = build_test_toolbox(fixture_bundle, fight_source=fight_source)

    tool_answer = require_answer(
        toolbox.call(KnowledgeToolName.SEARCH_FIGHT, {"query": "5gaka", "limit": 3})
    )

    fight_details: list[Any] = []
    for source_outcome in tool_answer.structured_content["source_outcomes"]:
        if source_outcome["source"] == "mitre_fight":
            fight_details.append(source_outcome["detail"])
    assert fight_details == [BACKEND_FAILURE_DETAILS[failure].value]


@pytest.mark.parametrize(
    "item_changes",
    [{"matched_terms": (VERDICT_TEXT,)}, {"matched_fields": (VERDICT_TEXT,)}],
    ids=["term_never_sent", "unknown_field"],
)
def test_fight_source_explaining_a_match_in_its_own_words_fails_the_integrity_check(
    fixture_bundle: FixtureBundle, item_changes: dict[str, Any]
) -> None:
    fight_source = RewordingFightSource(choose_fight_source("packaged")[0], item_changes)
    toolbox = build_test_toolbox(fixture_bundle, fight_source=fight_source)

    tool_failure = require_failure(
        toolbox.call(KnowledgeToolName.SEARCH_FIGHT, {"query": "5gaka", "limit": 3})
    )

    assert tool_failure.code is ToolFailureCode.INTEGRITY_CHECK_FAILED


def test_retriever_explaining_a_match_in_its_own_words_never_reaches_a_client(
    fixture_bundle: FixtureBundle,
) -> None:
    """The search fails its integrity check, and the investigation records the step as
    rejected evidence; neither answer carries the retriever's text."""
    lying_match = RetrievalMatch(
        cve_id="CVE-9999-0003",
        score=1.0,
        matched_fields=("description",),
        matched_terms=(VERDICT_TEXT,),
    )
    lexical_retriever = CannedRetriever(
        RetrievalOutcome(status=BackendStatus.OK, matches=(lying_match,))
    )
    toolbox = build_test_toolbox(fixture_bundle, lexical_retriever=lexical_retriever)

    search_outcome = toolbox.call(KnowledgeToolName.SEARCH_VULNERABILITIES, {"query": "ausf"})
    investigation_answer = require_answer(
        toolbox.call(
            KnowledgeToolName.INVESTIGATE_TELECOM_TOPIC, {"query": "ausf", "scope": "mixed"}
        )
    )

    assert require_failure(search_outcome).code is ToolFailureCode.INTEGRITY_CHECK_FAILED
    assert VERDICT_TEXT not in investigation_answer.json_text
    assert investigation_answer.structured_content["stop_reason"] == "invalid_evidence"


def test_adapter_forging_its_failure_returns_internal_error_without_the_text(
    fixture_bundle: FixtureBundle,
) -> None:
    """An adapter that skips validation to put text in its typed failure gets no answer
    published at all."""
    forged_outcome = RetrievalOutcome.model_construct(
        status=BackendStatus.UNAVAILABLE, matches=(), failure=VERDICT_TEXT
    )
    toolbox = build_test_toolbox(fixture_bundle, semantic_retriever=CannedRetriever(forged_outcome))

    tool_outcome = toolbox.call(
        KnowledgeToolName.SEARCH_VULNERABILITIES, {"query": "ausf crash", "semantic": True}
    )

    tool_failure = require_failure(tool_outcome)
    assert tool_failure.code is ToolFailureCode.INTERNAL_ERROR
    assert "CONFIRMED" not in tool_failure.model_dump_json()


def test_port_answering_verdict_text_returns_internal_error(
    fixture_bundle: FixtureBundle,
) -> None:
    trustify_port = MisansweringTrustifyPort(answer="CONFIRMED: pkg is affected by this CVE.")
    toolbox = build_test_toolbox(fixture_bundle, trustify_port=trustify_port)

    tool_failure = require_failure(
        toolbox.call(
            KnowledgeToolName.CHECK_AFFECTEDNESS,
            TOOL_ARGUMENTS[KnowledgeToolName.CHECK_AFFECTEDNESS],
        )
    )

    assert tool_failure.code is ToolFailureCode.INTERNAL_ERROR


def test_concurrent_calls_return_the_serial_results(fixture_bundle: FixtureBundle) -> None:
    toolbox = build_test_toolbox(fixture_bundle, tool_clock=time.monotonic)
    serial_fingerprints: dict[KnowledgeToolName, str] = {}
    for tool_name, arguments in TOOL_ARGUMENTS.items():
        serial_fingerprints[tool_name] = fingerprint_answer(
            require_answer(toolbox.call(tool_name, arguments))
        )

    with ThreadPoolExecutor(max_workers=4) as executor:
        pending_calls: list[tuple[KnowledgeToolName, Future[ToolAnswer | ToolFailure]]] = []
        for _ in range(4):
            for tool_name, arguments in TOOL_ARGUMENTS.items():
                pending_calls.append(
                    (tool_name, executor.submit(toolbox.call, tool_name, arguments))
                )
        concurrent_mismatches: list[str] = []
        for tool_name, pending_call in pending_calls:
            tool_answer = require_answer(pending_call.result())
            if fingerprint_answer(tool_answer) != serial_fingerprints[tool_name]:
                concurrent_mismatches.append(tool_name.value)

    assert len(pending_calls) == 4 * len(TOOL_ARGUMENTS)
    assert concurrent_mismatches == []
