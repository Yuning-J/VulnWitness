"""The committed request schema accepts exactly the requests the model accepts."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from cve_kgrag.domain.budget import (
    MAX_CONTEXT_BYTES,
    MAX_ROUNDS,
    MAX_SOURCES,
    MAX_TOOL_CALLS,
    MAX_WALL_TIME_SECONDS,
)
from cve_kgrag.domain.investigation import InvestigationRequest
from cve_kgrag.domain.planning import QueryPlan
from cve_kgrag.domain.search import (
    MAX_FILTER_VALUES,
    MAX_RESULTS_PER_CALL,
    SearchFilters,
    SearchRequest,
)
from cve_kgrag.domain.topic_context import TopicContextRequest
from cve_kgrag.schema_snapshots import REQUEST_CONTRACTS
from tests.support.paths import REPOSITORY_SCHEMA_DIR

REQUEST_SCHEMA_FILE = REPOSITORY_SCHEMA_DIR / "search_request.schema.json"
TOPIC_REQUEST_SCHEMA_FILE = REPOSITORY_SCHEMA_DIR / "topic_context_request.schema.json"
INVESTIGATION_REQUEST_SCHEMA_FILE = REPOSITORY_SCHEMA_DIR / "investigation_request.schema.json"
QUERY_PLAN_SCHEMA_FILE = REPOSITORY_SCHEMA_DIR / "query_plan.schema.json"
BUDGET_CAPS = {
    "max_rounds": MAX_ROUNDS,
    "max_tool_calls": MAX_TOOL_CALLS,
    "max_sources": MAX_SOURCES,
    "max_results_per_call": MAX_RESULTS_PER_CALL,
    "max_wall_time_seconds": MAX_WALL_TIME_SECONDS,
    "max_context_bytes": MAX_CONTEXT_BYTES,
}
SMUGGLED_KEYS = ("url", "path", "sql", "cypher", "shell", "planner")
TOPIC_REQUEST_SAMPLES = [
    {"query": "5gaka", "scope": "protocol_context_only"},
    {"query": "5gaka", "scope": "mixed", "limit": 20},
    {"query": "5gaka"},
    {"query": "5gaka", "scope": "protocol"},
    {"query": "5gaka", "scope": "mixed", "limit": "5"},
    {"query": "5gaka", "scope": "mixed", "limit": 0},
    {"query": "5gaka", "scope": "mixed", "max_results_per_search": 1},
    {"query": "5gaka", "scope": "mixed", "max_results_per_search": MAX_RESULTS_PER_CALL + 1},
    {"query": "5gaka", "scope": "mixed", "max_results_per_search": 0},
    {"query": "", "scope": "mixed"},
    {"query": "5gaka", "scope": "mixed", "formal": True},
]
FILTER_SAMPLES = [
    {"vendors": ["DemoCorp", "democorp"]},
    {"vendors": ["ß" * 128]},
    {"products": ["ﬃ" * 100]},
    {"vendors": ["democorp", "democorp"]},
    {"vendors": ["  "]},
    {"vendors": [" democorp"]},
    {"vendors": ["v" * 128]},
    {"vendors": ["v" * 129]},
    {"vendors": ["vendor"] * (MAX_FILTER_VALUES + 1)},
    {"products": ["demo gateway"]},
    {"purls": ["pkg:PyPI/example-parser"]},
    {"purls": ["PKG:pypi/example-parser"]},
    {"purls": ["pkg:pypi/example-parser@4.1.2"]},
    {"purls": ["pkg:pypi/example parser"]},
    {"cwe_ids": ["CWE-89"]},
    {"cwe_ids": ["cwe-89"]},
    {"cwe_ids": ["CWE-" + "9" * 12]},
    {"cwe_ids": ["CWE-" + "9" * 13]},
    {"severities": ["HIGH", "CRITICAL"]},
    {"severities": ["high"]},
    {"severities": ["HIGH", "HIGH"]},
    {"origins": ["implementation", "dependency"]},
    {"origins": ["protocol"]},
    {"published_years": [1999, 2026]},
    {"published_years": [1998]},
    {"published_years": [2026, 2026]},
    {"published_years": ["2020"]},
    {"published_years": [2020.0]},
    {"kev_only": True},
    {"kev_only": "false"},
    {"kev_only": 1},
    {"unknown_filter": True},
]
REQUEST_SAMPLES = [
    {"query": "   "},
    {"query": ""},
    {"query": "q" * 513},
    {"query": "gateway", "limit": 20},
    {"query": "gateway", "limit": 21},
    {"query": "gateway", "limit": "5"},
    {"query": "gateway", "limit": True},
    {"query": "gateway", "limit": 5.0},
    {"query": "gateway", "limit": 5.5},
    {"query": "gateway", "graph_expand": 1},
    {"query": "gateway", "semantic": "yes"},
    {"query": "gateway", "graph_expand": True, "semantic": False},
    {"query": "gateway", "filters": None},
    {"query": "gateway", "extra": 1},
]


INVESTIGATION_REQUEST_FIXED_SAMPLES = [
    {"query": "5gaka", "scope": "protocol_context_only"},
    {"query": "5gaka", "scope": "mixed", "filters": {"products": ["f5gc"]}, "semantic": True},
    {"query": "5gaka"},
    {"query": "5gaka", "scope": "protocol_only"},
    {"query": "5gaka", "scope": "mixed", "semantic": "yes"},
    {"query": "", "scope": "mixed"},
    {"query": "q" * 513, "scope": "mixed"},
    {"query": "5gaka", "scope": "mixed", "budget": None},
    {"query": "5gaka", "scope": "mixed", "budget": {}},
]
STEP = {"tool": "cve_search", "query": "ausf crash"}
QUERY_PLAN_SAMPLES = [
    {"steps": [STEP]},
    {
        "steps": [
            {"tool": "cve_exact_lookup", "cve_ids": ["CVE-9999-0003"]},
            {"tool": "topic_context", "topic_id": "3gpp:5g-aka"},
        ]
    },
    {"steps": [STEP] * 8},
    {"steps": [STEP] * 9},
    {"steps": []},
    {},
    {"steps": [STEP], "url": "https://evil.example"},
    {"steps": [{**STEP, "url": "https://evil.example"}]},
    {"steps": [{**STEP, "limit": 5}]},
    {"steps": [{**STEP, "claims": ["5G-AKA is broken"]}]},
    {"steps": [{"tool": "shell", "command": "ls"}]},
    {"steps": [{"tool": "cve_search"}]},
    {"steps": [{"tool": "cve_search", "query": ""}]},
    {"steps": [{"tool": "cve_exact_lookup", "cve_ids": ["CVE-99-1"]}]},
    {"steps": [{"tool": "cve_exact_lookup", "cve_ids": ["CVE-9999-0003"] * 21}]},
    {"steps": [{"tool": "topic_context", "topic_id": "../etc/passwd"}]},
    {"steps": [{"tool": "topic_context", "topic_id": "3gpp:5g-aka", "query": "5gaka"}]},
]


GENUINE_CVE_ID = "CVE-2021-44228"
GENUINE_PURL = "pkg:generic/open5gs@2.7.0"
GENUINE_EVIDENCE_ID = "ev:0123456789abcdef01234567"
# MCP tool requests beyond each tool's genuine one, with whether its contract accepts them.
TOOL_REQUEST_SAMPLES: list[tuple[str, dict[str, object], bool]] = [
    ("capabilities_request", {"x": 1}, False),
    ("concept_resolution_request", {"query": ""}, False),
    ("concept_resolution_request", {"query": "q" * 513}, False),
    ("cve_lookup_request", {"cve_id": "CVE-2021-44228; DROP"}, False),
    ("cve_lookup_request", {"cve_id": "cve-2021-44228"}, False),
    ("fight_search_request", {"query": "5G-AKA", "limit": 20}, True),
    ("fight_search_request", {"query": "5G-AKA", "limit": "5"}, False),
    ("fight_search_request", {"query": "5G-AKA", "limit": 0}, False),
    ("fight_search_request", {"query": "5G-AKA", "limit": 21}, False),
    ("fight_search_request", {"query": "5G-AKA", "limit": True}, False),
    ("evidence_lookup_request", {"evidence_id": GENUINE_EVIDENCE_ID[:-1]}, False),
    (
        "affectedness_request",
        {"cve_id": GENUINE_CVE_ID, "purl": "pkg:pypi/example-parser@4.1.2+local"},
        True,
    ),
    (
        "affectedness_request",
        {"cve_id": GENUINE_CVE_ID, "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
        True,
    ),
    ("affectedness_request", {"cve_id": GENUINE_CVE_ID, "purl": "pkg:generic/.profile@1"}, True),
    ("affectedness_request", {"cve_id": GENUINE_CVE_ID, "purl": "pkg:generic/../x@1"}, False),
    (
        "affectedness_request",
        {"cve_id": GENUINE_CVE_ID, "purl": "pkg:generic/../../etc/passwd@1"},
        False,
    ),
    ("affectedness_request", {"cve_id": GENUINE_CVE_ID, "purl": "pkg:generic/a/./b@1"}, False),
    ("affectedness_request", {"cve_id": GENUINE_CVE_ID, "purl": "pkg:generic/..@1"}, False),
    ("affectedness_request", {"cve_id": GENUINE_CVE_ID, "purl": "pkg:generic//@1"}, False),
    ("affectedness_request", {"cve_id": GENUINE_CVE_ID, "purl": "pkg:generic//a@1"}, False),
    ("affectedness_request", {"cve_id": GENUINE_CVE_ID, "purl": "pkg:generic/a/@1"}, False),
    ("affectedness_request", {"cve_id": "cve-2021-44228", "purl": GENUINE_PURL}, False),
    ("affectedness_request", {"cve_id": GENUINE_CVE_ID, "purl": "pkg:generic/open5gs"}, False),
    (
        "affectedness_request",
        {"cve_id": GENUINE_CVE_ID, "purl": GENUINE_PURL + "?repository_url=https://x"},
        False,
    ),
    ("affectedness_request", {"cve_id": GENUINE_CVE_ID, "purl": "pkg:generic/open 5gs@1"}, False),
    ("affectedness_request", {"cve_id": GENUINE_CVE_ID, "purl": "pkg:generic/a@1#sub"}, False),
    ("affectedness_request", {"cve_id": GENUINE_CVE_ID, "purl": "PKG:generic/a@1"}, False),
    ("affectedness_request", {"cve_id": GENUINE_CVE_ID, "purl": "pkg:generic/a\u0007@1"}, False),
    ("affectedness_request", {"cve_id": GENUINE_CVE_ID, "purl": GENUINE_PURL + "\n"}, False),
    ("affectedness_request", {"cve_id": GENUINE_CVE_ID, "product": "open5gs"}, False),
]
TOOL_REQUEST_GENUINE_FIELDS: dict[str, dict[str, object]] = {
    "capabilities_request": {},
    "concept_resolution_request": {"query": "5G-AKA"},
    "cve_lookup_request": {"cve_id": GENUINE_CVE_ID},
    "fight_search_request": {"query": "5G-AKA"},
    "evidence_lookup_request": {"evidence_id": GENUINE_EVIDENCE_ID},
    "affectedness_request": {"cve_id": GENUINE_CVE_ID, "purl": GENUINE_PURL},
}


def list_tool_requests() -> list[tuple[str, dict[str, object], bool]]:
    """The fixed samples, plus each tool's genuine request, alone and with a smuggled
    ``url`` or ``path`` key."""
    tool_requests = list(TOOL_REQUEST_SAMPLES)
    for contract_name, genuine_fields in TOOL_REQUEST_GENUINE_FIELDS.items():
        tool_requests.append((contract_name, genuine_fields, True))
        for smuggled_key in ("url", "path"):
            tool_requests.append(
                (contract_name, {**genuine_fields, smuggled_key: "/etc/passwd"}, False)
            )
    return tool_requests


def label_tool_request(tool_request: tuple[str, dict[str, object], bool]) -> str:
    contract_name, request_fields, _ = tool_request
    return f"{contract_name}-{json.dumps(request_fields)}"


def list_investigation_requests() -> list[dict[str, object]]:
    """Fixed samples plus, per cap: at max, max+1, 0, a bool, a string and a float."""
    requests: list[dict[str, object]] = list(INVESTIGATION_REQUEST_FIXED_SAMPLES)
    for cap_name, cap in BUDGET_CAPS.items():
        for cap_value in (cap, cap + 1, 0, True, "5", 1.0, 1.5):
            requests.append({"query": "5gaka", "scope": "mixed", "budget": {cap_name: cap_value}})
    for smuggled_key in SMUGGLED_KEYS:
        requests.append({"query": "5gaka", "scope": "mixed", smuggled_key: "x"})
        requests.append({"query": "5gaka", "scope": "mixed", "budget": {smuggled_key: 1}})
    return requests


def decide_by_schema_and_model(
    schema_file: Path, model: type[BaseModel], sample: dict[str, object]
) -> tuple[bool, bool]:
    """Whether the schema validates the sample's JSON form, and whether the model parses it."""
    schema_validator = Draft202012Validator(json.loads(schema_file.read_text()))

    is_schema_valid = schema_validator.is_valid(json.loads(json.dumps(sample)))
    try:
        model.model_validate_json(json.dumps(sample))
        is_model_valid = True
    except ValidationError:
        is_model_valid = False
    return is_schema_valid, is_model_valid


def check_schema_and_model_agree(
    schema_file: Path, model: type[BaseModel], sample: dict[str, object]
) -> None:
    """The schema validates the sample's JSON form exactly when the model accepts it."""
    is_schema_valid, is_model_valid = decide_by_schema_and_model(schema_file, model, sample)

    assert is_schema_valid == is_model_valid


def list_requests() -> list[dict[str, object]]:
    requests: list[dict[str, object]] = []
    for filters in FILTER_SAMPLES:
        requests.append({"query": "gateway", "filters": filters})
    requests.extend(REQUEST_SAMPLES)
    return requests


@pytest.mark.parametrize("request_fields", list_requests(), ids=json.dumps)
def test_schema_and_model_agree_on_whether_a_request_is_valid(
    request_fields: dict[str, object],
) -> None:
    check_schema_and_model_agree(REQUEST_SCHEMA_FILE, SearchRequest, request_fields)


@pytest.mark.parametrize("filters", FILTER_SAMPLES[:3], ids=["mixed_case", "eszett", "ligature"])
def test_validated_filters_serialize_to_json_that_validates_again(
    filters: dict[str, object],
) -> None:
    validated = SearchFilters.model_validate(filters)

    assert SearchFilters.model_validate_json(validated.model_dump_json()) == validated


@pytest.mark.parametrize("request_fields", TOPIC_REQUEST_SAMPLES, ids=json.dumps)
def test_schema_and_model_agree_on_whether_a_topic_request_is_valid(
    request_fields: dict[str, object],
) -> None:
    check_schema_and_model_agree(TOPIC_REQUEST_SCHEMA_FILE, TopicContextRequest, request_fields)


@pytest.mark.parametrize("request_fields", list_investigation_requests(), ids=json.dumps)
def test_schema_and_model_agree_on_whether_an_investigation_request_is_valid(
    request_fields: dict[str, object],
) -> None:
    check_schema_and_model_agree(
        INVESTIGATION_REQUEST_SCHEMA_FILE, InvestigationRequest, request_fields
    )


@pytest.mark.parametrize("plan", QUERY_PLAN_SAMPLES, ids=json.dumps)
def test_schema_and_model_agree_on_whether_a_query_plan_is_valid(
    plan: dict[str, object],
) -> None:
    check_schema_and_model_agree(QUERY_PLAN_SCHEMA_FILE, QueryPlan, plan)


@pytest.mark.parametrize("tool_request", list_tool_requests(), ids=label_tool_request)
def test_schema_and_model_both_decide_a_tool_request_as_its_contract_states(
    tool_request: tuple[str, dict[str, object], bool],
) -> None:
    contract_name, request_fields, is_expected_valid = tool_request
    schema_file = REPOSITORY_SCHEMA_DIR / f"{contract_name}.schema.json"

    verdicts = decide_by_schema_and_model(
        schema_file, REQUEST_CONTRACTS[contract_name], request_fields
    )

    assert verdicts == (is_expected_valid, is_expected_valid)


# Text a reader cannot see: control characters and bidirectional overrides or isolates.
HIDDEN_TEXT_SAMPLES = {
    "nul": "a\x00b",
    "control_character": "\x01",
    "vertical_tab": "a\x0bb",
    "delete": "a\x7fb",
    "right_to_left_override": "abc‮dcba",
    "isolate": "a⁦b⁩",
}
# Each contract with a free-text query, and the other fields its genuine request needs.
QUERY_CONTRACT_FIELDS: dict[str, dict[str, object]] = {
    "search_request": {},
    "topic_context_request": {"scope": "mixed"},
    "investigation_request": {"scope": "mixed"},
    "concept_resolution_request": {},
    "fight_search_request": {},
}
# Filters on a genuine search, with whether the search request contract accepts them.
PRODUCT_FILTER_SAMPLES: list[tuple[dict[str, object], bool]] = [
    ({"vendors": ["a\x00b"]}, False),
    ({"vendors": ["  "]}, False),
    ({"vendors": ["demo‮corp"]}, False),
    ({"products": ["demo\tgateway"]}, False),
    ({"vendors": [" democorp"]}, True),
    ({"purls": ["pkg:npm/foo\n"]}, False),
    ({"purls": ["pkg:\x00"]}, False),
    ({"purls": ["pkg:npm/foo‮"]}, False),
    ({"purls": ["pkg:npm/../../etc/passwd"]}, False),
    ({"purls": ["pkg:npm/./foo"]}, False),
    ({"purls": ["pkg:npm//foo"]}, False),
    ({"purls": ["pkg:pypi/example parser"]}, False),
    ({"purls": ["pkg:npm/foo@1.0.0"]}, False),
    ({"purls": ["pkg:npm"]}, False),
    ({"purls": ["pkg:PyPI/democorp-gateway"]}, True),
    ({"purls": ["pkg:generic/fictional5g/f5gc"]}, True),
    ({"purls": ["pkg:npm/%40scope/name"]}, True),
]


def decide_query_request(contract_name: str, query: str) -> tuple[bool, bool]:
    """Whether the committed schema and the model accept ``contract_name``'s genuine request
    asking ``query``."""
    return decide_by_schema_and_model(
        REPOSITORY_SCHEMA_DIR / f"{contract_name}.schema.json",
        REQUEST_CONTRACTS[contract_name],
        {"query": query, **QUERY_CONTRACT_FIELDS[contract_name]},
    )


@pytest.mark.parametrize("hidden_text", HIDDEN_TEXT_SAMPLES.values(), ids=HIDDEN_TEXT_SAMPLES)
@pytest.mark.parametrize("contract_name", QUERY_CONTRACT_FIELDS)
def test_schema_and_model_both_refuse_a_query_holding_hidden_text(
    contract_name: str, hidden_text: str
) -> None:
    verdicts = decide_query_request(contract_name, hidden_text)

    assert verdicts == (False, False)


@pytest.mark.parametrize("contract_name", QUERY_CONTRACT_FIELDS)
def test_schema_and_model_both_accept_a_query_of_spaces_only(contract_name: str) -> None:
    verdicts = decide_query_request(contract_name, "   ")

    assert verdicts == (True, True)


@pytest.mark.parametrize(
    "query",
    ["ausf\tcrash", "ausf\ncrash", "ausf crash\r\nin open5gs"],
    ids=["tab", "line_feed", "carriage_return_and_line_feed"],
)
@pytest.mark.parametrize("contract_name", QUERY_CONTRACT_FIELDS)
def test_schema_and_model_both_accept_a_query_pasted_with_line_breaks(
    contract_name: str, query: str
) -> None:
    verdicts = decide_query_request(contract_name, query)

    assert verdicts == (True, True)


@pytest.mark.parametrize(("filters", "is_expected_valid"), PRODUCT_FILTER_SAMPLES, ids=json.dumps)
def test_schema_and_model_both_decide_a_product_filter_as_its_contract_states(
    filters: dict[str, object], is_expected_valid: bool
) -> None:
    verdicts = decide_by_schema_and_model(
        REQUEST_SCHEMA_FILE, SearchRequest, {"query": "gateway", "filters": filters}
    )

    assert verdicts == (is_expected_valid, is_expected_valid)
