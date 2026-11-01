"""The planner contract: a plan carries allowlisted tool calls and nothing else."""

import json
from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError

from tests.support.investigation import build_exact_lookup_call, build_search_call, build_topic_call
from vulnwitness.domain.planning import (
    CveExactLookupCall,
    CveSearchCall,
    PlannerIdentity,
    QueryPlan,
    ToolCall,
    TopicContextCall,
    compute_call_key,
)

SEARCH_CALL = {"tool": "cve_search", "query": "ausf crash"}


def test_plan_of_every_allowlisted_tool_parses_into_typed_calls() -> None:
    plan_text = json.dumps(
        {
            "steps": [
                {"tool": "cve_exact_lookup", "cve_ids": ["CVE-9999-0003"]},
                SEARCH_CALL,
                {"tool": "topic_context", "topic_id": "3gpp:5g-aka"},
            ]
        }
    )

    query_plan = QueryPlan.model_validate_json(plan_text)

    step_types: list[type] = []
    for call in query_plan.steps:
        step_types.append(type(call))
    assert step_types == [CveExactLookupCall, CveSearchCall, TopicContextCall]


@pytest.mark.parametrize(
    "plan",
    [
        {"steps": [SEARCH_CALL], "url": "https://evil.example"},
        {"steps": [SEARCH_CALL], "scope": "mixed"},
        {"steps": [{**SEARCH_CALL, "url": "https://evil.example"}]},
        {"steps": [{**SEARCH_CALL, "sql": "DROP TABLE cves"}]},
        {"steps": [{**SEARCH_CALL, "cypher": "MATCH (n) DETACH DELETE n"}]},
        {"steps": [{**SEARCH_CALL, "limit": 100}]},
        {"steps": [{**SEARCH_CALL, "filters": {"vendors": ["x"]}}]},
        {"steps": [{**SEARCH_CALL, "claims": ["5G-AKA is broken"]}]},
        {"steps": [{"tool": "shell", "command": "rm -rf /"}]},
        {"steps": [{"tool": "graph_expand", "cve_ids": ["CVE-9999-0003"]}]},
        {"steps": [{"query": "ausf"}]},
        {"steps": []},
        {"steps": [SEARCH_CALL] * 9},
        {"steps": [{"tool": "topic_context", "topic_id": "../../etc/passwd"}]},
        {"steps": [{"tool": "topic_context", "topic_id": "5G-AKA"}]},
        {"steps": [{"tool": "cve_exact_lookup", "cve_ids": ["CVE-99-1"]}]},
        {"steps": [{"tool": "cve_exact_lookup", "cve_ids": []}]},
        {"steps": [{"tool": "cve_search", "query": ""}]},
        {"steps": [{"tool": "cve_search", "query": "q" * 513}]},
    ],
    ids=[
        "plan_url",
        "plan_scope",
        "step_url",
        "step_sql",
        "step_cypher",
        "step_limit",
        "step_filters",
        "step_claims",
        "unknown_tool_shell",
        "unknown_tool_graph_expand",
        "missing_tool",
        "zero_steps",
        "nine_steps",
        "topic_id_path",
        "topic_id_alias",
        "malformed_cve_id",
        "no_cve_ids",
        "empty_query",
        "overlong_query",
    ],
)
def test_plan_carrying_anything_but_allowlisted_calls_is_rejected(plan: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        QueryPlan.model_validate_json(json.dumps(plan))


def test_plan_of_eight_steps_is_accepted() -> None:
    query_plan = QueryPlan.model_validate({"steps": [SEARCH_CALL] * 8})

    assert len(query_plan.steps) == 8


@pytest.mark.parametrize(
    "identity_fields",
    [
        {"kind": "deterministic"},
        {"kind": "deterministic", "policy_version": "m4.1", "model_name": "gpt"},
        {"kind": "model"},
        {"kind": "model", "model_name": "name with spaces"},
        {"kind": "model", "policy_version": "m4.1", "model_name": "gpt"},
    ],
    ids=[
        "deterministic_without_version",
        "deterministic_with_model",
        "model_unnamed",
        "bad_name",
        "model_with_policy_version",
    ],
)
def test_planner_identity_that_does_not_fit_its_kind_is_rejected(
    identity_fields: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(PlannerIdentity).validate_python(identity_fields)


@pytest.mark.parametrize(
    ("first_call", "second_call"),
    [
        (build_search_call("5G  AKA"), build_search_call("5g-aka")),
        (build_search_call("the AUSF crash"), build_search_call("ausf, crash")),
        (build_search_call("ausf suci"), build_search_call("suci ausf ausf")),
        (build_search_call("cve ausf CVEs"), build_search_call("ausf")),
        (
            build_exact_lookup_call("CVE-9999-0003", "CVE-9999-0004"),
            build_exact_lookup_call("CVE-9999-0004", "CVE-9999-0003", "CVE-9999-0004"),
        ),
    ],
    ids=[
        "spacing_and_punctuation",
        "stopwords_and_case",
        "token_order_and_repeats",
        "low_signal_words",
        "id_order",
    ],
)
def test_call_key_is_equal_for_calls_that_normalize_alike(
    first_call: ToolCall, second_call: ToolCall
) -> None:
    assert compute_call_key(first_call) == compute_call_key(second_call)


@pytest.mark.parametrize(
    ("first_call", "second_call"),
    [
        (build_search_call("5g aka"), build_search_call("5gaka")),
        (
            build_exact_lookup_call("CVE-9999-0003"),
            build_exact_lookup_call("CVE-9999-0003", "CVE-9999-0004"),
        ),
        (build_topic_call(), build_search_call("3gpp 5g aka")),
    ],
    ids=["different_tokens", "different_ids", "different_tools"],
)
def test_call_key_differs_for_different_calls(first_call: ToolCall, second_call: ToolCall) -> None:
    assert compute_call_key(first_call) != compute_call_key(second_call)
