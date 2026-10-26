"""The knowledge tool surface is exactly the brief's eight tools over registered v2
contracts, no tool input can name a location, a query language, a command or a model, every
source-text field a CVE record or FiGHT technique carries is named untrusted, every tool
answering with CVE records says their affected entries are no affectedness check, and the
limits let the affectedness port time out inside its tool's limit."""

import json
from typing import Any

import pytest
from pydantic import BaseModel

from cve_kgrag.composition import load_packaged_source_registry
from cve_kgrag.domain.cve import CveRecord
from cve_kgrag.domain.served_dataset import ServedDatasetKind
from cve_kgrag.domain.threat_context import ThreatContextItem
from cve_kgrag.interfaces.knowledge_tools import (
    CVE_RECORD_SOURCE_TEXT_FIELDS,
    FIGHT_TECHNIQUE_SOURCE_TEXT_FIELDS,
    KNOWLEDGE_TOOL_SPECS,
    NVD_ATTRIBUTION,
    PUBLISHER_AFFECTED_STATEMENT,
    SERVER_INSTRUCTIONS,
    ToolLimits,
)
from cve_kgrag.schema_snapshots import REQUEST_CONTRACTS, RESPONSE_CONTRACTS, render_schema

BRIEF_TOOL_NAMES = {
    "get_knowledge_capabilities",
    "resolve_telecom_concept",
    "lookup_cve",
    "search_vulnerabilities",
    "search_fight",
    "check_affectedness",
    "get_evidence",
    "investigate_telecom_topic",
}
# A field name holding one of these words could carry a path, URL, endpoint, query
# language, command, code, model name or index operation.
FORBIDDEN_FIELD_WORDS = {
    "url",
    "uri",
    "path",
    "file",
    "directory",
    "endpoint",
    "host",
    "sql",
    "cypher",
    "command",
    "shell",
    "code",
    "script",
    "model",
    "index",
}
# Free-text fields of a FiGHT technique the service fills from its own matching, never from
# the source.
SERVICE_MATCH_FIELDS = {"matched_fields", "matched_terms"}


def list_input_schemas() -> list[dict[str, Any]]:
    input_schemas: list[dict[str, Any]] = []
    for tool_spec in KNOWLEDGE_TOOL_SPECS:
        input_schemas.append(json.loads(render_schema(tool_spec.request_model, "validation")))
    return input_schemas


def list_object_schemas(schema: dict[str, Any]) -> list[dict[str, Any]]:
    """Every schema object nested anywhere in ``schema`` that declares properties or the
    object type, ``schema`` included."""
    object_schemas: list[dict[str, Any]] = []
    unvisited_nodes: list[Any] = [schema]
    while unvisited_nodes:
        node = unvisited_nodes.pop()
        if isinstance(node, dict):
            if "properties" in node or node.get("type") == "object":
                object_schemas.append(node)
            unvisited_nodes.extend(node.values())
        elif isinstance(node, list):
            unvisited_nodes.extend(node)
    return object_schemas


def reaches_free_text(node: Any, definitions: dict[str, Any], visited_refs: frozenset[str]) -> bool:
    """Whether ``node`` or a schema it nests or references admits a string no pattern,
    enum, const or format constrains."""
    if isinstance(node, list):
        return any(reaches_free_text(child, definitions, visited_refs) for child in node)
    if not isinstance(node, dict):
        return False
    if "$ref" in node:
        definition_name = node["$ref"].rsplit("/", 1)[-1]
        if definition_name in visited_refs:
            return False
        return reaches_free_text(
            definitions[definition_name], definitions, visited_refs | {definition_name}
        )
    if node.get("type") == "string" and not node.keys() & {"pattern", "enum", "const", "format"}:
        return True
    return any(reaches_free_text(child, definitions, visited_refs) for child in node.values())


def list_free_text_fields(record_model: type[BaseModel]) -> set[str]:
    """The top-level fields of ``record_model`` that can carry free text."""
    schema = record_model.model_json_schema()
    free_text_fields: set[str] = set()
    for field_name, field_schema in schema["properties"].items():
        if reaches_free_text(field_schema, schema.get("$defs", {}), frozenset()):
            free_text_fields.add(field_name)
    return free_text_fields


def test_tool_names_are_exactly_the_eight_brief_tools() -> None:
    tool_names: list[str] = []
    for tool_spec in KNOWLEDGE_TOOL_SPECS:
        tool_names.append(tool_spec.name.value)

    assert sorted(tool_names) == sorted(BRIEF_TOOL_NAMES)


def test_each_tool_contract_is_a_registered_v2_contract() -> None:
    unregistered_contracts: list[str] = []
    for tool_spec in KNOWLEDGE_TOOL_SPECS:
        if tool_spec.request_model not in REQUEST_CONTRACTS.values():
            unregistered_contracts.append(tool_spec.request_model.__name__)
        if tool_spec.response_model not in RESPONSE_CONTRACTS.values():
            unregistered_contracts.append(tool_spec.response_model.__name__)

    assert unregistered_contracts == []


def test_no_input_schema_names_a_url_path_endpoint_sql_cypher_shell_code_model_or_index_field() -> (
    None
):
    field_names: set[str] = set()
    for input_schema in list_input_schemas():
        field_names.update(input_schema.get("$defs", {}))
        for object_schema in list_object_schemas(input_schema):
            field_names.update(object_schema.get("properties", {}))

    forbidden_field_names: list[str] = []
    for field_name in sorted(field_names):
        if FORBIDDEN_FIELD_WORDS.intersection(field_name.lower().split("_")):
            forbidden_field_names.append(field_name)
    assert field_names
    assert forbidden_field_names == []


def test_no_input_schema_accepts_free_form_keys() -> None:
    open_object_titles: list[str] = []
    object_count = 0
    for input_schema in list_input_schemas():
        for object_schema in list_object_schemas(input_schema):
            object_count += 1
            if object_schema.get("additionalProperties") is not False:
                open_object_titles.append(str(object_schema.get("title")))

    assert object_count > len(KNOWLEDGE_TOOL_SPECS)
    assert open_object_titles == []


@pytest.mark.parametrize(
    ("record_model", "untrusted_fields"),
    [
        (CveRecord, CVE_RECORD_SOURCE_TEXT_FIELDS),
        (ThreatContextItem, FIGHT_TECHNIQUE_SOURCE_TEXT_FIELDS),
    ],
    ids=["cve_record", "fight_technique"],
)
def test_every_source_text_field_is_named_untrusted_in_the_server_instructions(
    record_model: type[BaseModel], untrusted_fields: tuple[str, ...]
) -> None:
    source_text_fields = list_free_text_fields(record_model) - SERVICE_MATCH_FIELDS

    assert source_text_fields == set(untrusted_fields)
    for instructions in SERVER_INSTRUCTIONS.values():
        assert f"({', '.join(untrusted_fields)})" in instructions


def test_there_are_server_instructions_for_every_dataset_kind() -> None:
    assert set(SERVER_INSTRUCTIONS) == set(ServedDatasetKind)


def test_only_the_store_instructions_carry_the_registry_s_nvd_attribution() -> None:
    nvd_attribution = load_packaged_source_registry().find_source("nvd").attribution

    assert nvd_attribution == NVD_ATTRIBUTION
    assert SERVER_INSTRUCTIONS[ServedDatasetKind.CORPUS_STORE].endswith(NVD_ATTRIBUTION)
    assert NVD_ATTRIBUTION not in SERVER_INSTRUCTIONS[ServedDatasetKind.SYNTHETIC_FIXTURE]


def test_store_instructions_neither_claim_a_fixture_nor_real_data() -> None:
    store_instructions = SERVER_INSTRUCTIONS[ServedDatasetKind.CORPUS_STORE]

    assert "synthetic fixture" not in store_instructions
    assert "real" not in store_instructions.lower().split()
    assert "cve_search version" in store_instructions


def test_affectedness_timeout_not_below_the_tool_limit_is_refused() -> None:
    with pytest.raises(ValueError, match="affectedness_timeout_seconds must be below"):
        ToolLimits(time_limit_seconds=5.0, affectedness_timeout_seconds=5.0)


def test_every_tool_answering_with_cve_records_says_their_affected_entries_are_no_check() -> None:
    record_tool_names: list[str] = []
    unstated_tool_names: list[str] = []
    for tool_spec in KNOWLEDGE_TOOL_SPECS:
        response_schema = json.loads(render_schema(tool_spec.response_model, "serialization"))
        if "CveRecord" not in response_schema.get("$defs", {}):
            continue
        record_tool_names.append(tool_spec.name.value)
        if PUBLISHER_AFFECTED_STATEMENT not in tool_spec.description:
            unstated_tool_names.append(tool_spec.name.value)

    assert record_tool_names == [
        "lookup_cve",
        "search_vulnerabilities",
        "search_fight",
        "investigate_telecom_topic",
    ]
    assert unstated_tool_names == []
    for instructions in SERVER_INSTRUCTIONS.values():
        assert PUBLISHER_AFFECTED_STATEMENT in instructions
