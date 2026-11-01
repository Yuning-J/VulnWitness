"""The shipped investigation instructions stay callable against the knowledge contract."""

import json
import re
import tomllib
from enum import StrEnum
from pathlib import Path
from typing import Any, get_args

import pytest
import yaml
from jsonschema import Draft202012Validator
from mcp import Client
from pydantic import BaseModel

from tests.support.paths import REPOSITORY_ROOT
from tests.support.workspaces import build_test_workspace
from vulnwitness.domain.affectedness import AffectednessFailure, ApplicabilityStatus
from vulnwitness.domain.investigation import NeedOutcome, StopReason
from vulnwitness.domain.nvd_version_note import NvdVersionHit, NvdVersionNoHit, NvdVersionUnknown
from vulnwitness.domain.product_query import DescriptionMentionBasis, ProductFieldBasis
from vulnwitness.domain.relevance import RelevanceLabel
from vulnwitness.domain.session_record import SessionFindings
from vulnwitness.domain.taxonomy import ResultStatus
from vulnwitness.domain.tool_contracts import ToolFailureCode
from vulnwitness.domain.topic import ReviewStatus
from vulnwitness.domain.topic_context import QueryScope
from vulnwitness.domain.weakness_associations import WeaknessAssociationPath
from vulnwitness.domain.workspace import ReportStatus, TriageOutcome, WorkflowStatus
from vulnwitness.domain.workspace_knowledge import WORKSPACE_KNOWLEDGE_MODELS
from vulnwitness.interfaces.knowledge_tools import KNOWLEDGE_TOOL_SPECS
from vulnwitness.interfaces.mcp.server import build_knowledge_mcp_server
from vulnwitness.interfaces.mcp.workspace_tools import WORKSPACE_TOOL_SPECS
from vulnwitness.schema_snapshots import REQUEST_CONTRACTS

SKILL_DIRECTORY = REPOSITORY_ROOT / "skills" / "vulnwitness-investigation"


def enum_values(enum_type: type[StrEnum]) -> set[str]:
    values: set[str] = set()
    for member in enum_type:
        values.add(member.value)
    return values


def documented_rows(document: str) -> dict[str, set[str]]:
    """Read the contract table that agents consume, without a second status manifest."""
    contract_section = document.split("### Wire values checked against the code\n", 1)[1]
    contract_section = contract_section.split("\n## ", 1)[0]
    values_by_contract: dict[str, set[str]] = {}
    for line in contract_section.splitlines():
        if not line.startswith("| "):
            continue
        columns = line.split("|")
        values = set(re.findall(r"`([^`]+)`", columns[2]))
        if values:
            values_by_contract[columns[1].strip()] = values
    return values_by_contract


def test_skill_tool_names_and_status_values_match_the_served_contract() -> None:
    # Arrange
    document = (SKILL_DIRECTORY / "SKILL.md").read_text()
    expected_contracts = {
        "Scope": enum_values(QueryScope),
        "Product basis": {
            *get_args(ProductFieldBasis.model_fields["kind"].annotation),
            *get_args(DescriptionMentionBasis.model_fields["kind"].annotation),
        },
        "Version outcome": {
            *get_args(NvdVersionHit.model_fields["outcome"].annotation),
            *get_args(NvdVersionUnknown.model_fields["outcome"].annotation),
            *get_args(NvdVersionNoHit.model_fields["outcome"].annotation),
        },
        "Applicability": enum_values(ApplicabilityStatus),
        "Need outcome": enum_values(NeedOutcome),
        "Relevance label": enum_values(RelevanceLabel),
        "Topic review": enum_values(ReviewStatus),
        "Result status": enum_values(ResultStatus),
        "Stop reason": enum_values(StopReason),
        "Tool failure": enum_values(ToolFailureCode),
        "Affectedness blocker": {AffectednessFailure.BLOCKED_UNVERIFIED.value},
        "Triage outcome": set(get_args(TriageOutcome)),
        "Workflow": set(get_args(WorkflowStatus)),
        "Report": set(get_args(ReportStatus)),
        "Catalogue terminal": set(
            get_args(
                get_args(WeaknessAssociationPath.model_fields["terminal_reason"].annotation)[0]
            )
        ),
    }
    requests = workspace_request_models()

    # Act
    tool_section = document.split("## Tools and request arguments\n", 1)[1].split("\n## ", 1)[0]
    documented_tools = set(re.findall(r"^\|[^\n|]+\| `([a-z_]+)` \|", tool_section, re.MULTILINE))
    documented_contracts = documented_rows(document)

    # Assert
    assert documented_tools == set(requests)
    assert documented_contracts == expected_contracts


def workspace_request_models() -> dict[str, type[BaseModel]]:
    requests: dict[str, type[BaseModel]] = {}
    for specification in KNOWLEDGE_TOOL_SPECS:
        requests[specification.name.value] = WORKSPACE_KNOWLEDGE_MODELS[specification.request_model]
    for workspace_specification in WORKSPACE_TOOL_SPECS:
        requests[workspace_specification.name] = workspace_specification.request_model
    return requests


def published_request_schema(model: type[BaseModel]) -> dict[str, Any]:
    for name, request_model in REQUEST_CONTRACTS.items():
        if request_model is model:
            return json.loads(
                (REPOSITORY_ROOT / "schemas" / "v2" / f"{name}.schema.json").read_text()
            )
    raise AssertionError(f"No published request schema for {model.__name__}")


def documented_flows() -> list[Path]:
    documents = [SKILL_DIRECTORY / "SKILL.md"]
    documents.extend(sorted((SKILL_DIRECTORY / "templates").glob("*.md")))
    return documents


def schema_terms(node: Any) -> set[str]:
    terms: set[str] = set()
    if isinstance(node, dict):
        terms.update(node.get("properties", {}))
        for value in node.get("enum", []):
            if isinstance(value, str):
                terms.add(value)
        if isinstance(node.get("const"), str):
            terms.add(node["const"])
        for child in node.values():
            terms.update(schema_terms(child))
    elif isinstance(node, list):
        for child in node:
            terms.update(schema_terms(child))
    return terms


def test_documented_tool_arguments_exist_on_each_workspace_request() -> None:
    # Arrange
    document = (SKILL_DIRECTORY / "SKILL.md").read_text()
    requests = workspace_request_models()
    rows = re.findall(r"^\|[^\n|]+\| `([a-z_]+)` \|([^\n]+)\|", document, re.MULTILINE)

    # Act
    arguments_by_tool: dict[str, set[str]] = {}
    for tool, argument_column in rows:
        arguments_by_tool[tool] = set(re.findall(r"`([a-z_]+)`", argument_column))

    # Assert
    assert len(rows) == len(requests)
    for tool, arguments in arguments_by_tool.items():
        assert arguments <= set(published_request_schema(requests[tool])["properties"]), tool


@pytest.mark.parametrize("document", documented_flows())
def test_worked_flow_calls_validate_against_published_workspace_schemas(document: Path) -> None:
    # Arrange
    requests = workspace_request_models()
    call_examples = re.findall(r"```json\n(.*?)\n *```", document.read_text(), re.DOTALL)

    # Act
    for example in call_examples:
        call = json.loads(example)
        request_model = requests[call["tool"]]
        Draft202012Validator(published_request_schema(request_model)).validate(call["arguments"])
        request_model.model_validate(call["arguments"])

    # Assert
    assert call_examples or document.name == "SKILL.md"


@pytest.mark.parametrize("document", documented_flows())
def test_documented_identifiers_failures_and_outcomes_exist_in_the_contract(document: Path) -> None:
    # Arrange
    known_terms = set(workspace_request_models())
    for schema_path in (REPOSITORY_ROOT / "schemas" / "v2").glob("*.schema.json"):
        known_terms.update(schema_terms(json.loads(schema_path.read_text())))
    # Prompts and resource addresses are a separate workspace surface from tools.
    instructions = re.sub(
        r"Resources and prompts are available.*?(?=\nShell users)",
        "",
        document.read_text(),
        flags=re.DOTALL,
    )

    # Act
    identifiers = set(re.findall(r"`([a-z][a-z_]+)`", instructions))

    # Assert
    assert identifiers <= known_terms, identifiers - known_terms


@pytest.mark.parametrize(
    "relative_path", ["templates/findings.yaml", "examples/findings.example.yaml"]
)
def test_authored_findings_files_validate_against_the_session_contract(relative_path: str) -> None:
    # Arrange
    schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "v2" / "session_findings.schema.json").read_text()
    )
    authored_findings = yaml.safe_load((SKILL_DIRECTORY / relative_path).read_text())

    # Act
    Draft202012Validator(schema).validate(authored_findings)
    findings = SessionFindings.model_validate(authored_findings)

    # Assert
    assert findings.findings


@pytest.mark.parametrize("client", ["claude-code", "codex", "cursor"])
def test_client_snippets_parse_and_select_the_packaged_demo(client: str) -> None:
    # Arrange
    document = (SKILL_DIRECTORY / "mcp-config" / f"{client}.md").read_text()
    snippets = re.findall(r"```(?:json|toml)\n(.*?)\n```", document, re.DOTALL)

    # Act
    server_entries: list[dict[str, Any]] = []
    for snippet in snippets:
        if client == "codex":
            server = tomllib.loads(snippet)["mcp_servers"]["vulnwitness"]
        else:
            server = json.loads(snippet)["mcpServers"]["vulnwitness"]
        server_entries.append(server)

    # Assert
    assert len(server_entries) == 3
    assert server_entries[0]["args"] == ["mcp"]
    assert server_entries[1]["args"] == ["mcp", "--session", "/absolute/path/to/session"]
    assert server_entries[2]["args"] == [
        "mcp",
        "--workspace",
        "/absolute/path/to/.vulnwitness/workspace",
    ]
    assert "not yet tested inside the clients" in document
    for server in server_entries:
        assert server["command"] == "vulnwitness"
        assert server["env"]["VULNWITNESS_STORE_ROOT"] == ""
        assert server["env"]["VULNWITNESS_MITRE_SNAPSHOT_PATH"] == ""
        assert server["env"]["VULNWITNESS_MITRE_SNAPSHOT_SHA256"] == ""
        assert server["env"]["VULNWITNESS_FIGHT_SNAPSHOT_PATH"] == ""
        assert server["env"]["VULNWITNESS_FIGHT_SNAPSHOT_SHA256"] == ""
        assert server["env"]["VULNWITNESS_PLANNER_ENABLED"] == "false"
        assert server["env"]["VULNWITNESS_SEMANTIC_ENABLED"] == "false"


def test_add_findings_request_example_validates_and_matches_the_authored_file() -> None:
    # Arrange
    request_model = workspace_request_models()["add_findings"]
    request = json.loads(
        (SKILL_DIRECTORY / "examples" / "add_findings.request.example.json").read_text()
    )
    authored_findings = yaml.safe_load(
        (SKILL_DIRECTORY / "examples" / "findings.example.yaml").read_text()
    )

    # Act
    Draft202012Validator(published_request_schema(request_model)).validate(request)
    accepted = request_model.model_validate(request)

    # Assert
    assert accepted.findings
    assert request["findings"] == authored_findings["findings"]


@pytest.mark.anyio
async def test_example_findings_resolve_and_check_against_recorded_packaged_demo(
    tmp_path: Path,
) -> None:
    # Arrange
    request = json.loads(
        (SKILL_DIRECTORY / "examples" / "add_findings.request.example.json").read_text()
    )
    toolbox, workspace = build_test_workspace(tmp_path / "workspace")
    async with Client(build_knowledge_mcp_server(toolbox, workspace=workspace)) as client:
        # Act
        triage = await client.call_tool(
            "triage_product",
            {
                "vendor": "democorp",
                "version": "2.0",
                "lookups": 1,
                "request_key": "packaged-example",
            },
        )
        request["session_id"] = triage.structured_content["session_id"]
        saved = await client.call_tool(
            "read_call", {"session_id": request["session_id"], "call": 2}
        )
        page = json.loads(saved.structured_content["response_json"])
        added = await client.call_tool("add_findings", request)
        retried = await client.call_tool("add_findings", request)
        checked = await client.call_tool(
            "check_investigation", {"session_id": request["session_id"]}
        )
        rendered = await client.call_tool(
            "render_report", {"session_id": request["session_id"], "format": "md"}
        )

    # Assert
    assert not triage.is_error and triage.structured_content["outcome"] == "complete"
    assert page["items"][0]["record"]["cve_id"] == request["findings"][0]["claim"]["cve_id"]
    anchors: set[str] = set()
    for anchor in page["evidence"]:
        anchors.add(anchor["evidence_id"])
    for finding in request["findings"]:
        for citation in finding["citations"]:
            assert citation["call"] == saved.structured_content["call"]["sequence"]
            assert citation["evidence_id"] in anchors
    assert not added.is_error and added.structured_content["written"]
    assert not retried.is_error and not retried.structured_content["written"]
    assert checked.structured_content["record"]["consistent"]
    assert checked.structured_content["citations"]["resolved"]
    assert checked.structured_content["claims"]["verified"]
    assert "demo-component-review" in checked.structured_content["not_checked"]["finding_ids"]
    assert rendered.structured_content["report"] == "current"
    assert (
        Path(rendered.structured_content["local_path"]).read_text()
        == (rendered.structured_content["markdown"])
    )


@pytest.mark.anyio
async def test_topic_template_records_the_demo_need_statuses_and_renders(tmp_path: Path) -> None:
    # Arrange
    template = (SKILL_DIRECTORY / "templates" / "gtp-mixed-investigation.md").read_text()
    calls = re.findall(r"```json\n(.*?)\n *```", template, re.DOTALL)
    toolbox, workspace = build_test_workspace(tmp_path / "workspace")
    session_id = None
    answers: dict[str, Any] = {}

    # Act
    async with Client(build_knowledge_mcp_server(toolbox, workspace=workspace)) as client:
        for example in calls:
            call = json.loads(example)
            if "session_id" in call["arguments"]:
                call["arguments"]["session_id"] = session_id
            answer = await client.call_tool(call["tool"], call["arguments"])
            assert not answer.is_error, answer.structured_content
            answers[call["tool"]] = answer.structured_content
            if call["tool"] == "start_investigation":
                session_id = answer.structured_content["session_id"]

    # Assert
    checked = answers["check_investigation"]
    assert checked["record"]["consistent"] and checked["citations"]["resolved"]
    assert checked["claims"]["verified"]
    assert len(checked["claims"]["checks"]) == 2
    assert answers["render_report"]["report"] == "current"
