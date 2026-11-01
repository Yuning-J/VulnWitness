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

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.domain.affectedness import AffectednessFailure, ApplicabilityStatus
from cve_kgrag.domain.investigation import NeedOutcome, StopReason
from cve_kgrag.domain.nvd_version_note import NvdVersionHit, NvdVersionNoHit, NvdVersionUnknown
from cve_kgrag.domain.product_query import DescriptionMentionBasis, ProductFieldBasis
from cve_kgrag.domain.relevance import RelevanceLabel
from cve_kgrag.domain.session_contracts import CLI_SESSION_CONTRACTS
from cve_kgrag.domain.session_record import SessionFindings
from cve_kgrag.domain.taxonomy import ResultStatus
from cve_kgrag.domain.tool_contracts import ToolFailureCode
from cve_kgrag.domain.topic import ReviewStatus
from cve_kgrag.domain.topic_context import QueryScope
from cve_kgrag.domain.weakness_associations import WeaknessAssociationPath
from cve_kgrag.interfaces.knowledge_tools import KNOWLEDGE_TOOL_SPECS, KnowledgeToolName
from tests.support.paths import REPOSITORY_ROOT
from tests.support.toolbox import build_test_toolbox, require_answer

SKILL_DIRECTORY = REPOSITORY_ROOT / "skills" / "cve-kgrag-investigation"


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
        "Catalogue terminal": set(
            get_args(
                get_args(WeaknessAssociationPath.model_fields["terminal_reason"].annotation)[0]
            )
        ),
    }
    tool_names: set[str] = set()
    for member in KnowledgeToolName:
        tool_names.add(member.value)

    # Act
    tool_section = document.split("## Choose the next tool\n", 1)[1].split("\n## ", 1)[0]
    documented_tools = set(re.findall(r"^\|[^\n|]+\| `([a-z_]+)` \|", tool_section, re.MULTILINE))
    documented_contracts = documented_rows(document)

    # Assert
    assert documented_tools == tool_names
    assert documented_contracts == expected_contracts


@pytest.mark.parametrize("template", sorted((SKILL_DIRECTORY / "templates").glob("*.md")))
def test_worked_flow_calls_are_accepted_by_the_listed_tool_schemas(template: Path) -> None:
    # Arrange
    requests: dict[str, Any] = {}
    for specification in KNOWLEDGE_TOOL_SPECS:
        requests[specification.name.value] = specification.request_model
    call_examples = re.findall(r"```json\n(.*?)\n *```", template.read_text(), re.DOTALL)

    # Act
    accepted_calls: list[str] = []
    for example in call_examples:
        call = json.loads(example)
        requests[call["tool"]].model_validate(call["arguments"])
        accepted_calls.append(call["tool"])

    # Assert
    assert len(accepted_calls) == len(call_examples) > 0


def test_skill_session_fields_and_values_exist_in_the_published_schemas() -> None:
    # Arrange
    document = (SKILL_DIRECTORY / "SKILL.md").read_text()
    session_section = document.split("## Session record contract — alignment point\n", 1)[1]
    session_section = session_section.split("\n## ", 1)[0]
    schemas: list[dict[str, Any]] = []
    for name in ("session_record", "session_call", "session_findings", "session_check_report"):
        schemas.append(
            json.loads((REPOSITORY_ROOT / "schemas" / "v2" / f"{name}.schema.json").read_text())
        )
    fields: set[str] = set()
    values: set[str] = {"ok"}
    for schema in schemas:
        for model in [schema, *schema.get("$defs", {}).values()]:
            fields.update(model.get("properties", {}))
            for property_schema in model.get("properties", {}).values():
                values.update(property_schema.get("enum", []))
    values.update(enum_values(ToolFailureCode))
    values.update(CLI_SESSION_CONTRACTS)

    # Act
    documented_names = set(re.findall(r"`([a-z_]+)`", session_section))

    # Assert
    assert documented_names <= fields | values
    findings_schema = schemas[2]
    for model_name in ("SessionFinding", "SessionSelections", "ProductPaginationProgress"):
        assert set(findings_schema["$defs"][model_name]["properties"]) <= documented_names
    assert set(findings_schema["properties"]) <= documented_names
    citation_example = re.search(r"`\{call: .*?\}`", session_section)
    assert citation_example is not None
    citation_fields = set(re.findall(r"([a-z_]+):", citation_example.group()))
    assert citation_fields == set(findings_schema["$defs"]["SessionCitation"]["properties"])


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
            server = tomllib.loads(snippet)["mcp_servers"]["cve-kgrag"]
        else:
            server = json.loads(snippet)["mcpServers"]["cve-kgrag"]
        server_entries.append(server)

    # Assert
    assert len(server_entries) == 2
    assert server_entries[0]["args"] == ["mcp"]
    assert server_entries[1]["args"] == ["mcp", "--session", "/absolute/path/to/session"]
    for server in server_entries:
        assert server["command"] == "cve-kgrag"
        assert server["env"]["CVE_KGRAG_STORE_ROOT"] == ""
        assert server["env"]["CVE_KGRAG_MITRE_SNAPSHOT_PATH"] == ""
        assert server["env"]["CVE_KGRAG_MITRE_SNAPSHOT_SHA256"] == ""
        assert server["env"]["CVE_KGRAG_FIGHT_SNAPSHOT_PATH"] == ""
        assert server["env"]["CVE_KGRAG_FIGHT_SNAPSHOT_SHA256"] == ""
        assert server["env"]["CVE_KGRAG_PLANNER_ENABLED"] == "false"
        assert server["env"]["CVE_KGRAG_SEMANTIC_ENABLED"] == "false"


def test_example_citations_resolve_in_the_corresponding_fixture_call(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange
    example = yaml.safe_load((SKILL_DIRECTORY / "examples" / "findings.example.yaml").read_text())
    toolbox = build_test_toolbox(fixture_bundle)
    arguments: dict[str, Any] = {"vendor": "democorp", "version": "2.0", "limit": 1}
    anchors_by_call: dict[int, set[str]] = {}
    record_ids: list[str] = []

    # Act
    for sequence in (1, 2, 3):
        page = require_answer(
            toolbox.call(KnowledgeToolName.QUERY_PRODUCT_VULNERABILITIES, arguments)
        ).structured_content
        anchors_by_call[sequence] = set()
        for anchor in page["evidence"]:
            anchors_by_call[sequence].add(anchor["evidence_id"])
        for item in page["items"]:
            record_ids.append(item["record"]["cve_id"])
        arguments["cursor"] = page["next_cursor"]
    lookup = require_answer(
        toolbox.call(KnowledgeToolName.LOOKUP_CVE, {"cve_id": record_ids[0]})
    ).structured_content
    anchors_by_call[4] = set()
    for anchor in lookup["evidence"]:
        anchors_by_call[4].add(anchor["evidence_id"])

    # Assert
    assert arguments["cursor"] is None
    assert len(record_ids) == page["total_available"] == 3
    assert record_ids[0] == example["selections"]["cve_ids"][0]
    for finding in example["findings"]:
        assert finding["citations"]
        for citation in finding["citations"]:
            assert citation["evidence_id"] in anchors_by_call[citation["call"]]
