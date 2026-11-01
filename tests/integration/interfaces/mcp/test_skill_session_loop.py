"""The shipped findings template supports a checked MCP stdio investigation."""

import json
import os
import sys
from pathlib import Path

import pytest
import yaml
from mcp import StdioServerParameters

from tests.support.paths import REPOSITORY_ROOT
from tests.support.session_files import populate_product_findings
from tests.support.stdio_client import observe_stdio_client, read_until_notice
from vulnwitness.cli import main
from vulnwitness.domain.product_query import ProductQueryResponse
from vulnwitness.domain.search import SearchResponse
from vulnwitness.domain.session_record import SessionCall, SessionCheckReport


@pytest.mark.anyio
async def test_mcp_product_and_lookup_findings_pass_and_a_broken_citation_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    directory = tmp_path / "review"
    environment: dict[str, str] = {}
    for name, value in os.environ.items():
        if not name.startswith("VULNWITNESS_"):
            environment[name] = value
    server = StdioServerParameters(
        command=str(Path(sys.executable).parent / "vulnwitness"),
        args=["mcp", "--session", str(directory)],
        env=environment,
    )
    template = REPOSITORY_ROOT / "skills/vulnwitness-investigation/templates/findings.yaml"

    # Act
    async with observe_stdio_client(server) as (client, stderr):
        await read_until_notice(stderr, b" ready after ")
        product_answer = await client.call_tool(
            "query_product_vulnerabilities", {"vendor": "democorp", "version": "2.0", "limit": 1}
        )
        assert not product_answer.is_error
        page = ProductQueryResponse.model_validate(product_answer.structured_content)
        lookup_answer = await client.call_tool(
            "lookup_cve", {"cve_id": page.items[0].record.cve_id}
        )
        assert not lookup_answer.is_error
        lookup = SearchResponse.model_validate(lookup_answer.structured_content)
    product_call = SessionCall.model_validate_json((directory / "calls/0001.json").read_bytes())
    lookup_call = SessionCall.model_validate_json((directory / "calls/0002.json").read_bytes())
    findings = populate_product_findings(
        template, page, lookup, product_call.sequence, lookup_call.sequence
    )
    findings_path = directory / "findings.yaml"
    findings_path.write_text(yaml.safe_dump(findings), encoding="utf-8")
    valid_exit = main(["session", "check", str(directory)], environment={})
    valid_report = SessionCheckReport.model_validate_json(capsys.readouterr().out)
    findings["findings"][0]["citations"][0]["evidence_id"] = "ev:" + "0" * 24
    findings_path.write_text(yaml.safe_dump(findings), encoding="utf-8")
    invalid_exit = main(["session", "check", str(directory)], environment={})
    invalid_report = SessionCheckReport.model_validate_json(capsys.readouterr().out)

    # Assert
    assert page.items[0].record.cve_id.startswith("CVE-9999-")
    assert page.items[0].basis.kind == "product_field"
    assert page.next_cursor is not None
    assert not findings["selections"]["product_queries"][0]["complete"]
    for call, answer in ((product_call, product_answer), (lookup_call, lookup_answer)):
        assert call.interface == "mcp" and call.outcome == "ok"
        assert (
            json.loads((directory / call.response_file).read_bytes()) == answer.structured_content
        )
    assert product_call.command == "query_product_vulnerabilities"
    assert lookup_call.command == "lookup_cve"
    assert valid_exit == 0
    assert valid_report.record.consistent and valid_report.citations.resolved
    assert valid_report.claims.verified
    assert valid_report.record.calls_checked == valid_report.citations.citations_checked == 2
    assert invalid_exit == 1 and not invalid_report.citations.resolved
    assert invalid_report.record.consistent and invalid_report.claims.verified
    assert len(invalid_report.citations.violations) == 1
    assert (
        invalid_report.citations.violations[0].location == "findings.yaml.findings[0].citations[0]"
    )
