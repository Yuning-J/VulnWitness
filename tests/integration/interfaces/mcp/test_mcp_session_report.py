"""A report consumes an actual MCP recording without a triage workflow."""

import json
import os
import sys
from pathlib import Path

import pytest
from mcp import StdioServerParameters

from tests.support.session_files import write_findings
from tests.support.stdio_client import observe_stdio_client, read_until_notice
from vulnwitness.cli import main


@pytest.mark.anyio
async def test_mcp_lookup_report_retains_source_uri_and_catalogue_hops(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    directory = tmp_path / "mcp-review"
    environment: dict[str, str] = {}
    for name, value in os.environ.items():
        if not name.startswith("VULNWITNESS_"):
            environment[name] = value
    server = StdioServerParameters(
        command=str(Path(sys.executable).parent / "vulnwitness"),
        args=["mcp", "--session", str(directory)],
        env=environment,
    )
    async with observe_stdio_client(server) as (client, stderr):
        await read_until_notice(stderr, b" ready after ")
        await client.call_tool("lookup_cve", {"cve_id": "CVE-9999-0002"})
    lookup = json.loads((directory / "responses/0001.json").read_bytes())
    anchor = lookup["evidence"][0]
    write_findings(directory, [{"call": 1, "evidence_id": anchor["evidence_id"]}])

    # Act
    exit_code = main(["report", str(directory), "--format", "html"], environment={})
    document = capsys.readouterr().out

    # Assert
    assert exit_code == 0
    assert "mcp: lookup_cve" in document
    assert "CVE-9999-0002" in document
    assert anchor["source_uri"] in document
    assert "<li>CVE-9999-0002 → CWE-79 [nvd_cwe]" in document
    assert "capec_child_of" in document
