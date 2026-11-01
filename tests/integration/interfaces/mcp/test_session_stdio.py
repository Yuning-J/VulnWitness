"""An MCP stdio session records tool answers and refuses calls over its limit."""

import json
import os
import sys
from pathlib import Path

import pytest
from mcp import StdioServerParameters

from tests.support.session_files import assert_check_layers_hold, write_findings
from tests.support.stdio_client import observe_stdio_client, read_until_notice
from vulnwitness.adapters.session.check import SessionChecker

UNKNOWN_ANCHOR = "ev:" + "0" * 24


@pytest.mark.anyio
async def test_mcp_stdio_records_success_failures_and_refuses_calls_over_the_limit(
    tmp_path: Path,
) -> None:
    # Arrange
    directory = tmp_path / "review"
    environment: dict[str, str] = {}
    for name, value in os.environ.items():
        if not name.startswith("VULNWITNESS_"):
            environment[name] = value
    server = StdioServerParameters(
        command=str(Path(sys.executable).parent / "vulnwitness"),
        args=["mcp", "--session", str(directory), "--session-call-limit", "2"],
        env=environment,
    )
    # Act
    async with observe_stdio_client(server) as (client, stderr):
        await read_until_notice(stderr, b" ready after ")
        lookup = await client.call_tool("lookup_cve", {"cve_id": "CVE-9999-0001"})
        failure = await client.call_tool("get_evidence", {"evidence_id": UNKNOWN_ANCHOR})
        refused = await client.call_tool("lookup_cve", {"cve_id": "CVE-9999-0002"})
    # Assert
    assert not lookup.is_error
    assert failure.is_error and refused.is_error
    assert json.loads((directory / "responses/0001.json").read_bytes()) == lookup.structured_content
    assert (directory / "responses/0001.json").read_text() == lookup.content[0].text
    assert (
        json.loads((directory / "responses/0002.json").read_bytes()) == failure.structured_content
    )
    assert json.loads(failure.content[0].text)["code"] == "unknown_evidence_id"
    assert json.loads(refused.content[0].text)["code"] == "session_call_limit"
    assert len(list((directory / "calls").iterdir())) == 2
    write_findings(directory, [])
    assert_check_layers_hold(SessionChecker(directory).check())
