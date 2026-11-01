"""Recorded Streamable HTTP calls use the same session format as CLI and stdio."""

import json
from pathlib import Path

import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from cve_kgrag.adapters.session.check import SessionChecker
from cve_kgrag.adapters.session.recorder import SessionRecorder
from cve_kgrag.composition import (
    build_knowledge_toolbox,
    build_serving_data_plane,
    load_packaged_fixture,
)
from cve_kgrag.interfaces.mcp.http_runner import build_mcp_http_app
from tests.support.asgi import (
    AUTHORIZATION,
    HTTP_HOST,
    HTTP_PORT,
    HTTP_SECRET_TOKEN,
    SERVER_URL,
    running_lifespan,
)
from tests.support.clocks import read_fixed_clock
from tests.support.session_files import write_findings

pytestmark = pytest.mark.anyio


async def test_http_calls_record_normalized_requests_and_typed_failures(tmp_path: Path) -> None:
    # Arrange
    plane = build_serving_data_plane(load_packaged_fixture(), clock=read_fixed_clock)
    assert plane.session_dataset is not None
    directory = tmp_path / "review"
    app = build_mcp_http_app(
        build_knowledge_toolbox(plane),
        host=HTTP_HOST,
        port=HTTP_PORT,
        token=HTTP_SECRET_TOKEN,
        recorder=SessionRecorder(directory, plane.session_dataset, read_fixed_clock),
    )
    # Act
    async with (
        running_lifespan(app),
        httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), headers=AUTHORIZATION) as http,
        Client(streamable_http_client(f"{SERVER_URL}/mcp", http_client=http)) as client,
    ):
        answer = await client.call_tool("lookup_cve", {"cve_id": "CVE-9999-0001"})
        invalid = await client.call_tool("lookup_cve", {"cve_id": "invalid"})
        unknown = await client.call_tool("unknown_tool", {})
    write_findings(directory, [])
    # Assert
    assert not answer.is_error and invalid.is_error and unknown.is_error
    assert json.loads((directory / "responses/0001.json").read_bytes()) == answer.structured_content
    assert json.loads((directory / "calls/0002.json").read_bytes())["request"] is None
    assert (
        json.loads((directory / "calls/0003.json").read_bytes())["outcome"] == "invalid_arguments"
    )
    assert SessionChecker(directory).check().passed
