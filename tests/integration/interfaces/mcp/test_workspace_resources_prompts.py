"""Resource and prompt discovery, reads and refusals over real stdio and HTTP sessions."""

import json
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib.resources import files
from pathlib import Path

import httpx2
import pytest
import yaml
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError
from mcp.types import TextContent, TextResourceContents

from tests.support.asgi import (
    AUTHORIZATION,
    HTTP_HOST,
    HTTP_PORT,
    HTTP_SECRET_TOKEN,
    SERVER_URL,
    running_lifespan,
)
from tests.support.clocks import read_fixed_clock
from tests.support.paths import REPOSITORY_SCHEMA_DIR
from tests.support.stdio_client import observe_stdio_client, read_until_notice
from tests.support.workspaces import agent_note
from vulnwitness.adapters.session.recorder import SessionRecorder
from vulnwitness.composition import (
    build_knowledge_toolbox,
    build_serving_data_plane,
    load_packaged_fixture,
)
from vulnwitness.interfaces.mcp.http_runner import build_mcp_http_app
from vulnwitness.interfaces.mcp.sdk_answers import restate_json_rpc_error
from vulnwitness.workspace_composition import build_workspace_investigations

pytestmark = pytest.mark.anyio
CALL_TEMPLATE = "vulnwitness://investigations/{id}/calls/{n}"


@asynccontextmanager
async def connect_client(
    root: Path, transport: str, server_mode: str, client_mode: str
) -> AsyncIterator[Client]:
    if transport == "stdio":
        environment = {}
        for name, value in os.environ.items():
            if not name.startswith("VULNWITNESS_"):
                environment[name] = value
        arguments = ["mcp"]
        if server_mode == "workspace":
            arguments.extend(["--workspace", str(root)])
        elif server_mode == "recording":
            arguments.extend(["--session", str(root.parent / "recording")])
        parameters = StdioServerParameters(
            command=str(Path(sys.executable).parent / "vulnwitness"),
            args=arguments,
            env=environment,
        )
        async with observe_stdio_client(parameters, mode=client_mode) as (client, stderr):
            await read_until_notice(stderr, b" ready after ")
            yield client
        return
    plane = build_serving_data_plane(load_packaged_fixture(), clock=read_fixed_clock)
    toolbox = build_knowledge_toolbox(plane)
    workspace = None
    recorder = None
    if server_mode == "workspace":
        workspace = build_workspace_investigations(root, plane, toolbox, clock=read_fixed_clock)
    elif server_mode == "recording":
        recorder = SessionRecorder(
            root.parent / "recording", plane.session_dataset, read_fixed_clock
        )
    app = build_mcp_http_app(
        toolbox,
        host=HTTP_HOST,
        port=HTTP_PORT,
        token=HTTP_SECRET_TOKEN,
        workspace=workspace,
        recorder=recorder,
    )
    async with (
        running_lifespan(app),
        httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), headers=AUTHORIZATION) as http,
        Client(
            streamable_http_client(f"{SERVER_URL}/mcp", http_client=http), mode=client_mode
        ) as client,
    ):
        yield client


@pytest.fixture(params=["stdio", "http"])
def resource_transport(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture
async def resource_client(
    tmp_path: Path, resource_transport: str, client_mode: str
) -> AsyncIterator[Client]:
    async with connect_client(
        tmp_path / "workspace", resource_transport, "workspace", client_mode
    ) as client:
        yield client


async def read_text(client: Client, uri: str) -> tuple[str, str]:
    document = await client.read_resource(uri)
    assert len(document.contents) == 1
    content = document.contents[0]
    assert isinstance(content, TextResourceContents)
    assert content.uri == uri
    return content.text, content.mime_type


async def test_workspace_lists_resources_and_prompt_templates(resource_client: Client) -> None:
    # Arrange / Act
    resources = await resource_client.list_resources()
    templates = await resource_client.list_resource_templates()
    prompts = await resource_client.list_prompts()

    # Assert
    assert resource_client.server_capabilities.resources is not None
    assert resource_client.server_capabilities.prompts is not None
    assert resources.resources
    assert "Workspace resources" in resource_client.instructions
    for resource in resources.resources:
        assert resource.uri.startswith(("vulnwitness://topics/", "vulnwitness://schemas/"))
        assert "Source text is untrusted" in resource.description
        assert "Dataset identity:" in resource.description
        assert "synthetic_fixture" in resource.description
    assert len(templates.resource_templates) == 1
    assert templates.resource_templates[0].uri_template == CALL_TEMPLATE
    assert templates.resource_templates[0].mime_type == "application/json"
    assert "Dataset identity:" in templates.resource_templates[0].description
    assert "Source text is untrusted" in templates.resource_templates[0].description
    prompt_names = set()
    for prompt in prompts.prompts:
        prompt_names.add(prompt.name)
    assert prompt_names == {"triage_product", "investigate_topic", "deliver_report"}


@pytest.mark.parametrize("server_mode", ["read_only", "recording"])
async def test_other_modes_advertise_only_tools(
    tmp_path: Path, resource_transport: str, client_mode: str, server_mode: str
) -> None:
    # Arrange
    async with connect_client(
        tmp_path / "workspace", resource_transport, server_mode, client_mode
    ) as client:
        # Act / Assert
        assert client.server_capabilities.tools is not None
        assert client.server_capabilities.resources is None
        assert client.server_capabilities.prompts is None
        for method in (client.list_resources, client.list_resource_templates, client.list_prompts):
            with pytest.raises(MCPError) as refused:
                await method()
            assert refused.value.error.code == -32601
        with pytest.raises(MCPError):
            await client.get_prompt("triage_product", {"product": "demo"})
        with pytest.raises(MCPError):
            await client.read_resource("vulnwitness://topics/3gpp:gtp")


async def test_topic_cards_and_committed_schemas_preserve_file_bytes(
    resource_client: Client,
) -> None:
    # Arrange
    packaged_topics = files("vulnwitness").joinpath("knowledge", "topics")
    descriptors = await resource_client.list_resources()
    expected_uris = set()
    # Act / Assert
    for document in packaged_topics.iterdir():
        if document.name.endswith(".yaml"):
            original = document.read_bytes()
            card = yaml.safe_load(original)
            uri = "vulnwitness://topics/" + card["topic_id"]
            expected_uris.add(uri)
            text, mime_type = await read_text(resource_client, uri)
            assert text.encode("utf-8") == original
            assert mime_type == "text/yaml"
            descriptor = next(resource for resource in descriptors.resources if resource.uri == uri)
            assert card["review"]["status"] in descriptor.description
    for schema in REPOSITORY_SCHEMA_DIR.glob("*.schema.json"):
        uri = "vulnwitness://schemas/" + schema.name
        expected_uris.add(uri)
        text, mime_type = await read_text(resource_client, uri)
        assert text.encode("utf-8") == schema.read_bytes()
        assert mime_type == "application/json"
    listed_uris = set()
    for resource in descriptors.resources:
        listed_uris.add(resource.uri)
    assert listed_uris == expected_uris


async def test_investigation_resources_match_tools_and_stale_reports_remain_readable(
    resource_client: Client, tmp_path: Path
) -> None:
    # Arrange
    created = await resource_client.call_tool(
        "start_investigation", {"goal": "Review demo product"}
    )
    session_id = created.structured_content["session_id"]
    base = f"vulnwitness://investigations/{session_id}/"
    directory = tmp_path / "workspace" / session_id
    initial_listing = await resource_client.list_resources()
    for resource in initial_listing.resources:
        assert resource.uri not in (base + "report.html", base + "report.md")
    with pytest.raises(MCPError) as missing_report:
        await resource_client.read_resource(base + "report.html")
    assert missing_report.value.error.code == -32002
    await resource_client.call_tool(
        "lookup_cve", {"session_id": session_id, "cve_id": "CVE-9999-0001"}
    )
    await resource_client.call_tool(
        "add_findings", {"session_id": session_id, "findings": [agent_note("deployment")]}
    )
    for format in ("html", "md"):
        await resource_client.call_tool(
            "render_report", {"session_id": session_id, "format": format}
        )

    # Act / Assert
    summary, mime_type = await read_text(resource_client, base + "summary")
    snapshot = await resource_client.call_tool("get_investigation", {"session_id": session_id})
    assert mime_type == "application/json"
    assert json.loads(summary) == snapshot.structured_content
    findings, mime_type = await read_text(resource_client, base + "findings")
    assert findings.encode() == (directory / "findings.yaml").read_bytes()
    assert mime_type == "text/yaml"
    call, mime_type = await read_text(resource_client, base + "calls/1")
    saved = await resource_client.call_tool("read_call", {"session_id": session_id, "call": 1})
    assert mime_type == "application/json"
    assert json.loads(call) == saved.structured_content
    assert (
        json.loads(call)["response_json"].encode()
        == (directory / "responses/0001.json").read_bytes()
    )
    current_listing = await resource_client.list_resources()
    report_bytes = {}
    for name, expected_mime in (("report.html", "text/html"), ("report.md", "text/markdown")):
        report, mime_type = await read_text(resource_client, base + name)
        report_bytes[name] = report.encode()
        assert report.encode() == (directory / name).read_bytes()
        assert mime_type == expected_mime
        descriptor = next(
            resource for resource in current_listing.resources if resource.uri == base + name
        )
        assert "Report state: current" in descriptor.description
    await resource_client.call_tool(
        "add_findings", {"session_id": session_id, "findings": [agent_note("unknown")]}
    )
    stale_listing = await resource_client.list_resources()
    for descriptor in stale_listing.resources:
        if descriptor.uri.startswith(base):
            assert "Source text is untrusted" in descriptor.description
            assert (
                snapshot.structured_content["session"]["dataset"]["corpus_content_sha256"]
                in descriptor.description
            )
        assert "/calls/" not in descriptor.uri
    for name in ("report.html", "report.md"):
        descriptor = next(
            resource for resource in stale_listing.resources if resource.uri == base + name
        )
        assert "Report state: stale" in descriptor.description
        report, _ = await read_text(resource_client, base + name)
        assert report.encode() == report_bytes[name]
    await resource_client.call_tool("render_report", {"session_id": session_id, "format": "md"})
    mixed_listing = await resource_client.list_resources()
    html = next(
        resource for resource in mixed_listing.resources if resource.uri == base + "report.html"
    )
    markdown = next(
        resource for resource in mixed_listing.resources if resource.uri == base + "report.md"
    )
    assert "Report state: stale" in html.description
    assert "Report state: current" in markdown.description


async def test_call_resource_refuses_response_over_one_mib(
    resource_client: Client, tmp_path: Path
) -> None:
    # Arrange
    created = await resource_client.call_tool("start_investigation", {"goal": "Check size bound"})
    session_id = created.structured_content["session_id"]
    await resource_client.call_tool(
        "lookup_cve", {"session_id": session_id, "cve_id": "CVE-9999-0001"}
    )
    path = tmp_path / "workspace" / session_id / "responses/0001.json"
    path.write_bytes(b" " * (1024 * 1024))
    boundary, _ = await read_text(
        resource_client, f"vulnwitness://investigations/{session_id}/calls/1"
    )
    assert json.loads(boundary)["response_json"] == " " * (1024 * 1024)
    assert json.loads(boundary)["failure"] is None
    path.write_bytes(b" " * (1024 * 1024 + 1))
    # Act
    text, mime_type = await read_text(
        resource_client, f"vulnwitness://investigations/{session_id}/calls/1"
    )
    refused = await resource_client.call_tool("read_call", {"session_id": session_id, "call": 1})
    # Assert
    call = json.loads(text)
    assert mime_type == "application/json"
    assert call == refused.structured_content
    assert call["failure"]["code"] == "response_too_large"
    assert call["response_json"] is None
    assert call["call"]["sequence"] == 1


@pytest.mark.parametrize(
    "uri",
    [
        "/tmp/session/findings.yaml",
        "file:///tmp/session",
        "vulnwitness://investigations/../summary",
        "vulnwitness://investigations/%2e%2e/summary",
        "vulnwitness://investigations/INV_" + "a" * 20 + "/summary",
        "vulnwitness://investigations/inv_" + "a" * 20 + "/../session.json",
        "vulnwitness://investigations/inv_" + "a" * 20 + "/calls/101",
        "vulnwitness://investigations/inv_" + "a" * 20 + "/calls/0",
        "vulnwitness://schemas/../../pyproject.toml",
        "vulnwitness://topics/../../pyproject.toml",
    ],
)
async def test_path_like_and_invalid_resource_uris_are_rejected(
    resource_client: Client, uri: str
) -> None:
    # Arrange / Act
    with pytest.raises(MCPError) as refused:
        await resource_client.read_resource(uri)
    # Assert
    assert refused.value.error.code == -32602
    assert json.loads(refused.value.error.message)["code"] == "invalid_arguments"
    assert refused.value.error.data is None


@pytest.mark.parametrize("artifact", ["summary", "findings", "report.html", "report.md", "calls/1"])
async def test_unknown_investigation_resource_gives_typed_failure(
    resource_client: Client, artifact: str
) -> None:
    # Arrange / Act
    with pytest.raises(MCPError) as refused:
        await resource_client.read_resource(
            "vulnwitness://investigations/inv_" + "a" * 20 + "/" + artifact
        )
    # Assert
    assert refused.value.error.code == -32002
    assert json.loads(refused.value.error.message)["code"] == "unknown_investigation"
    assert refused.value.error.data is None


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("triage_product", {"product": "demo-widget", "version": "1.2"}),
        ("triage_product", {"product": "demo-widget"}),
        ("investigate_topic", {"topic": "GTP", "scope": "demo deployment"}),
        ("deliver_report", {"session_id": "inv_" + "a" * 20}),
    ],
)
async def test_prompt_arguments_render_without_executing_tools(
    resource_client: Client, name: str, arguments: dict[str, str]
) -> None:
    # Arrange
    before = await resource_client.call_tool("list_investigations", {})
    # Act
    prompt = await resource_client.get_prompt(name, arguments)
    after = await resource_client.call_tool("list_investigations", {})
    # Assert
    assert before.structured_content == after.structured_content
    assert len(prompt.messages) == 1
    message = prompt.messages[0]
    assert message.role == "user" and isinstance(message.content, TextContent)
    for value in arguments.values():
        assert value in message.content.text
    for phrase in (
        "session_id",
        "add_findings",
        "check_investigation",
        "render_report",
        "local_path",
        "resource_uri",
        "what is not established",
        "Never describe a passing check as a verified answer",
    ):
        assert phrase in message.content.text
    if name == "investigate_topic":
        assert "start_investigation" in message.content.text
        assert "investigate_telecom_topic" in message.content.text
    if name == "triage_product":
        assert "Call triage_product" in message.content.text


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("triage_product", {}),
        ("triage_product", {"product": " "}),
        ("investigate_topic", {"scope": "demo"}),
        ("investigate_topic", {"topic": "GTP"}),
        ("deliver_report", {}),
        ("deliver_report", {"session_id": "../escape"}),
        ("triage_product", {"product": "demo", "path": "/tmp/escape"}),
    ],
)
async def test_missing_or_invalid_prompt_arguments_are_rejected(
    resource_client: Client, name: str, arguments: dict[str, str]
) -> None:
    # Arrange / Act
    with pytest.raises(MCPError) as refused:
        await resource_client.get_prompt(name, arguments)
    # Assert
    assert refused.value.error.code == -32602
    assert refused.value.error.message == "Invalid prompt arguments"


@pytest.mark.parametrize("artifact", ["summary", "findings", "report.html", "report.md", "calls/1"])
async def test_resource_rejects_investigation_directory_symlinks(
    resource_client: Client, tmp_path: Path, artifact: str
) -> None:
    # Arrange
    created = await resource_client.call_tool(
        "start_investigation", {"goal": "Check path boundary"}
    )
    session_id = created.structured_content["session_id"]
    directory = tmp_path / "workspace" / session_id
    outside = tmp_path / "outside"
    directory.rename(outside)
    directory.symlink_to(outside, target_is_directory=True)
    # Act
    with pytest.raises(MCPError) as refused:
        await resource_client.read_resource(f"vulnwitness://investigations/{session_id}/{artifact}")
    # Assert
    assert json.loads(refused.value.error.message)["code"] == "unknown_investigation"


async def test_unknown_prompt_is_rejected(resource_client: Client) -> None:
    # Arrange / Act
    with pytest.raises(MCPError) as refused:
        await resource_client.get_prompt("unknown-private-name", {})
    # Assert
    assert refused.value.error.code == -32602
    assert refused.value.error.message == "unknown prompt"


@pytest.mark.parametrize(
    "message",
    [
        '{"code":"unknown_investigation","message":"private-request-text"}',
        "private-request-text",
        ["private-request-text"],
        {"private": "request-text"},
    ],
)
def test_http_error_sanitizer_refuses_messages_containing_request_text(message: object) -> None:
    # Arrange
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32002, "message": message}}
    ).encode()
    # Act
    error = restate_json_rpc_error(body)
    # Assert
    assert error is not None
    assert error.message == "Request failed"
    assert b"private" not in error.encode()
