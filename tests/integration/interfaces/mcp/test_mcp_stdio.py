"""``vulnwitness mcp`` serves the knowledge tools over stdio through the ``mcp_server`` entry
point, with nothing but the protocol on stdout."""

import json
import os
import signal
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import anyio
import pytest
from mcp import StdioServerParameters
from mcp.shared.exceptions import MCPError
from mcp.types import LATEST_PROTOCOL_VERSION, TextResourceContents

from tests.support.corpus_stores import import_store
from tests.support.stdio_client import observe_stdio_client, read_process_line, read_until_notice
from tests.support.toolbox import (
    BLOCKED_AFFECTEDNESS_CAPABILITY,
    TOOL_ARGUMENTS,
    list_affectedness_capabilities,
)
from vulnwitness.cli import main
from vulnwitness.domain.investigation import SourceCapabilityState
from vulnwitness.domain.tool_contracts import KnowledgeCapabilities, ToolFailure, ToolFailureCode
from vulnwitness.interfaces.knowledge_tools import KnowledgeToolName
from vulnwitness.interfaces.mcp.workspace_tools import WORKSPACE_TOOL_SPECS

pytestmark = pytest.mark.anyio

# The console script of the environment running the tests.
VULNWITNESS_SCRIPT = Path(sys.executable).parent / "vulnwitness"
# The prefix of every setting the server reads (vulnwitness.settings).
SETTINGS_PREFIX = "VULNWITNESS_"


def build_server_environment() -> dict[str, str]:
    """The test process's environment without any vulnwitness setting, so the server runs on
    its defaults whatever the shell running the tests exports."""
    server_environment: dict[str, str] = {}
    for variable_name, value in os.environ.items():
        if not variable_name.startswith(SETTINGS_PREFIX):
            server_environment[variable_name] = value
    return server_environment


# The initialize request a raw stdio client sends first.
INITIALIZE_FRAME = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": LATEST_PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "raw-stdio-test", "version": "1"},
    },
}

# Frames the SDK's stdio transport cannot decode: malformed JSON, a truncated request, and
# a request whose arguments nest deeper than the SDK's JSON parser goes.
UNDECODABLE_FRAMES = (
    "{not json",
    '{"jsonrpc":"2.0","id":3,"method":"tools/ca',
    '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_evidence",'
    '"arguments":{"evidence_id":' + "[" * 300 + "]" * 300 + "}}}",
)


async def test_vulnwitness_mcp_over_stdio_lists_tools_and_answers_capabilities() -> None:
    server_parameters = StdioServerParameters(
        command=str(VULNWITNESS_SCRIPT), args=["mcp"], env=build_server_environment()
    )

    async with observe_stdio_client(server_parameters) as (client, stderr):
        await read_until_notice(stderr, b" ready after ")
        tool_listing = await client.list_tools()
        capabilities_answer = await client.call_tool(
            KnowledgeToolName.GET_KNOWLEDGE_CAPABILITIES.value,
            TOOL_ARGUMENTS[KnowledgeToolName.GET_KNOWLEDGE_CAPABILITIES],
        )

    tool_names: list[str] = []
    for tool in tool_listing.tools:
        tool_names.append(tool.name)
    assert tool_names == list(KnowledgeToolName)
    assert capabilities_answer.is_error is False
    assert list_affectedness_capabilities(capabilities_answer.structured_content) == [
        BLOCKED_AFFECTEDNESS_CAPABILITY
    ]


def test_vulnwitness_mcp_with_stdin_closed_exits_zero_and_writes_nothing() -> None:
    """Nothing reaches stdout outside the protocol: no banner, no stdout log handler."""
    server_process = subprocess.run(
        [str(VULNWITNESS_SCRIPT), "mcp"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=60,
        check=False,
        env=build_server_environment(),
    )

    assert server_process.returncode == 0
    assert server_process.stdout == b""
    assert server_process.stderr == b""


def test_undecodable_frames_get_no_reply_and_later_requests_are_answered() -> None:
    """The SDK drops a frame it cannot decode without a JSON-RPC error or a word on stderr
    (ADR 0003 §7); the server keeps answering."""
    frames = [
        json.dumps(INITIALIZE_FRAME),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        *UNDECODABLE_FRAMES,
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ]

    server_process = subprocess.run(
        [str(VULNWITNESS_SCRIPT), "mcp"],
        input=("\n".join(frames) + "\n").encode(),
        capture_output=True,
        timeout=60,
        check=False,
        env=build_server_environment(),
    )

    answered_ids: list[object] = []
    for message_line in server_process.stdout.decode().splitlines():
        answered_ids.append(json.loads(message_line).get("id"))
    assert server_process.returncode == 0
    assert answered_ids == [1, 2]
    assert server_process.stderr == b""


@pytest.mark.parametrize("request_id", [2, "02"])
def test_cancelled_requests_do_not_keep_the_server_alive_after_stdin_closes(
    request_id: int | str,
) -> None:
    frames = [
        INITIALIZE_FRAME,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": request_id},
        },
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
    ]

    server_process = subprocess.run(
        [str(VULNWITNESS_SCRIPT), "mcp"],
        input=("\n".join(json.dumps(frame) for frame in frames) + "\n").encode(),
        capture_output=True,
        timeout=5,
        check=False,
        env=build_server_environment(),
    )

    answers_by_id = {}
    for line in server_process.stdout.splitlines():
        answer = json.loads(line)
        answers_by_id[answer["id"]] = answer
    assert server_process.returncode == 0
    assert 1 in answers_by_id
    assert "tools" in answers_by_id[3]["result"]
    # The cancellation may reach a request that has already been answered.
    assert set(answers_by_id) <= {1, 2, 3}


def test_json_rpc_errors_carry_no_data_and_repeat_nothing_sent() -> None:
    """A JSON-RPC error carries its code and fixed message, never ``data``, where the SDK
    would put the method name the client sent, or an empty string for parameters that
    fail its request model."""
    marked_method = "zzechomarkerzz/list"
    frames = [
        json.dumps(INITIALIZE_FRAME),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": marked_method}),
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": 5, "arguments": marked_method},
            }
        ),
    ]

    server_process = subprocess.Popen(
        [str(VULNWITNESS_SCRIPT), "mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=build_server_environment(),
    )
    assert server_process.stdin is not None and server_process.stdout is not None
    server_process.stdin.write(("\n".join(frames) + "\n").encode())
    server_process.stdin.flush()
    # Keep stdin open while this client consumes its three replies.
    initialize_answer = server_process.stdout.readline()
    unknown_method_answer = server_process.stdout.readline()
    invalid_params_answer = server_process.stdout.readline()
    server_process.stdin.close()
    server_process.wait(timeout=60)

    assert json.loads(initialize_answer)["id"] == 1
    assert json.loads(unknown_method_answer) == {
        "jsonrpc": "2.0",
        "id": 2,
        "error": {"code": -32601, "message": "Method not found"},
    }
    assert json.loads(invalid_params_answer) == {
        "jsonrpc": "2.0",
        "id": 3,
        "error": {"code": -32602, "message": "Invalid request parameters"},
    }
    assert marked_method.encode() not in unknown_method_answer + invalid_params_answer


async def test_vulnwitness_mcp_never_serves_the_semantic_channel_whatever_the_settings(
    tmp_path: Path,
) -> None:
    """The tools are read-only and the semantic store cannot be opened read-only, so the
    server loads no semantic adapter even when the settings enable one."""
    server_environment = {
        **build_server_environment(),
        "VULNWITNESS_SEMANTIC_ENABLED": "true",
        "VULNWITNESS_SEMANTIC_PERSIST_DIRECTORY": str(tmp_path / "vectors"),
    }
    server_parameters = StdioServerParameters(
        command=str(VULNWITNESS_SCRIPT), args=["mcp"], env=server_environment
    )

    async with observe_stdio_client(server_parameters) as (client, stderr):
        await read_until_notice(stderr, b" ready after ")
        capabilities_answer = await client.call_tool(
            KnowledgeToolName.GET_KNOWLEDGE_CAPABILITIES.value,
            TOOL_ARGUMENTS[KnowledgeToolName.GET_KNOWLEDGE_CAPABILITIES],
        )

    capabilities = KnowledgeCapabilities.model_validate(capabilities_answer.structured_content)
    semantic_capability = capabilities.source_capabilities[3]
    assert semantic_capability.source == "semantic_channel"
    assert semantic_capability.state is SourceCapabilityState.NOT_CONFIGURED
    assert semantic_capability.detail is None
    assert not (tmp_path / "vectors").exists()


def test_vulnwitness_mcp_over_a_store_announces_loading_on_stderr_and_keeps_stdout_protocol_only(
    tmp_path: Path,
) -> None:
    store_root = tmp_path / "stores"
    store_root.mkdir()
    import_store(store_root, "first")
    root_settings = {"VULNWITNESS_STORE_ROOT": str(store_root)}
    assert main(["store", "activate", "first"], root_settings) == 0
    frames = [
        json.dumps(INITIALIZE_FRAME),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ]

    server_process = subprocess.Popen(
        [str(VULNWITNESS_SCRIPT), "mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**build_server_environment(), **root_settings},
    )
    assert server_process.stdin is not None
    assert server_process.stdout is not None
    server_process.stdin.write(("\n".join(frames) + "\n").encode())
    server_process.stdin.flush()
    # Keep the client connected through the loading and readiness notices.
    answer_lines = [server_process.stdout.readline(), server_process.stdout.readline()]
    assert server_process.stderr is not None
    notice_lines: list[str] = []
    while not notice_lines or " ready after " not in notice_lines[-1]:
        notice_lines.append(read_process_line(server_process.stderr).decode().rstrip())
    trailing_stdout, stderr_bytes = server_process.communicate(timeout=60)

    answered_ids: list[object] = []
    for answer_line in answer_lines:
        message = json.loads(answer_line)
        assert message["jsonrpc"] == "2.0"
        answered_ids.append(message["id"])
    assert stderr_bytes == b""
    assert server_process.returncode == 0
    assert answered_ids == [1, 2]
    assert trailing_stdout == b""
    assert notice_lines[0] == "vulnwitness mcp: loading store first; a full NVD store takes minutes"
    assert notice_lines[1].startswith("vulnwitness mcp: corpus-store-v1@sha256:")
    assert " data loaded after " in notice_lines[1]
    assert " ready after " in notice_lines[2]
    assert len(notice_lines) == 3


@pytest.fixture
def loading_release(tmp_path: Path) -> Iterator[Path]:
    release_path = tmp_path / "release"
    os.mkfifo(release_path)
    yield release_path


def controlled_server_parameters(
    release_path: Path, failure: str = "none", server_mode: str = "plain"
) -> StdioServerParameters:
    arguments = ["-m", "tests.support.stdio_startup", str(release_path), failure]
    if server_mode != "plain":
        option = "--workspace" if server_mode == "workspace" else "--session"
        arguments.extend([option, str(release_path.parent / server_mode)])
    return StdioServerParameters(
        command=sys.executable,
        args=arguments,
        env=build_server_environment(),
    )


def release_loading(release_path: Path) -> None:
    with release_path.open("wb") as release:
        release.write(b"1")


@pytest.mark.parametrize("server_mode", ["plain", "workspace", "recording"])
@pytest.mark.parametrize("mode", ["legacy", "auto", LATEST_PROTOCOL_VERSION])
async def test_initialize_and_static_tools_are_available_while_loading_is_blocked(
    loading_release: Path, mode: str, server_mode: str
) -> None:
    parameters = controlled_server_parameters(loading_release, server_mode=server_mode)

    with anyio.fail_after(10):
        async with observe_stdio_client(parameters, mode=mode) as (client, stderr):
            with anyio.fail_after(5):
                tool_listing = await client.list_tools()
            await read_until_notice(stderr, b"test: loader blocked")

    expected_count = len(KnowledgeToolName)
    if server_mode == "workspace":
        expected_count += len(WORKSPACE_TOOL_SPECS)
    assert len(tool_listing.tools) == expected_count


@pytest.mark.parametrize("tool_name", list(KnowledgeToolName))
async def test_tool_call_during_loading_returns_an_explicit_error_immediately(
    loading_release: Path,
    tool_name: KnowledgeToolName,
) -> None:
    parameters = controlled_server_parameters(loading_release)

    async with observe_stdio_client(parameters) as (client, stderr):
        await read_until_notice(stderr, b"test: loader blocked")
        with anyio.fail_after(1):
            tool_answer = await client.call_tool(tool_name, TOOL_ARGUMENTS[tool_name])

    assert tool_answer.is_error is True
    failure = ToolFailure.model_validate_json(tool_answer.content[0].text)
    assert failure.code is ToolFailureCode.DATA_LOADING
    assert failure.message == "The data is still loading; retry later."


@pytest.mark.parametrize("mode", ["legacy", "auto", LATEST_PROTOCOL_VERSION])
async def test_same_tool_call_succeeds_after_loading_is_released(
    loading_release: Path, mode: str
) -> None:
    parameters = controlled_server_parameters(loading_release)

    async with observe_stdio_client(parameters, mode=mode) as (client, stderr):
        await client.list_tools()
        await read_until_notice(stderr, b"test: loader blocked")
        loading_answer = await client.call_tool(KnowledgeToolName.GET_KNOWLEDGE_CAPABILITIES, {})
        release_loading(loading_release)
        ready_notice = await read_until_notice(stderr, b" ready after ")
        capabilities_answer = await client.call_tool(
            KnowledgeToolName.GET_KNOWLEDGE_CAPABILITIES, {}
        )

    assert loading_answer.is_error is True
    assert capabilities_answer.is_error is False
    assert KnowledgeCapabilities.model_validate(capabilities_answer.structured_content)
    assert ready_notice.count(b" ready after ") == 1


@pytest.mark.parametrize(
    ("failure", "expected_exit_code", "expected_error"),
    [
        ("store", 2, b"store unavailable: no_active_store"),
        ("snapshot", 2, b"FiGHT snapshot unavailable: fight_snapshot_missing"),
        ("unexpected", 1, b"data loading failed"),
    ],
)
@pytest.mark.parametrize("server_mode", ["plain", "workspace", "recording"])
def test_load_failure_reports_its_reason_and_exits_without_waiting_for_stdin(
    loading_release: Path,
    failure: str,
    expected_exit_code: int,
    expected_error: bytes,
    server_mode: str,
) -> None:
    # Arrange
    parameters = controlled_server_parameters(loading_release, failure, server_mode)
    server_process = subprocess.Popen(
        [parameters.command, *parameters.args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=parameters.env,
    )
    try:
        assert server_process.stdin is not None and server_process.stderr is not None
        frames = [INITIALIZE_FRAME, {"jsonrpc": "2.0", "method": "notifications/initialized"}]
        for frame in frames:
            server_process.stdin.write((json.dumps(frame) + "\n").encode())
        server_process.stdin.flush()
        assert read_process_line(server_process.stderr) == b"test: loader blocked\n"
        release_loading(loading_release)

        exit_code = server_process.wait(timeout=5)
        stdout, stderr = server_process.communicate(timeout=5)
    finally:
        if server_process.poll() is None:
            server_process.kill()
            server_process.communicate(timeout=5)

    assert exit_code == expected_exit_code
    assert expected_error in stderr
    assert b"ready" not in stderr
    assert b"private loader exception" not in stderr
    assert json.loads(stdout.splitlines()[0])["id"] == 1


@pytest.mark.parametrize("stop", ["stdin", "interrupt"])
def test_disconnect_or_interrupt_during_loading_exits_promptly(
    loading_release: Path, stop: str
) -> None:
    parameters = controlled_server_parameters(loading_release)
    server_process = subprocess.Popen(
        [parameters.command, *parameters.args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=parameters.env,
    )
    try:
        assert server_process.stdin is not None and server_process.stderr is not None
        frames = [INITIALIZE_FRAME, {"jsonrpc": "2.0", "method": "notifications/initialized"}]
        for frame in frames:
            server_process.stdin.write((json.dumps(frame) + "\n").encode())
        server_process.stdin.flush()
        assert read_process_line(server_process.stderr) == b"test: loader blocked\n"

        if stop == "stdin":
            server_process.stdin.close()
            server_process.stdin = None
        else:
            server_process.send_signal(signal.SIGINT)
        exit_code = server_process.wait(timeout=5)
        _, stderr = server_process.communicate(timeout=5)
    finally:
        if server_process.poll() is None:
            server_process.kill()
            server_process.communicate(timeout=5)

    assert exit_code == 0
    assert b"ready" not in stderr


@pytest.mark.parametrize("mode", ["legacy", "auto", LATEST_PROTOCOL_VERSION])
async def test_workspace_loading_preserves_request_key_until_the_dataset_is_ready(
    loading_release: Path, mode: str
) -> None:
    # Arrange
    root = loading_release.parent / "workspace"
    parameters = controlled_server_parameters(loading_release, server_mode="workspace")
    arguments = {"vendor": "democorp", "lookups": 1, "request_key": "startup.1"}
    loading_answers = []

    # Act
    with anyio.fail_after(15):
        async with observe_stdio_client(parameters, mode=mode) as (client, stderr):
            await client.list_tools()
            await read_until_notice(stderr, b"test: loader blocked")
            with anyio.fail_after(2):
                for spec in WORKSPACE_TOOL_SPECS:
                    loading_answers.append(await client.call_tool(spec.name, arguments))
                for tool in KnowledgeToolName:
                    loading_answers.append(await client.call_tool(tool, TOOL_ARGUMENTS[tool]))
                loading_answers.append(
                    await client.call_tool(
                        "lookup_cve",
                        {"cve_id": "CVE-9999-0001", "session_id": "inv_aaaaaaaaaaaaaaaaaaaa"},
                    )
                )
            workspace_was_empty = not root.exists() or not tuple(root.iterdir())
            release_loading(loading_release)
            await read_until_notice(stderr, b" ready after ")
            triage = await client.call_tool("triage_product", arguments)
            retry = await client.call_tool("triage_product", arguments)

    # Assert
    assert workspace_was_empty
    for loading in loading_answers:
        assert loading.is_error
        assert loading.structured_content["code"] == "data_loading"
    assert not triage.is_error
    session_id = triage.structured_content["session_id"]
    assert retry.structured_content["session_id"] == session_id
    assert (root / "requests/startup.1.json").is_file()
    assert json.loads((root / session_id / "session.json").read_bytes())["dataset"]


@pytest.mark.parametrize("mode", ["legacy", "auto", LATEST_PROTOCOL_VERSION])
async def test_workspace_loading_serves_packaged_resources_and_refuses_investigation_reads(
    loading_release: Path, mode: str
) -> None:
    # Arrange
    parameters = controlled_server_parameters(loading_release, server_mode="workspace")
    investigation_uri = "vulnwitness://investigations/inv_aaaaaaaaaaaaaaaaaaaa/"
    documents = []
    failures = []

    # Act
    with anyio.fail_after(10):
        async with observe_stdio_client(parameters, mode=mode) as (client, stderr):
            await client.list_tools()
            await read_until_notice(stderr, b"test: loader blocked")
            with anyio.fail_after(2):
                listing = await client.list_resources()
                templates = await client.list_resource_templates()
                prompts = await client.list_prompts()
                topic = next(
                    document
                    for document in listing.resources
                    if document.uri == "vulnwitness://topics/3gpp:gtp"
                )
                schema = next(
                    document
                    for document in listing.resources
                    if document.uri.startswith("vulnwitness://schemas/")
                )
                for descriptor in (topic, schema):
                    documents.append(await client.read_resource(descriptor.uri))
                for artifact in ("summary", "findings", "report.html", "report.md", "calls/1"):
                    with pytest.raises(MCPError) as refused:
                        await client.read_resource(investigation_uri + artifact)
                    failures.append(refused.value.error)
            release_loading(loading_release)
            await read_until_notice(stderr, b" ready after ")
            ready_listing = await client.list_resources()
            ready_templates = await client.list_resource_templates()
            ready_topic = next(
                document for document in ready_listing.resources if document.uri == topic.uri
            )
            created = await client.call_tool("start_investigation", {"goal": "Review startup"})
            snapshot = await client.read_resource(
                "vulnwitness://investigations/"
                + created.structured_content["session_id"]
                + "/summary"
            )

    # Assert
    for document in documents:
        assert isinstance(document.contents[0], TextResourceContents)
        assert document.contents[0].text
    assert len(prompts.prompts) == 3
    assert templates.resource_templates
    assert "identity pending" in topic.description
    assert "identity pending" in templates.resource_templates[0].description
    for failure in failures:
        assert ToolFailure.model_validate_json(failure.message).code is ToolFailureCode.DATA_LOADING
        assert failure.data is None
    assert "identity pending" not in ready_topic.description
    assert "identity pending" not in ready_templates.resource_templates[0].description
    assert snapshot.contents


@pytest.mark.parametrize("mode", ["legacy", "auto", LATEST_PROTOCOL_VERSION])
async def test_recording_loading_records_only_the_call_retried_after_readiness(
    loading_release: Path, mode: str
) -> None:
    # Arrange
    root = loading_release.parent / "recording"
    parameters = controlled_server_parameters(loading_release, server_mode="recording")
    loading_answers = []

    # Act
    with anyio.fail_after(15):
        async with observe_stdio_client(parameters, mode=mode) as (client, stderr):
            await client.list_tools()
            await read_until_notice(stderr, b"test: loader blocked")
            with anyio.fail_after(2):
                for tool in KnowledgeToolName:
                    loading_answers.append(await client.call_tool(tool, TOOL_ARGUMENTS[tool]))
                loading_answers.append(
                    await client.call_tool(
                        "triage_product", {"vendor": "democorp", "request_key": "startup.1"}
                    )
                )
            session_was_absent = not root.exists()
            release_loading(loading_release)
            await read_until_notice(stderr, b" ready after ")
            capabilities = await client.call_tool("get_knowledge_capabilities", {})

    # Assert
    assert session_was_absent
    for loading in loading_answers:
        assert loading.is_error
        assert loading.structured_content["code"] == "data_loading"
    assert not capabilities.is_error
    calls = tuple((root / "calls").glob("*.json"))
    assert len(calls) == 1
    call = json.loads(calls[0].read_bytes())
    session = json.loads((root / "session.json").read_bytes())
    assert call["sequence"] == 1
    assert call["dataset"] == session["dataset"]
