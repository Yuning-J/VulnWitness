"""``cve-kgrag mcp`` serves the knowledge tools over stdio through the ``mcp_server`` entry
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
from mcp.types import LATEST_PROTOCOL_VERSION

from cve_kgrag.cli import main
from cve_kgrag.domain.investigation import SourceCapabilityState
from cve_kgrag.domain.tool_contracts import KnowledgeCapabilities, ToolFailure, ToolFailureCode
from cve_kgrag.interfaces.knowledge_tools import KnowledgeToolName
from tests.support.corpus_stores import import_store
from tests.support.stdio_client import observe_stdio_client, read_process_line, read_until_notice
from tests.support.toolbox import (
    BLOCKED_AFFECTEDNESS_CAPABILITY,
    TOOL_ARGUMENTS,
    list_affectedness_capabilities,
)

pytestmark = pytest.mark.anyio

# The console script of the environment running the tests.
CVE_KGRAG_SCRIPT = Path(sys.executable).parent / "cve-kgrag"
# The prefix of every setting the server reads (cve_kgrag.settings).
SETTINGS_PREFIX = "CVE_KGRAG_"


def build_server_environment() -> dict[str, str]:
    """The test process's environment without any cve-kgrag setting, so the server runs on
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


async def test_cve_kgrag_mcp_over_stdio_lists_tools_and_answers_capabilities() -> None:
    server_parameters = StdioServerParameters(
        command=str(CVE_KGRAG_SCRIPT), args=["mcp"], env=build_server_environment()
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


def test_cve_kgrag_mcp_with_stdin_closed_exits_zero_and_writes_nothing() -> None:
    """Nothing reaches stdout outside the protocol: no banner, no stdout log handler."""
    server_process = subprocess.run(
        [str(CVE_KGRAG_SCRIPT), "mcp"],
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
        [str(CVE_KGRAG_SCRIPT), "mcp"],
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
        [str(CVE_KGRAG_SCRIPT), "mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=build_server_environment(),
    )
    assert server_process.stdin is not None and server_process.stdout is not None
    server_process.stdin.write(("\n".join(frames) + "\n").encode())
    server_process.stdin.flush()
    # Read the answers before closing stdin: the server stops at end of input, and a
    # reply still in flight then is not written.
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


async def test_cve_kgrag_mcp_never_serves_the_semantic_channel_whatever_the_settings(
    tmp_path: Path,
) -> None:
    """The tools are read-only and the semantic store cannot be opened read-only, so the
    server loads no semantic adapter even when the settings enable one."""
    server_environment = {
        **build_server_environment(),
        "CVE_KGRAG_SEMANTIC_ENABLED": "true",
        "CVE_KGRAG_SEMANTIC_PERSIST_DIRECTORY": str(tmp_path / "vectors"),
    }
    server_parameters = StdioServerParameters(
        command=str(CVE_KGRAG_SCRIPT), args=["mcp"], env=server_environment
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


def test_cve_kgrag_mcp_over_a_store_announces_loading_on_stderr_and_keeps_stdout_protocol_only(
    tmp_path: Path,
) -> None:
    store_root = tmp_path / "stores"
    store_root.mkdir()
    import_store(store_root, "first")
    root_settings = {"CVE_KGRAG_STORE_ROOT": str(store_root)}
    assert main(["store", "activate", "first"], root_settings) == 0
    frames = [
        json.dumps(INITIALIZE_FRAME),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ]

    server_process = subprocess.Popen(
        [str(CVE_KGRAG_SCRIPT), "mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**build_server_environment(), **root_settings},
    )
    assert server_process.stdin is not None
    assert server_process.stdout is not None
    server_process.stdin.write(("\n".join(frames) + "\n").encode())
    server_process.stdin.flush()
    # stdin stays open until both answers arrived: the server may stop reading at end of
    # input before it answers a request still queued.
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
    assert notice_lines[0] == "cve-kgrag mcp: loading store first; a full NVD store takes minutes"
    assert notice_lines[1].startswith("cve-kgrag mcp: corpus-store-v1@sha256:")
    assert " data loaded after " in notice_lines[1]
    assert " ready after " in notice_lines[2]
    assert len(notice_lines) == 3


@pytest.fixture
def loading_release(tmp_path: Path) -> Iterator[Path]:
    release_path = tmp_path / "release"
    os.mkfifo(release_path)
    yield release_path


def controlled_server_parameters(
    release_path: Path, failure: str = "none"
) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "tests.support.stdio_startup", str(release_path), failure],
        env=build_server_environment(),
    )


def release_loading(release_path: Path) -> None:
    with release_path.open("wb") as release:
        release.write(b"1")


@pytest.mark.parametrize("mode", ["legacy", "auto", LATEST_PROTOCOL_VERSION])
async def test_initialize_and_static_tools_are_available_while_loading_is_blocked(
    loading_release: Path, mode: str
) -> None:
    parameters = controlled_server_parameters(loading_release)

    with anyio.fail_after(10):
        async with observe_stdio_client(parameters, mode=mode) as (client, stderr):
            with anyio.fail_after(5):
                tool_listing = await client.list_tools()
            await read_until_notice(stderr, b"test: loader blocked")

    assert len(tool_listing.tools) == len(KnowledgeToolName)


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
def test_load_failure_reports_its_reason_and_exits_without_waiting_for_stdin(
    loading_release: Path, failure: str, expected_exit_code: int, expected_error: bytes
) -> None:
    parameters = controlled_server_parameters(loading_release, failure)
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
