"""``cve-kgrag mcp`` serves the knowledge tools over stdio through the ``mcp_server`` entry
point, with nothing but the protocol on stdout."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters
from mcp.types import LATEST_PROTOCOL_VERSION

from cve_kgrag.cli import main
from cve_kgrag.domain.investigation import SourceCapabilityState
from cve_kgrag.domain.tool_contracts import KnowledgeCapabilities
from cve_kgrag.interfaces.knowledge_tools import KnowledgeToolName
from tests.support.corpus_stores import import_store
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

    async with Client(server_parameters) as client:
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

    async with Client(server_parameters) as client:
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
    trailing_stdout, stderr_bytes = server_process.communicate(timeout=60)

    answered_ids: list[object] = []
    for answer_line in answer_lines:
        message = json.loads(answer_line)
        assert message["jsonrpc"] == "2.0"
        answered_ids.append(message["id"])
    notice_lines = stderr_bytes.decode().splitlines()
    assert server_process.returncode == 0
    assert answered_ids == [1, 2]
    assert trailing_stdout == b""
    assert notice_lines[0] == "cve-kgrag mcp: loading store first; a full NVD store takes minutes"
    assert notice_lines[1].startswith("cve-kgrag mcp: corpus-store-v1@sha256:")
    assert " ready after " in notice_lines[1]
    assert len(notice_lines) == 2
