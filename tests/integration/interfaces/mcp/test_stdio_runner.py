"""EOF drains received requests and the transport's final stdout flush."""

import json
import threading

import anyio
import pytest

from tests.support.stdio_streams import (
    BlockedToolboxLoader,
    ImmediateStdioInput,
    PausedStdioOutput,
)
from tests.support.toolbox import build_test_toolbox
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.domain.served_dataset import ServedDatasetKind
from vulnwitness.domain.tool_contracts import ToolFailureCode
from vulnwitness.interfaces.mcp.stdio_runner import StdioServer
from vulnwitness.interfaces.mcp_deployment import McpDeployment

pytestmark = pytest.mark.anyio

INITIALIZE_FRAME = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "immediate-eof-test", "version": "1"},
    },
}


def fail_loading() -> McpDeployment:
    raise SystemExit(2)


async def finish_stdio(
    server: StdioServer,
    stdin: ImmediateStdioInput,
    stdout: PausedStdioOutput,
    exit_codes: list[int],
) -> None:
    try:
        exit_codes.append(await server.run(stdin=stdin, stdout=stdout))
    finally:
        # Wake the test even if the server exits before writing its final response.
        stdout.flush_started.set()


@pytest.mark.parametrize("finish_loading_after_eof", [False, True])
async def test_immediate_eof_answers_received_requests_and_finishes_stdout_flush(
    fixture_bundle: FixtureBundle,
    blocked_call_release: threading.Event,
    finish_loading_after_eof: bool,
    capsys: pytest.CaptureFixture[str],
) -> None:
    frames = [
        INITIALIZE_FRAME,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "get_knowledge_capabilities", "arguments": {}},
        },
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": 5}},
        {"jsonrpc": "2.0", "id": 5, "method": "unknown/method"},
    ]
    loader = BlockedToolboxLoader(build_test_toolbox(fixture_bundle), blocked_call_release)
    stdin = ImmediateStdioInput(
        "{not json\n" + "\n".join(json.dumps(frame) for frame in frames) + "\n",
        before_eof=loader.started if finish_loading_after_eof else None,
    )
    stdout = PausedStdioOutput(response_count=5)
    server = StdioServer(
        loader,
        ServedDatasetKind.SYNTHETIC_FIXTURE,
    )
    exit_codes: list[int] = []

    with anyio.fail_after(5):
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(finish_stdio, server, stdin, stdout, exit_codes)
            await stdout.flush_started.wait()
            if finish_loading_after_eof:
                await stdin.eof.wait()
                blocked_call_release.set()
                await anyio.to_thread.run_sync(loader.returned.wait)
            stdout.release_flush.set()

    answers = stdout.contents.getvalue().splitlines()
    assert exit_codes == [0]
    assert len(answers) == 5
    assert json.loads(answers[0])["id"] == 1
    answers_by_id = {}
    for line in answers:
        answer = json.loads(line)
        answers_by_id[answer["id"]] = answer
    assert "tools" in answers_by_id[2]["result"]
    loading_answer = answers_by_id[3]["result"]
    assert loading_answer["isError"] is True
    assert json.loads(loading_answer["content"][0]["text"])["code"] == ToolFailureCode.DATA_LOADING
    assert answers_by_id[4]["error"] == {"code": -32602, "message": "Invalid request parameters"}
    assert answers_by_id[5]["error"] == {"code": -32601, "message": "Method not found"}
    assert stdout.flush_finished
    assert capsys.readouterr().err == ""


async def test_load_failure_finishes_the_initialize_reply_before_exiting() -> None:
    frames = [INITIALIZE_FRAME, {"jsonrpc": "2.0", "method": "notifications/initialized"}]
    stdin = ImmediateStdioInput(
        "\n".join(json.dumps(frame) for frame in frames) + "\n", before_eof=anyio.Event()
    )
    stdout = PausedStdioOutput(response_count=1)
    server = StdioServer(fail_loading, ServedDatasetKind.SYNTHETIC_FIXTURE)
    exit_codes: list[int] = []

    with anyio.fail_after(5):
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(finish_stdio, server, stdin, stdout, exit_codes)
            await stdout.flush_started.wait()
            stdout.release_flush.set()

    assert exit_codes == [2]
    assert json.loads(stdout.contents.getvalue())["id"] == 1
    assert stdout.flush_finished
