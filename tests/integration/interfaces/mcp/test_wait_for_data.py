"""Readiness waits stay asynchronous, bounded and isolated on both MCP transports."""

import json
from collections.abc import AsyncIterator
from pathlib import Path

import anyio
import pytest
from anyio.abc import TaskStatus
from jsonschema import Draft202012Validator
from mcp import Client
from mcp.types import LATEST_PROTOCOL_VERSION, CallToolResult

from tests.integration.interfaces.mcp.wait_client import WaitingClient, connect_waiting_client
from tests.support.paths import REPOSITORY_SCHEMA_DIR
from vulnwitness.domain.tool_contracts import ToolFailure

pytestmark = pytest.mark.anyio


@pytest.fixture(params=["stdio", "http"])
def transport(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@pytest.fixture(params=["plain", "workspace", "recording"])
def server_mode(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@pytest.fixture(params=["legacy", "auto", LATEST_PROTOCOL_VERSION])
def protocol(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@pytest.fixture
async def waiting_client(
    tmp_path: Path, transport: str, server_mode: str, protocol: str
) -> AsyncIterator[WaitingClient]:
    with anyio.fail_after(15):
        async with connect_waiting_client(tmp_path, transport, server_mode, protocol) as waiting:
            yield waiting


async def capture_wait(
    client: Client,
    answers: list[CallToolResult],
    *,
    task_status: TaskStatus[anyio.CancelScope] = anyio.TASK_STATUS_IGNORED,
) -> None:
    with anyio.CancelScope() as scope:
        task_status.started(scope)
        answers.append(await client.call_tool("wait_for_data", {}))


def assert_wait_answer(answer: CallToolResult, expected: dict[str, object]) -> None:
    schema = json.loads((REPOSITORY_SCHEMA_DIR / "wait_for_data_response.schema.json").read_text())
    assert not answer.is_error
    assert answer.structured_content == expected
    assert json.loads(answer.content[0].text) == expected
    Draft202012Validator(schema).validate(answer.structured_content)


def has_no_records(root: Path) -> bool:
    return not any(root.glob("inv_*")) and not any(root.rglob("*.json"))


async def test_wait_returns_ready_when_loader_completes_without_blocking_metadata(
    waiting_client: WaitingClient,
) -> None:
    # Arrange
    client = waiting_client.client
    answers: list[CallToolResult] = []
    topics = None
    resources = None

    # Act
    async with anyio.create_task_group() as tasks:
        await tasks.start(capture_wait, client, answers)
        with anyio.fail_after(2):
            tools = await client.list_tools()
            if waiting_client.mode == "workspace":
                resources = await client.list_resources()
                topics = await client.read_resource("vulnwitness://topics/3gpp:gtp")
            refused = await client.call_tool("get_knowledge_capabilities", {})
        still_waiting = not answers
        records_were_absent = has_no_records(waiting_client.root)
        waiting_client.release()
    with anyio.fail_after(1):
        already_ready = await client.call_tool("wait_for_data", {"timeout_seconds": 60})
    records_still_absent = has_no_records(waiting_client.root)
    successful = await client.call_tool("get_knowledge_capabilities", {})

    # Assert
    assert still_waiting
    assert records_were_absent and records_still_absent
    assert_wait_answer(answers[0], {"status": "ready"})
    assert_wait_answer(already_ready, {"status": "ready"})
    assert refused.is_error
    failure = ToolFailure.model_validate_json(refused.content[0].text)
    assert failure.code == "data_loading"
    assert "wait_for_data" in failure.message and "same request_key" in failure.message
    assert not successful.is_error
    descriptor = next(tool for tool in tools.tools if tool.name == "wait_for_data")
    assert descriptor.annotations.read_only_hint is True
    assert descriptor.annotations.idempotent_hint is True
    assert descriptor.annotations.open_world_hint is False
    assert "session_id" not in descriptor.input_schema["properties"]
    assert descriptor.input_schema == json.loads(
        (REPOSITORY_SCHEMA_DIR / "wait_for_data_request.schema.json").read_text()
    )
    assert descriptor.output_schema == json.loads(
        (REPOSITORY_SCHEMA_DIR / "wait_for_data_response.schema.json").read_text()
    )
    if waiting_client.mode == "workspace":
        assert resources.resources and topics.contents
    elif waiting_client.mode == "recording":
        assert len(tuple((waiting_client.root / "calls").glob("*.json"))) == 1


async def test_timeout_returns_loading_and_later_wait_observes_completed_load(
    waiting_client: WaitingClient,
) -> None:
    # Arrange
    client = waiting_client.client

    # Act
    started_at = anyio.current_time()
    expired = await client.call_tool("wait_for_data", {"timeout_seconds": 1})
    waited_seconds = anyio.current_time() - started_at
    refused = await client.call_tool("get_knowledge_capabilities", {})
    records_were_absent = has_no_records(waiting_client.root)
    waiting_client.release()
    ready = await client.call_tool("wait_for_data", {})

    # Assert
    assert_wait_answer(expired, {"status": "loading", "waited_seconds": 1})
    assert waited_seconds >= 1
    assert refused.is_error and records_were_absent
    assert_wait_answer(ready, {"status": "ready"})
    assert has_no_records(waiting_client.root)


async def test_client_cancellation_leaves_loader_and_other_waiters_running(
    waiting_client: WaitingClient,
) -> None:
    # Arrange
    client = waiting_client.client
    cancelled_answers: list[CallToolResult] = []
    other_answers: list[CallToolResult] = []

    # Act
    async with anyio.create_task_group() as tasks:
        cancelled_scope = await tasks.start(capture_wait, client, cancelled_answers)
        await tasks.start(capture_wait, client, other_answers)
        await client.list_tools()
        cancelled_scope.cancel()
        refused = await client.call_tool("get_knowledge_capabilities", {})
        waiting_client.release()
    ready = await client.call_tool("wait_for_data", {})
    records_were_absent = has_no_records(waiting_client.root)
    successful = await client.call_tool("get_knowledge_capabilities", {})

    # Assert
    assert not cancelled_answers
    assert refused.is_error and records_were_absent
    assert_wait_answer(other_answers[0], {"status": "ready"})
    assert_wait_answer(ready, {"status": "ready"})
    assert not successful.is_error


async def test_invalid_wait_arguments_return_typed_failure_without_recording(
    waiting_client: WaitingClient,
) -> None:
    # Arrange
    client = waiting_client.client
    invalid_arguments = [
        {"timeout_seconds": 0},
        {"timeout_seconds": 61},
        {"timeout_seconds": -1},
        {"timeout_seconds": 1.5},
        {"timeout_seconds": True},
        {"timeout_seconds": "20"},
        {"timeout_seconds": None},
        {"session_id": "inv_" + "a" * 20},
    ]
    refusals = []

    # Act
    for arguments in invalid_arguments:
        refusals.append(await client.call_tool("wait_for_data", arguments))
    waiting_client.release()
    ready = await client.call_tool("wait_for_data", {})
    for arguments in invalid_arguments:
        refusals.append(await client.call_tool("wait_for_data", arguments))

    # Assert
    assert_wait_answer(ready, {"status": "ready"})
    for refusal in refusals:
        assert refusal.is_error
        assert refusal.structured_content["code"] == "invalid_arguments"
    assert has_no_records(waiting_client.root)
