"""MCP over Streamable HTTP: the knowledge tools behind the HTTP guard, stateless with
JSON answers, and every answer the SDK makes itself restated in the server's words."""

import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import AsyncIterator, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError
from mcp.types import TextContent
from starlette.types import Receive, Scope, Send

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.domain.http_rejection import HttpRejection, HttpRejectionCode, build_http_rejection
from cve_kgrag.domain.tool_contracts import ToolFailure, ToolFailureCode
from cve_kgrag.interfaces.http.guard import DEFAULT_BODY_CAP_BYTES, HttpGuard
from cve_kgrag.interfaces.http.serving import find_graceful_shutdown_seconds
from cve_kgrag.interfaces.knowledge_tools import KnowledgeToolName, ToolLimits
from cve_kgrag.interfaces.mcp.http_runner import build_mcp_http_app, find_request_deadline_seconds
from cve_kgrag.interfaces.mcp.sdk_answers import SdkAnswersRestated
from tests.support.asgi import (
    HTTP_HOST,
    HTTP_PORT,
    HTTP_SECRET_TOKEN,
    HTTP_TOKEN,
    AsgiRequest,
    running_lifespan,
    send_request,
)
from tests.support.clocks import SteppingClock
from tests.support.fakes import BlockingRetriever
from tests.support.toolbox import (
    BLOCKED_AFFECTEDNESS_CAPABILITY,
    TOOL_ARGUMENTS,
    UNKNOWN_EVIDENCE_ID,
    build_test_toolbox,
    list_affectedness_capabilities,
)

pytestmark = pytest.mark.anyio

SERVER_URL = f"http://{HTTP_HOST}:{HTTP_PORT}"
AUTHORIZATION = {"authorization": f"Bearer {HTTP_TOKEN}"}
JSON_RPC_HEADERS = {
    **AUTHORIZATION,
    "accept": "application/json, text/event-stream",
    "content-type": "application/json",
}
ECHO_MARKER = "zzechomarkerzz"
CVE_KGRAG_SCRIPT = Path(sys.executable).parent / "cve-kgrag"
SETTINGS_PREFIX = "CVE_KGRAG_"
SERVER_START_SECONDS = 30.0


@pytest.fixture
async def mcp_http_app(fixture_bundle: FixtureBundle) -> AsyncIterator[HttpGuard]:
    """The guarded MCP app over the production toolbox wiring, its lifespan running."""
    mcp_http_app = build_mcp_http_app(
        build_test_toolbox(fixture_bundle), host=HTTP_HOST, port=HTTP_PORT, token=HTTP_SECRET_TOKEN
    )
    async with running_lifespan(mcp_http_app):
        yield mcp_http_app


@pytest.fixture
async def http_client(mcp_http_app: HttpGuard) -> AsyncIterator[httpx2.AsyncClient]:
    """An in-process HTTP client of ``mcp_http_app``, sending no token by itself."""
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=mcp_http_app), base_url=SERVER_URL
    ) as http_client:
        yield http_client


async def test_client_over_http_lists_the_tools_and_answers_capabilities(
    mcp_http_app: HttpGuard, client_mode: str
) -> None:
    async with (
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=mcp_http_app), headers=AUTHORIZATION
        ) as authorized_client,
        Client(
            streamable_http_client(f"{SERVER_URL}/mcp", http_client=authorized_client),
            mode=client_mode,
        ) as client,
    ):
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


async def test_unknown_tool_over_http_is_the_fixed_json_rpc_error(
    mcp_http_app: HttpGuard, client_mode: str
) -> None:
    async with (
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=mcp_http_app), headers=AUTHORIZATION
        ) as authorized_client,
        Client(
            streamable_http_client(f"{SERVER_URL}/mcp", http_client=authorized_client),
            mode=client_mode,
        ) as client,
    ):
        with pytest.raises(MCPError) as raised:
            await client.call_tool(ECHO_MARKER, {})

    assert raised.value.error.message == "unknown tool"
    assert raised.value.error.data is None


def build_tool_call(tool_name: KnowledgeToolName, arguments: dict[str, object]) -> bytes:
    """A ``tools/call`` request on the handshake-era path, which needs no envelope."""
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": tool_name.value, "arguments": arguments},
        }
    ).encode()


def read_tool_failure(answer: httpx2.Response) -> ToolFailure:
    """The ``ToolFailure`` a failed tool's JSON-RPC result carries: an error result with
    one text block holding it and no structured content."""
    tool_result = answer.json()["result"]
    assert tool_result["isError"] is True
    assert "structuredContent" not in tool_result
    assert len(tool_result["content"]) == 1
    return ToolFailure.model_validate_json(tool_result["content"][0]["text"])


@pytest.mark.parametrize(
    ("tool_name", "arguments", "expected_code"),
    [
        (
            KnowledgeToolName.LOOKUP_CVE,
            {"cve_id": ECHO_MARKER},
            ToolFailureCode.INVALID_ARGUMENTS,
        ),
        (
            KnowledgeToolName.GET_EVIDENCE,
            {"evidence_id": UNKNOWN_EVIDENCE_ID},
            ToolFailureCode.UNKNOWN_EVIDENCE_ID,
        ),
        (
            KnowledgeToolName.SEARCH_VULNERABILITIES,
            {"query": "x" * (DEFAULT_BODY_CAP_BYTES // 2)},
            ToolFailureCode.ARGUMENTS_TOO_LARGE,
        ),
    ],
    ids=["invalid_arguments", "unknown_evidence_id", "arguments_too_large"],
)
async def test_tool_failure_over_http_is_a_200_error_result_holding_the_tool_failure(
    http_client: httpx2.AsyncClient,
    tool_name: KnowledgeToolName,
    arguments: dict[str, object],
    expected_code: ToolFailureCode,
) -> None:
    """MCP answers a tool failure as stdio does, never with ADR 0007's REST statuses."""
    answer = await http_client.post(
        "/mcp", content=build_tool_call(tool_name, arguments), headers=JSON_RPC_HEADERS
    )

    assert answer.status_code == 200
    assert read_tool_failure(answer).code is expected_code
    assert ECHO_MARKER not in answer.text


async def test_tool_call_that_runs_out_of_time_over_http_is_a_200_timed_out_result(
    fixture_bundle: FixtureBundle, blocked_call_release: threading.Event
) -> None:
    toolbox = build_test_toolbox(
        fixture_bundle,
        tool_clock=SteppingClock(seconds_per_read=0.03).read,
        limits=ToolLimits(time_limit_seconds=0.05, affectedness_timeout_seconds=0.04),
        lexical_retriever=BlockingRetriever(blocked_call_release),
    )
    app = build_mcp_http_app(toolbox, host=HTTP_HOST, port=HTTP_PORT, token=HTTP_SECRET_TOKEN)
    tool_call = build_tool_call(KnowledgeToolName.SEARCH_VULNERABILITIES, {"query": "ausf"})

    async with (
        running_lifespan(app),
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url=SERVER_URL
        ) as http_client,
    ):
        answer = await http_client.post("/mcp", content=tool_call, headers=JSON_RPC_HEADERS)

    assert answer.status_code == 200
    assert read_tool_failure(answer).code is ToolFailureCode.TIMED_OUT


async def test_client_in_either_mode_reads_a_tool_failure_as_an_error_result(
    mcp_http_app: HttpGuard, client_mode: str
) -> None:
    async with (
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=mcp_http_app), headers=AUTHORIZATION
        ) as authorized_client,
        Client(
            streamable_http_client(f"{SERVER_URL}/mcp", http_client=authorized_client),
            mode=client_mode,
        ) as client,
    ):
        failed_call = await client.call_tool(
            KnowledgeToolName.LOOKUP_CVE.value, {"cve_id": ECHO_MARKER}
        )

    assert failed_call.is_error is True
    assert failed_call.structured_content is None
    failure_block = failed_call.content[0]
    assert isinstance(failure_block, TextContent)
    assert ToolFailure.model_validate_json(failure_block.text).code is (
        ToolFailureCode.INVALID_ARGUMENTS
    )


async def test_mcp_endpoint_refuses_get_instead_of_holding_a_stream_open(
    http_client: httpx2.AsyncClient,
) -> None:
    answer = await http_client.get("/mcp", headers={**AUTHORIZATION, "accept": "text/event-stream"})

    assert answer.status_code == 405
    assert HttpRejection.model_validate_json(answer.content).code is (
        HttpRejectionCode.METHOD_NOT_ALLOWED
    )


async def test_ready_answers_204_with_the_token_and_health_without_it(
    http_client: httpx2.AsyncClient,
) -> None:
    ready_answer = await http_client.get("/ready", headers=AUTHORIZATION)
    health_answer = await http_client.get("/health")

    assert ready_answer.status_code == 204
    assert health_answer.status_code == 204


async def test_ready_answers_503_while_every_worker_holds_a_call(
    fixture_bundle: FixtureBundle, blocked_call_release: threading.Event
) -> None:
    blocking_retriever = BlockingRetriever(blocked_call_release)
    toolbox = build_test_toolbox(
        fixture_bundle,
        limits=ToolLimits(max_calls_in_flight=1),
        lexical_retriever=blocking_retriever,
    )
    app = build_mcp_http_app(toolbox, host=HTTP_HOST, port=HTTP_PORT, token=HTTP_SECRET_TOKEN)
    with ThreadPoolExecutor(max_workers=1) as executor:
        blocked_call = executor.submit(
            toolbox.call, KnowledgeToolName.SEARCH_VULNERABILITIES, {"query": "ausf"}
        )
        assert blocking_retriever.entered.wait(timeout=SERVER_START_SECONDS)
        async with (
            running_lifespan(app),
            httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app), base_url=SERVER_URL
            ) as http_client,
        ):
            busy_answer = await http_client.get("/ready", headers=AUTHORIZATION)
        blocked_call_release.set()
        blocked_call.result(timeout=SERVER_START_SECONDS)

    assert busy_answer.status_code == 503
    assert HttpRejection.model_validate_json(busy_answer.content).code is (
        HttpRejectionCode.NOT_READY
    )


async def test_request_deadline_is_fifty_seconds_and_a_stop_waits_past_it(
    mcp_http_app: HttpGuard,
) -> None:
    """The deadline runs 10 s past the longest call (a 30 s investigation plus its 10 s
    seal margin), and a stop waits past the deadline, so uvicorn cuts no request off."""
    assert find_request_deadline_seconds(ToolLimits()) == 50.0
    assert mcp_http_app.request_deadline_seconds == 50.0
    assert find_graceful_shutdown_seconds(mcp_http_app) > mcp_http_app.request_deadline_seconds


async def test_sdk_answer_with_a_server_error_in_plain_text_is_an_internal_error() -> None:
    restated_app = SdkAnswersRestated(answer_server_error_in_plain_text)

    answer = await send_request(
        restated_app, AsgiRequest(method="POST", target=b"/mcp", body_parts=(b"{}",))
    )

    assert answer.status == 500
    assert HttpRejection.model_validate_json(answer.body).code is HttpRejectionCode.INTERNAL_ERROR
    assert ECHO_MARKER.encode() not in answer.body


async def answer_server_error_in_plain_text(scope: Scope, receive: Receive, send: Send) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 500,
            "headers": [(b"content-type", b"text/plain"), (b"x-detail", ECHO_MARKER.encode())],
        }
    )
    await send({"type": "http.response.body", "body": ECHO_MARKER.encode()})


def restate_error(request_id: int | None, code: int, message: str) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


# Requests the SDK answers itself, each carrying the marker where the SDK would repeat it,
# and the status and body the server answers instead.
SDK_ANSWERED_REQUESTS: list[tuple[dict[str, str], bytes, int, object]] = [
    (
        {},
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": ECHO_MARKER}).encode(),
        200,
        restate_error(1, -32601, "Method not found"),
    ),
    (
        {},
        json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": ECHO_MARKER}
        ).encode(),
        400,
        restate_error(None, -32602, "Invalid params"),
    ),
    (
        {},
        json.dumps({"jsonrpc": ECHO_MARKER, "id": 1, "method": "tools/list"}).encode(),
        400,
        restate_error(None, -32602, "Invalid params"),
    ),
    (
        {},
        f'{{"jsonrpc":"2.0","id":1,"method":"{ECHO_MARKER}'.encode(),
        400,
        restate_error(None, -32700, "Parse error"),
    ),
    (
        {"mcp-protocol-version": ECHO_MARKER, "mcp-method": "tools/list"},
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode(),
        400,
        restate_error(1, -32602, "Invalid params"),
    ),
    (
        {"mcp-protocol-version": "2026-07-28", "mcp-method": ECHO_MARKER},
        json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": ECHO_MARKER, "params": {"_meta": {}}}
        ).encode(),
        400,
        restate_error(1, -32602, "Invalid params"),
    ),
    (
        {"content-type": "text/plain"},
        ECHO_MARKER.encode(),
        400,
        build_http_rejection(HttpRejectionCode.INVALID_REQUEST).model_dump(mode="json"),
    ),
    (
        {"accept": "text/html"},
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": ECHO_MARKER}).encode(),
        406,
        restate_error(None, -32600, "Invalid Request"),
    ),
]


@pytest.mark.parametrize(
    ("extra_headers", "body", "expected_status", "expected_answer"),
    SDK_ANSWERED_REQUESTS,
    ids=[
        "unknown_method",
        "params_not_an_object",
        "other_json_rpc_version",
        "truncated_json",
        "unknown_protocol_version",
        "modern_unknown_method",
        "not_json",
        "json_not_accepted",
    ],
)
async def test_sdk_answer_is_restated_without_anything_the_request_sent(
    http_client: httpx2.AsyncClient,
    extra_headers: dict[str, str],
    body: bytes,
    expected_status: int,
    expected_answer: object,
) -> None:
    answer = await http_client.post(
        "/mcp", content=body, headers={**JSON_RPC_HEADERS, **extra_headers}
    )

    assert answer.status_code == expected_status
    assert answer.json() == expected_answer
    for header_value in answer.headers.values():
        assert ECHO_MARKER not in header_value


# Requests uvicorn itself answers or warns about before the guard runs.
UPGRADE_REQUEST = (
    b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade, close\r\n"
    b"Upgrade: websocket\r\n\r\n"
)
MALFORMED_REQUEST = b"GARBAGE\r\n\r\n"


@dataclass(frozen=True)
class ServedMcpHttp:
    """A running ``cve-kgrag mcp --http``: the address it listens on and its process."""

    host: str
    port: int
    process: subprocess.Popen[bytes]

    @property
    def url(self) -> str:
        url_host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{url_host}:{self.port}"


def send_raw_requests(host: str, port: int, raw_requests: list[bytes]) -> None:
    """Send each request on its own connection and read until the server closes it."""
    for raw_request in raw_requests:
        with socket.create_connection((host, port), timeout=SERVER_START_SECONDS) as client:
            client.sendall(raw_request)
            while client.recv(65536):
                pass


def find_free_loopback_port(host: str) -> int:
    """A port free on ``host``; ``pytest.skip`` when the machine has no such address."""
    address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(address_family, socket.SOCK_STREAM) as probe_socket:
        try:
            probe_socket.bind((host, 0))
        except OSError:
            pytest.skip(f"no {host} loopback address on this machine")
        free_port: int = probe_socket.getsockname()[1]
        return free_port


def build_server_environment(host: str, port: int) -> dict[str, str]:
    """The test process's environment without its cve-kgrag settings, plus the token,
    ``host`` and ``port``."""
    server_environment: dict[str, str] = {}
    for variable_name, value in os.environ.items():
        if not variable_name.startswith(SETTINGS_PREFIX):
            server_environment[variable_name] = value
    server_environment["CVE_KGRAG_HTTP_TOKEN"] = HTTP_TOKEN
    server_environment["CVE_KGRAG_HTTP_HOST"] = host
    server_environment["CVE_KGRAG_MCP_HTTP_PORT"] = str(port)
    return server_environment


def wait_until_healthy(server_url: str, server_process: subprocess.Popen[bytes]) -> None:
    started_at = time.monotonic()
    while time.monotonic() - started_at < SERVER_START_SECONDS:
        if server_process.poll() is not None:
            raise RuntimeError("cve-kgrag mcp --http exited before serving")
        try:
            health_status = httpx2.get(f"{server_url}/health").status_code
        except httpx2.TransportError:
            time.sleep(0.05)
            continue
        if health_status != 204:
            raise RuntimeError(f"/health answered {health_status}")
        return
    raise RuntimeError("cve-kgrag mcp --http did not start serving")


@pytest.fixture(params=["127.0.0.1", "::1"])
def served_mcp_http(request: pytest.FixtureRequest) -> Iterator[ServedMcpHttp]:
    """``cve-kgrag mcp --http`` on each loopback host the settings accept, on a free port;
    killed at teardown if a test left it running."""
    host: str = request.param
    port = find_free_loopback_port(host)
    served = ServedMcpHttp(
        host=host,
        port=port,
        process=subprocess.Popen(
            [str(CVE_KGRAG_SCRIPT), "mcp", "--http"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=build_server_environment(host, port),
        ),
    )
    try:
        wait_until_healthy(served.url, served.process)
        yield served
    finally:
        if served.process.poll() is None:
            served.process.kill()
        served.process.communicate(timeout=SERVER_START_SECONDS)


async def test_cve_kgrag_mcp_http_serves_the_tools_logs_nothing_and_stops_on_interrupt(
    served_mcp_http: ServedMcpHttp,
) -> None:
    async with (
        httpx2.AsyncClient(headers=AUTHORIZATION) as authorized_client,
        Client(
            streamable_http_client(f"{served_mcp_http.url}/mcp", http_client=authorized_client)
        ) as client,
    ):
        tool_listing = await client.list_tools()
    unauthenticated_answer = httpx2.get(f"{served_mcp_http.url}/ready")
    send_raw_requests(
        served_mcp_http.host, served_mcp_http.port, [UPGRADE_REQUEST, MALFORMED_REQUEST]
    )
    oversized_answer = httpx2.post(
        f"{served_mcp_http.url}/mcp", content=b" " * (1024 * 1024), headers=JSON_RPC_HEADERS
    )
    served_mcp_http.process.send_signal(signal.SIGINT)
    stdout, stderr = served_mcp_http.process.communicate(timeout=SERVER_START_SECONDS)

    assert len(tool_listing.tools) == len(KnowledgeToolName)
    assert unauthenticated_answer.status_code == 401
    assert "server" not in unauthenticated_answer.headers
    assert oversized_answer.status_code == 413
    assert served_mcp_http.process.returncode == 0
    assert stdout == b""
    assert stderr == b""


def test_cve_kgrag_mcp_http_on_a_port_in_use_exits_one_saying_why() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listening_socket:
        listening_socket.bind((HTTP_HOST, 0))
        listening_socket.listen()
        taken_port: int = listening_socket.getsockname()[1]

        server_process = subprocess.run(
            [str(CVE_KGRAG_SCRIPT), "mcp", "--http"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=SERVER_START_SECONDS,
            check=False,
            env=build_server_environment(HTTP_HOST, taken_port),
        )

    assert server_process.returncode == 1
    assert server_process.stdout == b""
    assert b"address already in use" in server_process.stderr
    assert HTTP_TOKEN.encode() not in server_process.stderr
