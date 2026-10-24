"""Drives ASGI apps in-process the way uvicorn would, without a socket: one request with
any target bytes, headers and body messages; the lifespan; and small fake routes."""

import json
import threading
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from urllib.parse import unquote

import anyio
import httpx2
from pydantic import SecretStr
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# A token as `secrets.token_urlsafe(32)` writes one.
HTTP_TOKEN = "Kq3vY8xN2pL5sT7wB9dF1gH4jM6zC0aE-tR8uI2oP5a"
HTTP_SECRET_TOKEN = SecretStr(HTTP_TOKEN)
HTTP_HOST = "127.0.0.1"
HTTP_PORT = 8765
SERVED_HOST_HEADER = (b"host", f"{HTTP_HOST}:{HTTP_PORT}".encode())
TOKEN_HEADER = (b"authorization", f"Bearer {HTTP_TOKEN}".encode())
SERVER_URL = f"http://{HTTP_HOST}:{HTTP_PORT}"
AUTHORIZATION = {"authorization": f"Bearer {HTTP_TOKEN}"}
# How long a test waits for something that happens at once; far longer than any deadline
# a test sets.
GENEROUS_WAIT_SECONDS = 10.0


@dataclass(frozen=True)
class AsgiRequest:
    """One request: its method, its target as the request line wrote it (path, then any
    query), its headers and its body as the messages the server would pass on.
    ``client_disconnects`` ends the body with a disconnect; ``body_stalls`` never ends it."""

    method: str = "GET"
    target: bytes = b"/"
    headers: Sequence[tuple[bytes, bytes]] = (SERVED_HOST_HEADER, TOKEN_HEADER)
    body_parts: Sequence[bytes] = (b"",)
    client_disconnects: bool = False
    body_stalls: bool = False


@dataclass
class AsgiAnswer:
    """What the app sent: the status and headers of its response start, and its body."""

    status: int | None = None
    headers: list[tuple[bytes, bytes]] = field(default_factory=list)
    body: bytes = b""
    is_complete: bool = False
    body_messages_received: int = 0

    def list_header_values(self, header_name: bytes) -> list[bytes]:
        header_values: list[bytes] = []
        for name, value in self.headers:
            if name == header_name:
                header_values.append(value)
        return header_values

    def read_json(self) -> object:
        return json.loads(self.body)


class RequestExchange:
    """The server side of one request: hands the app the body messages, then the
    disconnect once the answer is complete, and records the answer."""

    def __init__(self, request: AsgiRequest) -> None:
        self._request = request
        self._next_part = 0
        self.answer = AsgiAnswer()
        self.answer_completed = anyio.Event()

    async def receive(self) -> Message:
        if self._next_part < len(self._request.body_parts):
            part_index = self._next_part
            self._next_part += 1
            self.answer.body_messages_received += 1
            is_last_part = self._next_part == len(self._request.body_parts)
            body_ends_here = is_last_part and not (
                self._request.body_stalls or self._request.client_disconnects
            )
            return {
                "type": "http.request",
                "body": self._request.body_parts[part_index],
                "more_body": not body_ends_here,
            }
        if self._request.client_disconnects:
            return {"type": "http.disconnect"}
        if self._request.body_stalls:
            await anyio.sleep_forever()
        await self.answer_completed.wait()
        return {"type": "http.disconnect"}

    async def send(self, message: Message) -> None:
        if message["type"] == "http.response.start":
            self.answer.status = message["status"]
            self.answer.headers = list(message.get("headers", []))
        elif message["type"] == "http.response.body":
            self.answer.body += message.get("body", b"")
            if not message.get("more_body", False):
                self.answer.is_complete = True
                self.answer_completed.set()


def build_http_scope(request: AsgiRequest) -> Scope:
    raw_path, _, query_string = request.target.partition(b"?")
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": request.method,
        "scheme": "http",
        # As uvicorn does: the path decoded, the raw path as the request line wrote it.
        "path": unquote(raw_path.decode("latin-1")),
        "raw_path": raw_path,
        "query_string": query_string,
        "root_path": "",
        "headers": list(request.headers),
        "client": ("127.0.0.1", 50000),
        "server": (HTTP_HOST, HTTP_PORT),
        "state": {},
    }


async def send_request(app: ASGIApp, request: AsgiRequest) -> AsgiAnswer:
    """``app``'s answer to ``request``."""
    exchange = RequestExchange(request)
    await app(build_http_scope(request), exchange.receive, exchange.send)
    return exchange.answer


@asynccontextmanager
async def running_lifespan(app: ASGIApp) -> AsyncIterator[None]:
    """``app`` started through the ASGI lifespan protocol, and shut down on exit."""
    to_app_send, to_app_receive = anyio.create_memory_object_stream[Message](2)
    from_app_send, from_app_receive = anyio.create_memory_object_stream[Message](2)
    lifespan_scope: Scope = {"type": "lifespan", "asgi": {"version": "3.0"}, "state": {}}
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(app, lifespan_scope, to_app_receive.receive, from_app_send.send)
        await to_app_send.send({"type": "lifespan.startup"})
        startup_answer = await from_app_receive.receive()
        if startup_answer["type"] != "lifespan.startup.complete":
            raise RuntimeError("the app did not start")
        yield
        await to_app_send.send({"type": "lifespan.shutdown"})
        await from_app_receive.receive()


@asynccontextmanager
async def open_app_client(
    app: ASGIApp, headers: Mapping[str, str] | None = None
) -> AsyncIterator[httpx2.AsyncClient]:
    """An in-process HTTP client of ``app`` at ``SERVER_URL``, its lifespan running,
    sending ``headers`` (the token by default) with every request."""
    async with (
        running_lifespan(app),
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url=SERVER_URL,
            headers=AUTHORIZATION if headers is None else headers,
        ) as http_client,
    ):
        yield http_client


class AnsweringRoute:
    """Answers 200 with a small JSON body and its own cache header, and records each body
    it was handed."""

    def __init__(self) -> None:
        self.received_bodies: list[bytes] = []

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        body = bytearray()
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break
        self.received_bodies.append(bytes(body))
        answer = json.dumps({"received_bytes": len(body)}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"cache-control", b"max-age=60"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": answer})


async def answer_never(scope: Scope, receive: Receive, send: Send) -> None:
    """A route that waits forever, until it is cancelled."""
    await anyio.sleep_forever()


class ThreadBlockedRoute:
    """A route waiting on a worker thread that ignores cancellation until ``release`` is
    set, as a tool call handed to ``anyio.to_thread.run_sync`` does."""

    def __init__(self, release: threading.Event, timeout_seconds: float) -> None:
        self._release = release
        self._timeout_seconds = timeout_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await anyio.to_thread.run_sync(self._release.wait, self._timeout_seconds)


async def raise_an_error(scope: Scope, receive: Receive, send: Send) -> None:
    raise RuntimeError("route failed with /secret/path in its message")


async def answer_partly(scope: Scope, receive: Receive, send: Send) -> None:
    """A route that starts an answer and returns before finishing it."""
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"{", "more_body": True})


async def answer_nothing(scope: Scope, receive: Receive, send: Send) -> None:
    """A route that returns without answering."""
