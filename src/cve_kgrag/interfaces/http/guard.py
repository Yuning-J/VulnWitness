"""The guard in front of every HTTP route (ADR 0007): it checks the Host and Origin
headers and the bearer token, routes on the exact path (or, for a route that takes one,
on its path and one last segment), counts the body on the wire
against the route's cap before anything parses it, and holds each request to a deadline.
Every refusal is an ``HttpRejection`` carrying its code's fixed sentence, so no answer
repeats a header, a path or a body the request sent.

Checks run in this order, so a caller learns no more than the first failed check tells:
Host (421), Origin (403), the token (401) on every route but an open one, the route
(404), the method (405), then the declared body length (400 or 413). The deadline covers
reading the body as well as running the route.

The route's answer is recorded in full before any of it is sent, so the guard can still
answer 504 when the deadline passes, whatever the route is doing; the routes answer
bounded JSON (a tool's answer by ``ToolLimits``, a verification report by its
contract), so recording it costs at most that much memory.
"""

import hmac
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

import anyio
from pydantic import SecretStr
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from cve_kgrag.domain.http_rejection import HttpRejectionCode, build_http_rejection

# Every route's body cap but the verification route's (ADR 0007, decision 11).
DEFAULT_BODY_CAP_BYTES = 256 * 1024
REJECTION_STATUSES: dict[HttpRejectionCode, int] = {
    HttpRejectionCode.INVALID_REQUEST: 400,
    HttpRejectionCode.UNAUTHORIZED: 401,
    HttpRejectionCode.ORIGIN_NOT_ALLOWED: 403,
    HttpRejectionCode.NOT_FOUND: 404,
    HttpRejectionCode.METHOD_NOT_ALLOWED: 405,
    HttpRejectionCode.BODY_TOO_LARGE: 413,
    HttpRejectionCode.HOST_NOT_ALLOWED: 421,
    HttpRejectionCode.INTERNAL_ERROR: 500,
    HttpRejectionCode.NOT_READY: 503,
    HttpRejectionCode.ROUTE_BUSY: 503,
    HttpRejectionCode.DEADLINE_EXCEEDED: 504,
}
# Sent with every answer: nothing a route answers is cached, and no answer is sniffed as
# another type than it declares.
SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"cache-control", b"no-store"),
    (b"x-content-type-options", b"nosniff"),
)
SECURITY_HEADER_NAMES = frozenset({b"cache-control", b"x-content-type-options"})
BEARER_SCHEME = b"bearer"
JSON_CONTENT_TYPE = (b"content-type", b"application/json")


@dataclass(frozen=True)
class GuardedRoute:
    """One route: the methods it accepts, the ASGI app answering it, the most body bytes a
    request to it may carry, whether it is served without the token (``/health`` alone
    is), and whether its path ends in ``/`` followed by one path segment the app reads
    (``takes_path_segment``)."""

    methods: frozenset[str]
    app: ASGIApp
    body_cap_bytes: int = DEFAULT_BODY_CAP_BYTES
    is_open: bool = False
    takes_path_segment: bool = False


@dataclass(frozen=True)
class GuardRefusal:
    """A check the request failed: the rejection's code and the headers HTTP requires
    with it (``WWW-Authenticate`` with a 401, ``Allow`` with a 405)."""

    code: HttpRejectionCode
    headers: tuple[tuple[bytes, bytes], ...] = ()


@dataclass
class RecordedResponse:
    """A route's answer as the route sent it, kept until it is complete."""

    start: Message | None = None
    body_parts: list[bytes] = field(default_factory=list)
    is_complete: bool = False

    async def record(self, message: Message) -> None:
        if message["type"] == "http.response.start":
            self.start = message
        elif message["type"] == "http.response.body":
            self.body_parts.append(message.get("body", b""))
            self.is_complete = not message.get("more_body", False)


RouteOutcome = RecordedResponse | HttpRejectionCode | None


@dataclass
class RouteRun:
    """What running a route came to: its answer, a refusal, or ``None`` when the client
    went away before its body arrived."""

    outcome: RouteOutcome = None
    finished: anyio.Event = field(default_factory=anyio.Event)


class ReplayedReceive:
    """Hands the route the body the guard read, as one message, then the server's own
    ``receive``, so a route waiting for the client to disconnect still learns of it."""

    def __init__(self, body: bytes, receive: Receive) -> None:
        self._body: bytes | None = body
        self._receive = receive

    async def __call__(self) -> Message:
        if self._body is None:
            return await self._receive()
        body = self._body
        self._body = None
        return {"type": "http.request", "body": body, "more_body": False}


def list_served_hosts(host: str, port: int) -> frozenset[bytes]:
    """The Host header values a request to a server on ``host`` and ``port`` may carry:
    the address as a URL writes it, or ``localhost``, with the port; without it only on
    port 80, the one a client leaves out."""
    url_hosts = (f"[{host}]" if ":" in host else host, "localhost")
    served_hosts: set[bytes] = set()
    for url_host in url_hosts:
        served_hosts.add(f"{url_host}:{port}".encode())
        if port == 80:
            served_hosts.add(url_host.encode())
    return frozenset(served_hosts)


def list_served_origins(served_hosts: frozenset[bytes]) -> frozenset[bytes]:
    """The origins of pages the server itself would serve: ``http://`` and a served
    host."""
    served_origins: set[bytes] = set()
    for served_host in served_hosts:
        served_origins.add(b"http://" + served_host)
    return frozenset(served_origins)


def list_header_values(scope: Scope, header_name: bytes) -> list[bytes]:
    header_values: list[bytes] = []
    for name, value in scope["headers"]:
        if name == header_name:
            header_values.append(value)
    return header_values


def read_declared_length(scope: Scope) -> int | HttpRejectionCode | None:
    """The body length the request declares, ``None`` when it declares none, or
    ``invalid_request`` for a declaration that is not exactly one decimal number."""
    declared_lengths = list_header_values(scope, b"content-length")
    if not declared_lengths:
        return None
    if len(declared_lengths) > 1 or not declared_lengths[0].isdigit():
        return HttpRejectionCode.INVALID_REQUEST
    return int(declared_lengths[0])


def read_path_segment(scope: Scope) -> bytes:
    """The last segment of the request's path as the request line wrote it: what a route
    that takes a path segment reads (``GuardedRoute.takes_path_segment``)."""
    raw_path: bytes = scope["raw_path"]
    return raw_path.rpartition(b"/")[2]


def carries_token(scope: Scope, token: bytes) -> bool:
    """Whether the request carries exactly one ``Authorization`` header holding ``Bearer``
    (any case) and the token, compared in constant time as bytes, so a header holding
    other bytes than ASCII is refused rather than raising."""
    authorizations = list_header_values(scope, b"authorization")
    if len(authorizations) != 1:
        return False
    scheme, separator, presented_token = authorizations[0].partition(b" ")
    if not separator or scheme.lower() != BEARER_SCHEME:
        return False
    return hmac.compare_digest(presented_token, token)


async def read_body(receive: Receive, body_cap_bytes: int) -> bytes | HttpRejectionCode | None:
    """The request body, ``body_too_large`` as soon as the count passes the cap (so no
    more than one message past it is held), or ``None`` when the client disconnects."""
    body = bytearray()
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return None
        body += message.get("body", b"")
        if len(body) > body_cap_bytes:
            return HttpRejectionCode.BODY_TOO_LARGE
        if not message.get("more_body", False):
            return bytes(body)


async def read_route_body(receive: Receive) -> bytes:
    """The body the guard read, which it hands a route in one message."""
    message = await receive()
    body: bytes = message.get("body", b"")
    return body


async def send_json(
    send: Send, status: int, body: bytes, headers: Sequence[tuple[bytes, bytes]] = ()
) -> None:
    """Answer ``body``, JSON already serialized, with ``status`` and ``headers``."""
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                JSON_CONTENT_TYPE,
                (b"content-length", str(len(body)).encode()),
                *headers,
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


async def send_rejection(
    send: Send, code: HttpRejectionCode, headers: Sequence[tuple[bytes, bytes]] = ()
) -> None:
    """Answer with the ``HttpRejection`` of ``code`` and its status. The answer carries no
    ``connection: close``: a client still sending a body it was refused then reads the
    answer instead of a reset connection, and the server discards the rest of the body."""
    body = build_http_rejection(code).model_dump_json().encode()
    await send_json(send, REJECTION_STATUSES[code], body, [*headers, *SECURITY_HEADERS])


async def send_recorded_response(send: Send, recorded_response: RecordedResponse) -> None:
    """Send the route's answer with the security headers in place of any it set."""
    if recorded_response.start is None:
        raise ValueError("the route sent no response start")
    headers: list[tuple[bytes, bytes]] = []
    for header_name, header_value in recorded_response.start.get("headers", []):
        if header_name.lower() not in SECURITY_HEADER_NAMES:
            headers.append((header_name, header_value))
    await send({**recorded_response.start, "headers": [*headers, *SECURITY_HEADERS]})
    await send({"type": "http.response.body", "body": b"".join(recorded_response.body_parts)})


class HttpGuard:
    """The ASGI app a server runs: lifespan events go to ``lifespan_app``; an HTTP request
    is checked, then answered by the route its path names (``routes``, keyed by path;
    ``_find_route``) within ``request_deadline_seconds``. Any other scope is not
    served."""

    def __init__(
        self,
        *,
        routes: Mapping[str, GuardedRoute],
        lifespan_app: ASGIApp,
        host: str,
        port: int,
        token: SecretStr,
        request_deadline_seconds: float,
    ) -> None:
        self._routes: dict[bytes, GuardedRoute] = {}
        for path, route in routes.items():
            self._routes[path.encode()] = route
        self._lifespan_app = lifespan_app
        self._served_hosts = list_served_hosts(host, port)
        self._served_origins = list_served_origins(self._served_hosts)
        self._token = token.get_secret_value().encode()
        self._request_deadline_seconds = request_deadline_seconds

    @property
    def request_deadline_seconds(self) -> float:
        return self._request_deadline_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan_app(scope, receive, send)
            return
        if scope["type"] != "http":
            return
        checked_route = self._check_request(scope)
        if isinstance(checked_route, GuardRefusal):
            await send_rejection(send, checked_route.code, checked_route.headers)
            return
        await self._answer(checked_route, scope, receive, send)

    def _check_request(self, scope: Scope) -> GuardedRoute | GuardRefusal:
        """The route the request may reach, or the first check it fails."""
        hosts = list_header_values(scope, b"host")
        if len(hosts) != 1 or hosts[0].lower() not in self._served_hosts:
            return GuardRefusal(HttpRejectionCode.HOST_NOT_ALLOWED)
        origins = list_header_values(scope, b"origin")
        if len(origins) > 1 or (origins and origins[0].lower() not in self._served_origins):
            return GuardRefusal(HttpRejectionCode.ORIGIN_NOT_ALLOWED)
        route = self._find_route(scope)
        is_open_route = route is not None and route.is_open
        if not is_open_route and not carries_token(scope, self._token):
            return GuardRefusal(HttpRejectionCode.UNAUTHORIZED, ((b"www-authenticate", b"Bearer"),))
        if route is None:
            return GuardRefusal(HttpRejectionCode.NOT_FOUND)
        if scope["method"] not in route.methods:
            allowed_methods = ", ".join(sorted(route.methods)).encode()
            return GuardRefusal(
                HttpRejectionCode.METHOD_NOT_ALLOWED, ((b"allow", allowed_methods),)
            )
        declared_length = read_declared_length(scope)
        if isinstance(declared_length, HttpRejectionCode):
            return GuardRefusal(declared_length)
        if declared_length is not None and declared_length > route.body_cap_bytes:
            return GuardRefusal(HttpRejectionCode.BODY_TOO_LARGE)
        return route

    def _find_route(self, scope: Scope) -> GuardedRoute | None:
        """The route the request target names byte for byte, never normalized: its whole
        path, or for a route that takes a path segment, its path up to and including the
        last ``/`` followed by a segment that is not empty. A target with a query string
        names none."""
        if scope["query_string"]:
            return None
        raw_path: bytes = scope["raw_path"]
        exact_route = self._routes.get(raw_path)
        if exact_route is not None and not exact_route.takes_path_segment:
            return exact_route
        route_path, separator, path_segment = raw_path.rpartition(b"/")
        segment_route = self._routes.get(route_path + separator)
        if segment_route is None or not segment_route.takes_path_segment or not path_segment:
            return None
        return segment_route

    async def _answer(
        self, route: GuardedRoute, scope: Scope, receive: Receive, send: Send
    ) -> None:
        """Read the body and run the route in a task; answer 504 when the deadline passes
        first, then cancel it, so the answer never waits for a route that ignores
        cancellation."""
        route_run = RouteRun()
        async with anyio.create_task_group() as task_group:
            task_group.start_soon(run_route, route, scope, receive, route_run)
            with anyio.move_on_after(self._request_deadline_seconds):
                await route_run.finished.wait()
            if not route_run.finished.is_set():
                await send_rejection(send, HttpRejectionCode.DEADLINE_EXCEEDED)
                task_group.cancel_scope.cancel()
                return
        await send_outcome(send, route_run.outcome)


async def run_route(
    route: GuardedRoute, scope: Scope, receive: Receive, route_run: RouteRun
) -> None:
    """Read the body within the route's cap and record the route's answer to it; a route
    that raises, or returns without a complete answer, comes to ``internal_error``."""
    try:
        body = await read_body(receive, route.body_cap_bytes)
        if isinstance(body, bytes):
            recorded_response = RecordedResponse()
            await route.app(scope, ReplayedReceive(body, receive), recorded_response.record)
            if recorded_response.start is None or not recorded_response.is_complete:
                route_run.outcome = HttpRejectionCode.INTERNAL_ERROR
            else:
                route_run.outcome = recorded_response
        else:
            route_run.outcome = body
    except Exception:
        logging.getLogger(__name__).error("an http route failed", exc_info=True)
        route_run.outcome = HttpRejectionCode.INTERNAL_ERROR
    route_run.finished.set()


async def send_outcome(send: Send, outcome: RouteOutcome) -> None:
    """Send what running the route came to; nothing when the client went away."""
    if isinstance(outcome, RecordedResponse):
        await send_recorded_response(send, outcome)
    elif outcome is not None:
        await send_rejection(send, outcome)
