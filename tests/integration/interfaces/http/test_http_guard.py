"""The HTTP guard refuses what ADR 0007 refuses, in its order and in its own words: Host,
Origin, the token, the route, the method and the declared length before any body is
read; the body counted against the route's cap; the deadline over reading and running."""

import threading
from collections.abc import Sequence

import anyio
import pytest
from starlette.types import ASGIApp, Receive, Scope, Send

from cve_kgrag.domain.http_rejection import (
    HTTP_REJECTION_MESSAGES,
    HttpRejection,
    HttpRejectionCode,
)
from cve_kgrag.interfaces.http.guard import (
    REJECTION_STATUSES,
    SECURITY_HEADERS,
    GuardedRoute,
    HttpGuard,
)
from cve_kgrag.interfaces.http.status_routes import ReadinessRoute, answer_health
from tests.support.asgi import (
    HTTP_HOST,
    HTTP_PORT,
    HTTP_SECRET_TOKEN,
    HTTP_TOKEN,
    SERVED_HOST_HEADER,
    TOKEN_HEADER,
    AnsweringRoute,
    AsgiAnswer,
    AsgiRequest,
    RequestExchange,
    ThreadBlockedRoute,
    answer_never,
    answer_nothing,
    answer_partly,
    build_http_scope,
    raise_an_error,
    running_lifespan,
    send_request,
)

pytestmark = pytest.mark.anyio

# The status of each rejection, as ADR 0007 and the m6 doc publish them.
EXPECTED_STATUSES = {
    HttpRejectionCode.INVALID_REQUEST: 400,
    HttpRejectionCode.UNAUTHORIZED: 401,
    HttpRejectionCode.ORIGIN_NOT_ALLOWED: 403,
    HttpRejectionCode.NOT_FOUND: 404,
    HttpRejectionCode.METHOD_NOT_ALLOWED: 405,
    HttpRejectionCode.BODY_TOO_LARGE: 413,
    HttpRejectionCode.HOST_NOT_ALLOWED: 421,
    HttpRejectionCode.INTERNAL_ERROR: 500,
    HttpRejectionCode.NOT_READY: 503,
    HttpRejectionCode.DEADLINE_EXCEEDED: 504,
}
BODY_CAP_BYTES = 1024
DEADLINE_SECONDS = 0.2
# How long a test waits for something that happens at once; far longer than any deadline.
GENEROUS_WAIT_SECONDS = 10.0
JSON_HEADERS = (SERVED_HOST_HEADER, TOKEN_HEADER, (b"content-type", b"application/json"))


def build_guard(
    route_app: ASGIApp,
    *,
    host: str = HTTP_HOST,
    port: int = HTTP_PORT,
    deadline_seconds: float = GENEROUS_WAIT_SECONDS,
    lifespan_app: ASGIApp = answer_nothing,
) -> HttpGuard:
    """A guard over ``route_app`` at ``POST /tools``, ``/health`` and a ready ``/ready``."""
    return HttpGuard(
        routes={
            "/tools": GuardedRoute(
                methods=frozenset({"POST"}), app=route_app, body_cap_bytes=BODY_CAP_BYTES
            ),
            "/health": GuardedRoute(methods=frozenset({"GET"}), app=answer_health, is_open=True),
            "/ready": GuardedRoute(methods=frozenset({"GET"}), app=ReadinessRoute(lambda: True)),
        },
        lifespan_app=lifespan_app,
        host=host,
        port=port,
        token=HTTP_SECRET_TOKEN,
        request_deadline_seconds=deadline_seconds,
    )


def post_tools(
    headers: Sequence[tuple[bytes, bytes]] = JSON_HEADERS,
    body_parts: Sequence[bytes] = (b"{}",),
    target: bytes = b"/tools",
) -> AsgiRequest:
    return AsgiRequest(method="POST", target=target, headers=headers, body_parts=body_parts)


def assert_rejected(answer: AsgiAnswer, code: HttpRejectionCode) -> None:
    """The answer is the rejection of ``code`` with its status and the security headers."""
    assert answer.status == EXPECTED_STATUSES[code]
    assert HttpRejection.model_validate_json(answer.body).code is code
    for header in SECURITY_HEADERS:
        assert header in answer.headers


@pytest.mark.parametrize(
    "host_headers",
    [
        [],
        [(b"host", b"evil.example:8765")],
        [(b"host", b"127.0.0.1")],
        [(b"host", b"127.0.0.1:8766")],
        [(b"host", b"127.1:8765")],
        [(b"host", b"[::1]:8765")],
        [(b"host", b"localhost.:8765")],
        [(b"host", b"a@127.0.0.1:8765")],
        [SERVED_HOST_HEADER, SERVED_HOST_HEADER],
    ],
    ids=[
        "missing",
        "rebinding_name",
        "no_port",
        "other_port",
        "short_form_address",
        "other_family",
        "trailing_dot",
        "user_information",
        "repeated",
    ],
)
async def test_request_naming_a_host_the_server_does_not_serve_is_refused_421(
    host_headers: list[tuple[bytes, bytes]],
) -> None:
    route = AnsweringRoute()

    answer = await send_request(
        build_guard(route), post_tools(headers=[*host_headers, TOKEN_HEADER])
    )

    assert_rejected(answer, HttpRejectionCode.HOST_NOT_ALLOWED)
    assert route.received_bodies == []


@pytest.mark.parametrize(
    ("host", "port", "host_header"),
    [
        ("127.0.0.1", 8765, b"127.0.0.1:8765"),
        ("127.0.0.1", 8765, b"LOCALHOST:8765"),
        ("::1", 8765, b"[::1]:8765"),
        ("::1", 8765, b"localhost:8765"),
        ("127.0.0.1", 80, b"127.0.0.1"),
    ],
    ids=["address", "name_in_capitals", "ipv6_address", "name_on_ipv6", "default_port"],
)
async def test_request_naming_a_served_host_reaches_the_route(
    host: str, port: int, host_header: bytes
) -> None:
    route = AnsweringRoute()
    headers = [(b"host", host_header), TOKEN_HEADER]

    answer = await send_request(build_guard(route, host=host, port=port), post_tools(headers))

    assert answer.status == 200
    assert route.received_bodies == [b"{}"]


@pytest.mark.parametrize(
    "origin_headers",
    [
        [(b"origin", b"http://evil.example")],
        [(b"origin", b"null")],
        [(b"origin", b"http://127.0.0.1:3000")],
        [(b"origin", b"https://127.0.0.1:8765")],
        [(b"origin", b"http://127.0.0.1:8765"), (b"origin", b"http://127.0.0.1:8765")],
    ],
    ids=["other_site", "null", "other_port", "https", "repeated"],
)
async def test_request_from_an_origin_other_than_the_server_s_own_is_refused_403(
    origin_headers: list[tuple[bytes, bytes]],
) -> None:
    route = AnsweringRoute()

    answer = await send_request(
        build_guard(route), post_tools(headers=[*JSON_HEADERS, *origin_headers])
    )

    assert_rejected(answer, HttpRejectionCode.ORIGIN_NOT_ALLOWED)
    assert route.received_bodies == []


async def test_request_from_the_server_s_own_origin_reaches_the_route() -> None:
    route = AnsweringRoute()
    headers = [*JSON_HEADERS, (b"origin", b"http://localhost:8765")]

    answer = await send_request(build_guard(route), post_tools(headers))

    assert answer.status == 200


@pytest.mark.parametrize(
    "authorization_headers",
    [
        [],
        [(b"authorization", HTTP_TOKEN.encode())],
        [(b"authorization", b"Basic " + HTTP_TOKEN.encode())],
        [(b"authorization", b"Bearer  " + HTTP_TOKEN.encode())],
        [(b"authorization", b"Bearer " + HTTP_TOKEN[:-1].encode())],
        [(b"authorization", b"Bearer " + HTTP_TOKEN.encode() + b"x")],
        [(b"authorization", b"Bearer \xff\xfe")],
        [TOKEN_HEADER, TOKEN_HEADER],
    ],
    ids=[
        "missing",
        "no_scheme",
        "basic_scheme",
        "two_spaces",
        "prefix",
        "suffix",
        "not_ascii",
        "repeated",
    ],
)
async def test_request_without_exactly_the_token_is_refused_401_with_one_answer(
    authorization_headers: list[tuple[bytes, bytes]],
) -> None:
    route = AnsweringRoute()
    headers = [SERVED_HOST_HEADER, *authorization_headers]

    answer = await send_request(build_guard(route), post_tools(headers))

    assert_rejected(answer, HttpRejectionCode.UNAUTHORIZED)
    assert answer.list_header_values(b"www-authenticate") == [b"Bearer"]
    assert route.received_bodies == []


@pytest.mark.parametrize("scheme", [b"bearer", b"BEARER"], ids=str)
async def test_bearer_scheme_is_read_in_any_case(scheme: bytes) -> None:
    headers = [SERVED_HOST_HEADER, (b"authorization", scheme + b" " + HTTP_TOKEN.encode())]

    answer = await send_request(build_guard(AnsweringRoute()), post_tools(headers))

    assert answer.status == 200


@pytest.mark.parametrize(
    "target",
    [
        b"/tool",
        b"/tools/",
        b"//tools",
        b"/Tools",
        b"/tool%73",
        b"/tools?x=1",
        b"/health/../tools",
        b"http://127.0.0.1:8765/tools",
        b"*",
    ],
    ids=[
        "other_path",
        "trailing_slash",
        "double_slash",
        "other_case",
        "encoded",
        "query",
        "dot_segments",
        "absolute_form",
        "asterisk",
    ],
)
async def test_target_naming_no_route_byte_for_byte_is_401_without_token_and_404_with_it(
    target: bytes,
) -> None:
    route = AnsweringRoute()
    guard = build_guard(route)

    unauthenticated_answer = await send_request(
        guard, AsgiRequest(method="POST", target=target, headers=[SERVED_HOST_HEADER])
    )
    authenticated_answer = await send_request(guard, AsgiRequest(method="POST", target=target))

    assert_rejected(unauthenticated_answer, HttpRejectionCode.UNAUTHORIZED)
    assert_rejected(authenticated_answer, HttpRejectionCode.NOT_FOUND)
    assert route.received_bodies == []


@pytest.mark.parametrize(
    ("method", "target", "allowed"),
    [
        ("GET", b"/tools", b"POST"),
        ("DELETE", b"/tools", b"POST"),
        ("OPTIONS", b"/tools", b"POST"),
        ("HEAD", b"/ready", b"GET"),
        ("POST", b"/ready", b"GET"),
    ],
    ids=["get_tools", "delete_tools", "options_tools", "head_ready", "post_ready"],
)
async def test_method_a_route_does_not_accept_is_refused_405_naming_the_accepted_ones(
    method: str, target: bytes, allowed: bytes
) -> None:
    route = AnsweringRoute()

    answer = await send_request(build_guard(route), AsgiRequest(method=method, target=target))

    assert_rejected(answer, HttpRejectionCode.METHOD_NOT_ALLOWED)
    assert answer.list_header_values(b"allow") == [allowed]
    assert route.received_bodies == []


async def test_method_check_comes_after_the_token() -> None:
    answer = await send_request(
        build_guard(AnsweringRoute()),
        AsgiRequest(method="GET", target=b"/tools", headers=[SERVED_HOST_HEADER]),
    )

    assert_rejected(answer, HttpRejectionCode.UNAUTHORIZED)


async def test_health_answers_204_without_the_token_and_with_no_body() -> None:
    answer = await send_request(
        build_guard(AnsweringRoute()), AsgiRequest(target=b"/health", headers=[SERVED_HOST_HEADER])
    )

    assert answer.status == 204
    assert answer.body == b""
    for header in SECURITY_HEADERS:
        assert header in answer.headers


async def test_health_still_checks_the_host() -> None:
    answer = await send_request(
        build_guard(AnsweringRoute()),
        AsgiRequest(target=b"/health", headers=[(b"host", b"evil.example:8765")]),
    )

    assert_rejected(answer, HttpRejectionCode.HOST_NOT_ALLOWED)


async def test_readiness_needs_the_token_and_answers_204_when_ready() -> None:
    guard = build_guard(AnsweringRoute())

    unauthenticated_answer = await send_request(
        guard, AsgiRequest(target=b"/ready", headers=[SERVED_HOST_HEADER])
    )
    ready_answer = await send_request(guard, AsgiRequest(target=b"/ready"))

    assert_rejected(unauthenticated_answer, HttpRejectionCode.UNAUTHORIZED)
    assert ready_answer.status == 204


async def test_readiness_answers_503_while_the_server_cannot_take_a_call() -> None:
    answer = await send_request(ReadinessRoute(lambda: False), AsgiRequest(target=b"/ready"))

    assert_rejected(answer, HttpRejectionCode.NOT_READY)


@pytest.mark.parametrize(
    "length_headers",
    [
        [(b"content-length", b"2"), (b"content-length", b"2")],
        [(b"content-length", b"+2")],
        [(b"content-length", b"0x2")],
        [(b"content-length", b" 2")],
    ],
    ids=["repeated", "signed", "hexadecimal", "padded"],
)
async def test_length_declared_other_than_one_decimal_number_is_refused_400(
    length_headers: list[tuple[bytes, bytes]],
) -> None:
    route = AnsweringRoute()

    answer = await send_request(
        build_guard(route), post_tools(headers=[*JSON_HEADERS, *length_headers])
    )

    assert_rejected(answer, HttpRejectionCode.INVALID_REQUEST)
    assert answer.body_messages_received == 0


async def test_declared_length_over_the_cap_is_refused_413_before_any_body_is_read() -> None:
    route = AnsweringRoute()
    headers = [*JSON_HEADERS, (b"content-length", str(BODY_CAP_BYTES + 1).encode())]

    answer = await send_request(
        build_guard(route), post_tools(headers, body_parts=(b"x" * (BODY_CAP_BYTES + 1),))
    )

    assert_rejected(answer, HttpRejectionCode.BODY_TOO_LARGE)
    assert answer.body_messages_received == 0
    assert route.received_bodies == []


async def test_undeclared_body_over_the_cap_is_refused_413_once_the_count_passes_it() -> None:
    route = AnsweringRoute()
    body_parts = (b" " * 600, b" " * 600, b" " * 600)

    answer = await send_request(build_guard(route), post_tools(body_parts=body_parts))

    assert_rejected(answer, HttpRejectionCode.BODY_TOO_LARGE)
    assert answer.body_messages_received == 2
    assert route.received_bodies == []


async def test_body_of_exactly_the_cap_reaches_the_route_whole() -> None:
    route = AnsweringRoute()
    body_parts = (b"[" + b" " * 500, b" " * (BODY_CAP_BYTES - 502) + b"]")

    answer = await send_request(build_guard(route), post_tools(body_parts=body_parts))

    assert answer.status == 200
    assert route.received_bodies == [b"".join(body_parts)]


async def test_route_answer_carries_the_security_headers_in_place_of_its_own() -> None:
    answer = await send_request(build_guard(AnsweringRoute()), post_tools())

    assert answer.status == 200
    assert answer.list_header_values(b"cache-control") == [b"no-store"]
    assert answer.list_header_values(b"x-content-type-options") == [b"nosniff"]


async def test_route_that_runs_past_the_deadline_is_answered_504() -> None:
    with anyio.fail_after(GENEROUS_WAIT_SECONDS):
        answer = await send_request(
            build_guard(answer_never, deadline_seconds=DEADLINE_SECONDS), post_tools()
        )

    assert_rejected(answer, HttpRejectionCode.DEADLINE_EXCEEDED)


async def test_body_that_never_arrives_is_answered_504_at_the_deadline() -> None:
    route = AnsweringRoute()
    stalled_request = AsgiRequest(
        method="POST", target=b"/tools", headers=JSON_HEADERS, body_parts=(b"{",), body_stalls=True
    )

    with anyio.fail_after(GENEROUS_WAIT_SECONDS):
        answer = await send_request(
            build_guard(route, deadline_seconds=DEADLINE_SECONDS), stalled_request
        )

    assert_rejected(answer, HttpRejectionCode.DEADLINE_EXCEEDED)
    assert route.received_bodies == []


async def test_deadline_is_answered_while_the_route_s_thread_still_blocks() -> None:
    """The 504 goes out before the route's worker thread returns: the thread is released
    only once the answer has been sent, so a guard waiting for it would never answer."""
    release = threading.Event()
    guard = build_guard(
        ThreadBlockedRoute(release, timeout_seconds=GENEROUS_WAIT_SECONDS),
        deadline_seconds=DEADLINE_SECONDS,
    )
    request = post_tools()
    exchange = RequestExchange(request)

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(guard, build_http_scope(request), exchange.receive, exchange.send)
        with anyio.fail_after(GENEROUS_WAIT_SECONDS):
            await exchange.answer_completed.wait()
        was_blocked_when_answered = not release.is_set()
        release.set()

    assert was_blocked_when_answered
    assert_rejected(exchange.answer, HttpRejectionCode.DEADLINE_EXCEEDED)


async def test_client_that_disconnects_during_the_body_gets_no_answer() -> None:
    route = AnsweringRoute()
    request = AsgiRequest(
        method="POST",
        target=b"/tools",
        headers=JSON_HEADERS,
        body_parts=(b"{",),
        client_disconnects=True,
    )

    answer = await send_request(build_guard(route), request)

    assert answer.status is None
    assert route.received_bodies == []


@pytest.mark.parametrize(
    "route_app",
    [raise_an_error, answer_nothing, answer_partly],
    ids=["raises", "silent", "partial"],
)
async def test_route_that_fails_to_answer_is_answered_500_without_its_error_text(
    route_app: ASGIApp,
) -> None:
    answer = await send_request(build_guard(route_app), post_tools())

    assert_rejected(answer, HttpRejectionCode.INTERNAL_ERROR)
    assert b"secret" not in answer.body


async def test_lifespan_events_reach_the_lifespan_app() -> None:
    lifespan_events: list[str] = []
    guard = build_guard(AnsweringRoute(), lifespan_app=LifespanRecorder(lifespan_events).run)

    async with running_lifespan(guard):
        lifespan_events.append("serving")

    assert lifespan_events == ["started", "serving", "stopped"]


class LifespanRecorder:
    def __init__(self, lifespan_events: list[str]) -> None:
        self._lifespan_events = lifespan_events

    async def run(self, scope: Scope, receive: Receive, send: Send) -> None:
        await receive()
        self._lifespan_events.append("started")
        await send({"type": "lifespan.startup.complete"})
        await receive()
        self._lifespan_events.append("stopped")
        await send({"type": "lifespan.shutdown.complete"})


def test_every_rejection_code_has_its_published_status_and_a_fixed_message() -> None:
    assert REJECTION_STATUSES == EXPECTED_STATUSES
    assert set(HTTP_REJECTION_MESSAGES) == set(HttpRejectionCode)


async def test_no_answer_repeats_what_the_request_sent() -> None:
    """Rejections carry fixed sentences only: a marker in the target, a header or the body
    of a refused request never comes back."""
    marker = b"zzechomarkerzz"
    guard = build_guard(AnsweringRoute())
    refused_requests = [
        AsgiRequest(target=b"/" + marker, headers=[(b"host", marker + b":8765")]),
        AsgiRequest(target=b"/" + marker, headers=[SERVED_HOST_HEADER, (b"origin", marker)]),
        AsgiRequest(target=b"/" + marker, headers=[SERVED_HOST_HEADER, (b"authorization", marker)]),
        AsgiRequest(target=b"/" + marker + b"?" + marker),
        AsgiRequest(method="GET", target=b"/tools?" + marker),
        post_tools(headers=[*JSON_HEADERS, (b"content-length", marker)]),
        post_tools(body_parts=(marker * 100,)),
    ]

    for refused_request in refused_requests:
        answer = await send_request(guard, refused_request)

        assert answer.status is not None and answer.status >= 400
        assert marker not in answer.body
        for _, header_value in answer.headers:
            assert marker not in header_value
