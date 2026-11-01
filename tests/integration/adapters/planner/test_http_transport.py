"""``post_json`` against loopback servers: the path on the wire, one total deadline, capped
reads, unread error bodies, no redirect and no proxy from the environment."""

import time
import urllib.request
from urllib.parse import urlsplit

import pytest

from tests.support.fake_chat_server import FakeChatServers, ScriptedAnswer
from vulnwitness.adapters.planner.http_transport import (
    MAX_RESPONSE_BYTES,
    HttpAnswer,
    open_connection,
    post_json,
)
from vulnwitness.domain.planning import ModelReplyFailureDetail

REQUEST_BODY = b'{"model": "example-chat"}'
REQUEST_HEADERS = {"Content-Type": "application/json", "Authorization": "Bearer sk-test-key"}
# How far past its timeout a call may return: thread scheduling and one socket wake-up.
DEADLINE_MARGIN_SECONDS = 0.5


def send(url: str, timeout_seconds: float = 5.0) -> HttpAnswer | ModelReplyFailureDetail:
    return post_json(
        url=url, headers=REQUEST_HEADERS, body=REQUEST_BODY, timeout_seconds=timeout_seconds
    )


@pytest.mark.parametrize(
    ("base_path", "expected_path"),
    [("/v1", "/v1/chat/completions"), ("/v1/", "/v1//chat/completions")],
    ids=["configured_v1", "configured_v1_with_a_second_trailing_slash"],
)
def test_request_reaches_exactly_the_joined_path_with_its_headers_and_body(
    fake_chat_servers: FakeChatServers, base_path: str, expected_path: str
) -> None:
    server = fake_chat_servers.start(ScriptedAnswer(body=b'{"choices": []}'))

    answer = send(f"{server.base_url}{base_path}/chat/completions")

    received_request = server.received_requests[0]
    assert answer == HttpAnswer(status=200, body=b'{"choices": []}')
    assert received_request.path == expected_path
    assert received_request.body == REQUEST_BODY
    assert received_request.headers["Authorization"] == "Bearer sk-test-key"


def test_redirect_is_answered_as_its_status_and_never_followed(
    fake_chat_servers: FakeChatServers,
) -> None:
    redirect_target = fake_chat_servers.start(ScriptedAnswer(body=b"{}"))
    redirecting_server = fake_chat_servers.start(
        ScriptedAnswer(status=302, location=f"{redirect_target.base_url}/stolen")
    )

    answer = send(f"{redirecting_server.base_url}/v1/chat/completions")

    assert answer == HttpAnswer(status=302, body=b"")
    assert redirect_target.received_requests == []


def test_error_status_body_is_never_read(fake_chat_servers: FakeChatServers) -> None:
    """The endpoint sends a 401's headers and then nothing: a client reading the body
    would wait out its deadline instead of answering at once."""
    server = fake_chat_servers.start(ScriptedAnswer(status=401, drips=True, drip_seconds=0.0))

    answer = send(f"{server.base_url}/v1/chat/completions", timeout_seconds=1.0)

    assert answer == HttpAnswer(status=401, body=b"")


def test_body_over_the_cap_is_malformed(fake_chat_servers: FakeChatServers) -> None:
    server = fake_chat_servers.start(ScriptedAnswer(body=b" " * (MAX_RESPONSE_BYTES + 1)))

    answer = send(f"{server.base_url}/v1/chat/completions")

    assert answer is ModelReplyFailureDetail.MALFORMED_RESPONSE


@pytest.mark.parametrize(
    "answer_script",
    [
        ScriptedAnswer(waits_for_release=True),
        ScriptedAnswer(drips=True),
        ScriptedAnswer(drips=True, drip_seconds=0.8),
    ],
    ids=["never_answers", "drips_a_blank_line_now_and_then", "drips_then_stalls"],
)
def test_endpoint_that_holds_the_call_times_out_at_the_deadline(
    fake_chat_servers: FakeChatServers, answer_script: ScriptedAnswer
) -> None:
    """The stalling case reads for most of the timeout first, so a read that kept the
    timeout it started with would return well past the deadline."""
    server = fake_chat_servers.start(answer_script)

    started_at = time.monotonic()
    answer = send(f"{server.base_url}/v1/chat/completions", timeout_seconds=1.0)
    elapsed_seconds = time.monotonic() - started_at

    assert answer is ModelReplyFailureDetail.TIMED_OUT
    assert elapsed_seconds < 1.0 + DEADLINE_MARGIN_SECONDS


@pytest.mark.parametrize(
    "answer_script",
    [
        ScriptedAnswer(raw_drip=b"H"),
        ScriptedAnswer(raw=b"HTTP/1.1 200 OK\r\n", raw_drip=b"X"),
        ScriptedAnswer(raw_drip=b"HTTP/1.1 100 Continue\r\n\r\n"),
        ScriptedAnswer(
            raw=b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n",
            raw_drip=b"X: y\r\n",
        ),
    ],
    ids=[
        "status_line_byte_by_byte",
        "header_line_byte_by_byte",
        "endless_100_continue",
        "endless_chunk_trailers",
    ],
)
def test_endpoint_that_never_finishes_a_response_line_times_out_at_the_deadline(
    fake_chat_servers: FakeChatServers, answer_script: ScriptedAnswer
) -> None:
    """``http.client`` reads a status line, a header block, interim responses and chunk
    trailers in many reads; each fragment arrives in time, so only a deadline over all of
    them ends the call."""
    server = fake_chat_servers.start(answer_script)

    started_at = time.monotonic()
    answer = send(f"{server.base_url}/v1/chat/completions", timeout_seconds=1.0)
    elapsed_seconds = time.monotonic() - started_at

    assert answer is ModelReplyFailureDetail.TIMED_OUT
    assert elapsed_seconds < 1.0 + DEADLINE_MARGIN_SECONDS


@pytest.mark.parametrize(
    "raw_response",
    [
        b"NOT-HTTP\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n" + b"X-Header: 1\r\n" * 101 + b"\r\n",
    ],
    ids=["not_a_status_line", "more_than_100_headers"],
)
def test_response_that_is_not_http_is_unreachable(
    fake_chat_servers: FakeChatServers, raw_response: bytes
) -> None:
    server = fake_chat_servers.start(ScriptedAnswer(raw=raw_response))

    answer = send(f"{server.base_url}/v1/chat/completions")

    assert answer is ModelReplyFailureDetail.UNREACHABLE


def test_closed_port_is_unreachable(fake_chat_servers: FakeChatServers) -> None:
    server = fake_chat_servers.start(ScriptedAnswer())
    closed_url = f"{server.base_url}/v1/chat/completions"
    fake_chat_servers.stop_all()

    answer = send(closed_url)

    assert answer is ModelReplyFailureDetail.UNREACHABLE


def test_proxy_settings_in_the_environment_are_never_used(
    fake_chat_servers: FakeChatServers, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The environment is what a proxy-honouring client reads, so it is this test's input.
    A request through urllib's default opener reaches the proxy, so the test can fail."""
    target = fake_chat_servers.start(ScriptedAnswer(body=b"{}"))
    proxy = fake_chat_servers.start(ScriptedAnswer(body=b"{}"))
    for variable_name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        monkeypatch.setenv(variable_name, proxy.base_url)
    for variable_name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(variable_name, raising=False)
    target_url = f"{target.base_url}/v1/chat/completions"
    urllib.request.build_opener().open(
        urllib.request.Request(target_url, data=REQUEST_BODY), timeout=5
    ).close()
    proxy_requests_before = len(proxy.received_requests)

    answer = send(target_url)

    assert proxy_requests_before == 1
    assert answer == HttpAnswer(status=200, body=b"{}")
    assert len(proxy.received_requests) == 1
    assert len(target.received_requests) == 1


@pytest.mark.parametrize(
    ("url", "expected_host", "expected_port"),
    [
        ("http://[::1]/v1/chat/completions", "::1", 80),
        ("https://[2001:db8::abcd]/v1/chat/completions", "2001:db8::abcd", 443),
        ("https://[2001:db8::1:443]/v1/chat/completions", "2001:db8::1:443", 443),
        ("https://[::1]:8443/v1/chat/completions", "::1", 8443),
    ],
    ids=["ipv6_loopback_http", "ipv6_https_hex_tail", "ipv6_https_port_like_tail", "ipv6_port"],
)
def test_ipv6_host_keeps_its_address_and_gets_the_scheme_s_port(
    url: str, expected_host: str, expected_port: int
) -> None:
    """``http.client`` reads a port out of a host it is given without one; the connection
    is always given the port, so the configured address is the one connected to."""
    connection = open_connection(urlsplit(url), timeout_seconds=1.0)

    assert (connection.host, connection.port) == (expected_host, expected_port)
