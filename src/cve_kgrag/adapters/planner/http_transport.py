"""One JSON POST to a model endpoint under one deadline, on ``http.client``.

``http.client`` reads no proxy setting from the environment and follows no redirect, so a
request goes to the URL it is given and nowhere else; a 3xx comes back as a status.
Connecting (name resolution, TCP and the TLS handshake) and sending run under the socket
timeout, the whole timeout for each address tried. Once the request is sent, a watchdog
shuts the socket down at the deadline, so no endpoint can hold the reads past it, however
slowly it sends its status line, headers or body. A body is read only for a 200, and never
past ``MAX_RESPONSE_BYTES``. Nothing here logs, and no failure carries a header, a body or
an exception's text.
"""

import http.client
import socket
import ssl
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import SplitResult, urlsplit

from cve_kgrag.domain.planning import ModelReplyFailureDetail

MAX_RESPONSE_BYTES = 1_048_576
READ_CHUNK_BYTES = 65_536
OK_STATUS = 200


@dataclass(frozen=True)
class HttpAnswer:
    """The endpoint's status, and its body when the status is 200 (empty otherwise)."""

    status: int
    body: bytes


class PostJson(Protocol):
    """Sends ``body`` to ``url`` and answers within ``timeout_seconds``; never raises."""

    def __call__(
        self, *, url: str, headers: Mapping[str, str], body: bytes, timeout_seconds: float
    ) -> HttpAnswer | ModelReplyFailureDetail: ...


def open_connection(url_parts: SplitResult, timeout_seconds: float) -> http.client.HTTPConnection:
    """An unopened connection to the URL's host and port (the scheme's default when none
    is written, so ``http.client`` never reads a port out of an IPv6 host): TLS with
    certificate and host name checks for https, plain only for the http a setting allows
    (a loopback host). Raises ``ValueError`` for a URL without a host, which no accepted
    setting gives."""
    host = url_parts.hostname
    if host is None:
        raise ValueError("the URL names no host")
    if url_parts.scheme == "https":
        https_port = url_parts.port if url_parts.port is not None else http.client.HTTPS_PORT
        return http.client.HTTPSConnection(
            host, https_port, timeout=timeout_seconds, context=ssl.create_default_context()
        )
    http_port = url_parts.port if url_parts.port is not None else http.client.HTTP_PORT
    return http.client.HTTPConnection(host, http_port, timeout=timeout_seconds)


def shut_down_at_deadline(
    endpoint_socket: socket.socket, deadline_reached: threading.Event
) -> None:
    """The watchdog's action: record that the deadline came, and shut the socket down,
    which wakes whatever read is blocked on it, however many reads ``http.client`` makes
    for one status line, header block, interim response or chunk."""
    deadline_reached.set()
    try:
        endpoint_socket.shutdown(socket.SHUT_RDWR)
    except OSError:  # the call ended and closed the socket first; nothing is left to stop
        return


def read_capped_body(response: http.client.HTTPResponse) -> HttpAnswer | ModelReplyFailureDetail:
    """The 200 response's body, or ``MALFORMED_RESPONSE`` past ``MAX_RESPONSE_BYTES``."""
    chunks: list[bytes] = []
    body_size = 0
    # A response that has delivered its declared length closes, and its socket with it.
    while not response.isclosed():
        chunk = response.read1(READ_CHUNK_BYTES)
        if not chunk:
            break
        body_size += len(chunk)
        if body_size > MAX_RESPONSE_BYTES:
            return ModelReplyFailureDetail.MALFORMED_RESPONSE
        chunks.append(chunk)
    return HttpAnswer(status=OK_STATUS, body=b"".join(chunks))


def read_answer(connection: http.client.HTTPConnection) -> HttpAnswer | ModelReplyFailureDetail:
    """The status, with the body only for a 200: any other body is never read."""
    response = connection.getresponse()
    if response.status != OK_STATUS:
        return HttpAnswer(status=response.status, body=b"")
    return read_capped_body(response)


def exchange(
    connection: http.client.HTTPConnection,
    path: str,
    headers: Mapping[str, str],
    body: bytes,
    deadline: float,
) -> HttpAnswer | ModelReplyFailureDetail:
    """Send the request, then read the answer under a watchdog that shuts the socket down
    at ``deadline``; ``TIMED_OUT`` whenever the deadline came, whatever the reads gave."""
    deadline_reached = threading.Event()
    watchdog: threading.Timer | None = None
    try:
        connection.request("POST", path, body=body, headers=dict(headers))
        endpoint_socket = connection.sock
        seconds_left = deadline - time.monotonic()
        if endpoint_socket is None or seconds_left <= 0:
            return ModelReplyFailureDetail.TIMED_OUT
        watchdog = threading.Timer(
            seconds_left, shut_down_at_deadline, (endpoint_socket, deadline_reached)
        )
        watchdog.daemon = True
        watchdog.start()
        endpoint_answer = read_answer(connection)
    except TimeoutError:
        return ModelReplyFailureDetail.TIMED_OUT
    except (OSError, http.client.HTTPException, ValueError):
        endpoint_answer = ModelReplyFailureDetail.UNREACHABLE
    finally:
        if watchdog is not None:
            watchdog.cancel()
    if deadline_reached.is_set():
        return ModelReplyFailureDetail.TIMED_OUT
    return endpoint_answer


def post_json(
    *, url: str, headers: Mapping[str, str], body: bytes, timeout_seconds: float
) -> HttpAnswer | ModelReplyFailureDetail:
    """POST ``body`` to ``url``: the status, with the body of a 200, or ``TIMED_OUT`` or
    ``UNREACHABLE``. ``url`` is an endpoint the settings accepted (``check_endpoint_url``)
    joined with a route."""
    deadline = time.monotonic() + timeout_seconds
    url_parts = urlsplit(url)
    try:
        connection = open_connection(url_parts, timeout_seconds)
    except (OSError, ValueError, http.client.HTTPException):  # the trust store, or no host
        return ModelReplyFailureDetail.UNREACHABLE
    try:
        return exchange(connection, url_parts.path, headers, body, deadline)
    finally:
        connection.close()
