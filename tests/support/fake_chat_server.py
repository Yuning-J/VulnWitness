"""A loopback HTTP server standing in for an OpenAI-compatible chat-completions endpoint.

It binds 127.0.0.1 on a free port, answers every POST as its ``ScriptedAnswer`` says, and
records what it received. It is the only network a test touches, and only in-process.
"""

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The seconds between two blank lines a dripping answer sends.
DRIP_INTERVAL_SECONDS = 0.05


@dataclass(frozen=True)
class RecordedRequest:
    path: str
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True)
class ScriptedAnswer:
    """What the server answers: ``status`` with ``body``; ``location`` as a Location
    header; ``raw`` written instead of any HTTP response; ``waits_for_release`` blocks
    before answering until the server is released; ``drips`` sends a 200's headers, then a
    blank line every ``DRIP_INTERVAL_SECONDS`` until released, or only for
    ``drip_seconds`` and then nothing until released; ``raw_drip`` writes ``raw`` (if
    any), then this fragment every ``DRIP_INTERVAL_SECONDS`` until released, as an endpoint
    that never finishes its status line, headers or chunks would; ``echoes_authorization``
    puts the received Authorization header in the body as a message's content."""

    status: int = 200
    body: bytes = b""
    location: str | None = None
    raw: bytes | None = None
    raw_drip: bytes | None = None
    waits_for_release: bool = False
    drips: bool = False
    drip_seconds: float | None = None
    echoes_authorization: bool = False


def build_completion_body(content: str) -> bytes:
    """A chat completion whose first choice's message holds ``content``."""
    completion = {
        "id": "fake",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
    }
    return json.dumps(completion).encode()


class FakeChatServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, answer: ScriptedAnswer) -> None:
        super().__init__(("127.0.0.1", 0), FakeChatHandler)
        self.answer = answer
        self.received_requests: list[RecordedRequest] = []
        self.release = threading.Event()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server_port}"

    def handle_error(self, request: object, client_address: object) -> None:
        """A client that stops reading (a capped or abandoned read) is expected here."""


class FakeChatHandler(BaseHTTPRequestHandler):
    server: FakeChatServer

    def log_message(self, format: str, *args: object) -> None:
        """The server writes nothing to stderr."""

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        received_headers: dict[str, str] = {}
        for header_name, header_value in self.headers.items():
            received_headers[header_name] = header_value
        self.server.received_requests.append(RecordedRequest(self.path, received_headers, body))
        self.answer_as_scripted(received_headers)

    def do_GET(self) -> None:
        self.server.received_requests.append(RecordedRequest(self.path, {}, b""))
        self.answer_as_scripted({})

    def drip_until_released(self, drip_seconds: float | None) -> None:
        """A blank line every ``DRIP_INTERVAL_SECONDS`` until released, or for
        ``drip_seconds`` and then nothing until released."""
        drips_left = None
        if drip_seconds is not None:
            drips_left = round(drip_seconds / DRIP_INTERVAL_SECONDS)
        while not self.server.release.wait(DRIP_INTERVAL_SECONDS):
            if drips_left == 0:
                self.server.release.wait()
                return
            self.wfile.write(b"\n")
            self.wfile.flush()
            if drips_left is not None:
                drips_left -= 1

    def answer_as_scripted(self, received_headers: dict[str, str]) -> None:
        answer = self.server.answer
        if answer.waits_for_release:
            self.server.release.wait()
        if answer.raw is not None:
            self.wfile.write(answer.raw)
            self.wfile.flush()
        if answer.raw_drip is not None:
            while not self.server.release.wait(DRIP_INTERVAL_SECONDS):
                self.wfile.write(answer.raw_drip)
                self.wfile.flush()
            return
        if answer.raw is not None:
            return
        body = answer.body
        if answer.echoes_authorization:
            body = build_completion_body(received_headers.get("Authorization", ""))
        self.send_response(answer.status)
        if answer.location is not None:
            self.send_header("Location", answer.location)
        self.send_header("Content-Type", "application/json")
        if answer.drips:
            self.end_headers()
            self.drip_until_released(answer.drip_seconds)
            return
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@dataclass
class FakeChatServers:
    """Starts fake servers and stops every one it started."""

    started_servers: list[FakeChatServer] = field(default_factory=list)

    def start(self, answer: ScriptedAnswer) -> FakeChatServer:
        server = FakeChatServer(answer)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.started_servers.append(server)
        return server

    def stop_all(self) -> None:
        for server in self.started_servers:
            server.release.set()
            server.shutdown()
            server.server_close()
