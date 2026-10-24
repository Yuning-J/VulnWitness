"""The routes that tell whether a server is up and whether it can take a call now."""

from collections.abc import Callable
from dataclasses import dataclass

from starlette.types import Receive, Scope, Send

from cve_kgrag.domain.http_rejection import HttpRejectionCode
from cve_kgrag.interfaces.http.guard import send_rejection


async def send_no_content(send: Send) -> None:
    await send({"type": "http.response.start", "status": 204, "headers": []})
    await send({"type": "http.response.body", "body": b""})


async def answer_health(scope: Scope, receive: Receive, send: Send) -> None:
    """``/health``: 204 and no body while the process serves at all."""
    await send_no_content(send)


@dataclass(frozen=True)
class ReadinessRoute:
    """``/ready``: 204 while ``is_ready`` says the server can take a call now, else 503
    ``not_ready``."""

    is_ready: Callable[[], bool]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not self.is_ready():
            await send_rejection(send, HttpRejectionCode.NOT_READY)
            return
        await send_no_content(send)
