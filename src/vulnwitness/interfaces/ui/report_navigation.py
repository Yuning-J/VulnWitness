"""Authorize a top-level report navigation without a cookie or query-string token."""

import hmac
from dataclasses import dataclass
from urllib.parse import parse_qs

from pydantic import SecretStr
from starlette.types import Receive, Scope, Send

from vulnwitness.domain.http_rejection import HttpRejectionCode
from vulnwitness.interfaces.http.guard import ReplayedReceive, read_route_body, send_rejection
from vulnwitness.interfaces.ui.api_route import UiApiRoute
from vulnwitness.interfaces.ui.state import UiState


@dataclass(frozen=True)
class ReportNavigationRoute:
    """The guard checks Host, Origin and the body cap before this read-only form POST.

    A browser navigation cannot attach Authorization. Its per-launch token is instead
    carried in the bounded form body; it never appears in a cookie or request target.
    """

    state: UiState
    token: SecretStr

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        body = await read_route_body(receive)
        try:
            fields = parse_qs(body.decode("ascii"), strict_parsing=True, max_num_fields=1)
        except (ValueError, UnicodeError):
            fields = {}
        tokens = fields.get("token", [])
        if len(tokens) != 1 or not hmac.compare_digest(
            tokens[0].encode(), self.token.get_secret_value().encode()
        ):
            await send_rejection(
                send, HttpRejectionCode.UNAUTHORIZED, ((b"www-authenticate", b"Bearer"),)
            )
            return
        await UiApiRoute(self.state, "report")(scope, ReplayedReceive(b"", receive), send)
