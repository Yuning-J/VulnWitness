"""Only fixed packaged assets are public; no request path grants file authority."""

from dataclasses import dataclass
from importlib.resources import files

from starlette.responses import Response
from starlette.types import Receive, Scope, Send

UI_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


@dataclass(frozen=True)
class StaticRoute:
    filename: str
    media_type: str

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        content = files("vulnwitness.interfaces.ui").joinpath("static", self.filename).read_bytes()
        await Response(
            content,
            media_type=self.media_type,
            headers={"Content-Security-Policy": UI_CSP, "Referrer-Policy": "no-referrer"},
        )(scope, receive, send)
