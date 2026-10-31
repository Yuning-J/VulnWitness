"""Announce HTTP readiness only once uvicorn has started serving."""

import socket
import sys

import uvicorn


class ServingServer(uvicorn.Server):
    """A uvicorn server whose ready notice follows successful socket startup."""

    def __init__(self, config: uvicorn.Config, command: str) -> None:
        super().__init__(config)
        self._command = command

    async def startup(self, sockets: list[socket.socket] | None = None) -> None:
        await super().startup(sockets)
        if self.started:
            host = self.config.host
            url_host = f"[{host}]" if ":" in host else host
            port = self.servers[0].sockets[0].getsockname()[1]
            print(
                f"cve-kgrag {self._command}: ready on http://{url_host}:{port}",
                file=sys.stderr,
                flush=True,
            )
