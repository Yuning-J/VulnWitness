"""Print the fragment token after binding; stop with failure when loading fails."""

import socket
import sys

import uvicorn

from vulnwitness.interfaces.ui.state import UiState


class UiServer(uvicorn.Server):
    """HTTP acceptance announces the UI; dataset publication is a separate signal."""

    def __init__(self, config: uvicorn.Config, state: UiState, launch_token: str) -> None:
        super().__init__(config)
        self._state = state
        self._launch_token = launch_token

    async def startup(self, sockets: list[socket.socket] | None = None) -> None:
        await super().startup(sockets)
        if self.started:
            print(
                f"vulnwitness ui: http://127.0.0.1:{self.config.port}/#token={self._launch_token}",
                file=sys.stderr,
                flush=True,
            )

    async def on_tick(self, counter: int) -> bool:
        return self._state.failed or await super().on_tick(counter)
