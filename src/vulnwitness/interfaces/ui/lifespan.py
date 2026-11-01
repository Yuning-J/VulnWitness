"""Background loading never delays static pages or keeps an interrupted process alive."""

import asyncio
import logging
import threading
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

import anyio
from starlette.applications import Starlette

from vulnwitness.interfaces.mcp_deployment import McpDeployment
from vulnwitness.interfaces.ui.state import UiState


class UiLifespan:
    """Load off-loop and publish the complete dataset-bound deployment on-loop."""

    def __init__(self, state: UiState, load_deployment: Callable[[], McpDeployment]) -> None:
        self._state = state
        self._load_deployment = load_deployment

    def load_in_background(
        self, loop: asyncio.AbstractEventLoop, loaded: asyncio.Future[McpDeployment | None]
    ) -> None:
        try:
            deployment = self._load_deployment()
        except BaseException:
            logging.getLogger(__name__).error("UI data loading failed")
            deployment = None
        try:
            loop.call_soon_threadsafe(self.finish_loading, loaded, deployment)
        except RuntimeError:
            return  # The server has already stopped.

    def finish_loading(
        self, loaded: asyncio.Future[McpDeployment | None], deployment: McpDeployment | None
    ) -> None:
        if not loaded.done():
            loaded.set_result(deployment)

    async def load(self) -> None:
        loop = asyncio.get_running_loop()
        loaded: asyncio.Future[McpDeployment | None] = loop.create_future()
        threading.Thread(target=self.load_in_background, args=(loop, loaded), daemon=True).start()
        deployment = await loaded
        if deployment is None:
            self._state.failed = True
        else:
            self._state.publish(deployment)

    @asynccontextmanager
    async def __call__(self, app: Starlette) -> AsyncIterator[None]:
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(self.load)
            yield
            tasks.cancel_scope.cancel()
