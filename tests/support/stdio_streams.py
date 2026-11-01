"""Stdio boundaries that expose EOF immediately and hold the final stdout flush."""

import asyncio
import threading
from io import StringIO

import anyio

from vulnwitness.interfaces.knowledge_toolbox import KnowledgeToolbox


class ImmediateStdioInput(anyio.AsyncFile[str]):
    """An already closed input source, with no worker or readiness scheduling at EOF."""

    def __init__(self, frames: str, *, before_eof: anyio.Event | None = None) -> None:
        super().__init__(StringIO(frames))
        self._before_eof = before_eof
        self.eof = anyio.Event()

    async def readline(self) -> str:
        line = self.wrapped.readline()
        if not line:
            if self._before_eof is not None:
                await self._before_eof.wait()
            self.eof.set()
        return line


class PausedStdioOutput(anyio.AsyncFile[str]):
    """Keep the last response in flight until the test permits its flush to finish."""

    def __init__(self, response_count: int) -> None:
        self.contents = StringIO()
        super().__init__(self.contents)
        self.flush_started = anyio.Event()
        self.release_flush = anyio.Event()
        self.flush_finished = False
        self._remaining = response_count

    async def flush(self) -> None:
        self._remaining -= 1
        if self._remaining == 0:
            self.flush_started.set()
            await self.release_flush.wait()
            await super().flush()
            self.flush_finished = True
        else:
            await super().flush()


class BlockedToolboxLoader:
    """Keep the real toolbox unpublished for the lifetime of a test connection."""

    def __init__(self, toolbox: KnowledgeToolbox, release: threading.Event) -> None:
        self._toolbox = toolbox
        self._release = release
        self._loop = asyncio.get_running_loop()
        self.started = anyio.Event()
        self.returned = threading.Event()

    def __call__(self) -> KnowledgeToolbox:
        self._loop.call_soon_threadsafe(self.started.set)
        self._release.wait()
        self.returned.set()
        return self._toolbox
