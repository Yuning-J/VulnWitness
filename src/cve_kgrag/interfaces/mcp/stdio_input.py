"""Cancellable stdin reads, so startup failure can stop a connected stdio server."""

import os
import stat
from typing import TextIO

import anyio


class StdioInput(anyio.AsyncFile[str]):
    """Read UTF-8 protocol lines without leaving a worker blocked on the client's pipe."""

    def __init__(self, stream: TextIO) -> None:
        super().__init__(stream)
        self._descriptor = stream.fileno()
        self._pending = b""
        mode = os.fstat(self._descriptor).st_mode
        self._can_wait = stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode) or stream.isatty()

    async def readline(self) -> str:
        while b"\n" not in self._pending:
            if self._can_wait:
                await anyio.wait_readable(self._descriptor)
            chunk = os.read(self._descriptor, 65536)
            if not chunk:
                line = self._pending
                self._pending = b""
                return line.decode("utf-8", errors="replace")
            self._pending += chunk
        line, self._pending = self._pending.split(b"\n", 1)
        return (line + b"\n").decode("utf-8", errors="replace")
