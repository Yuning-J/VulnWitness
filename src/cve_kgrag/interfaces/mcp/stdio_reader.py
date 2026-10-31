"""Stop a blocked stdin reader without cancelling the transport's stdout writer."""

import anyio


class StdioReader(anyio.AsyncFile[str]):
    """A cancellable read boundary over either process stdin or an injected source."""

    def __init__(self, source: anyio.AsyncFile[str]) -> None:
        super().__init__(source.wrapped)
        self._source = source
        self._stopped = False
        self._read_scope: anyio.CancelScope | None = None

    async def readline(self) -> str:
        if self._stopped:
            return ""
        with anyio.CancelScope() as read_scope:
            self._read_scope = read_scope
            try:
                return await self._source.readline()
            finally:
                self._read_scope = None
        return ""

    def stop(self) -> None:
        """End iteration, including a read currently waiting for more client input."""
        self._stopped = True
        if self._read_scope is not None:
            self._read_scope.cancel()
