"""Publication signal shared by transports that serve during dataset loading."""

import anyio

from vulnwitness.domain.data_readiness import (
    WaitForDataLoading,
    WaitForDataReady,
    WaitForDataRequest,
)


class DataReadiness:
    """Bounded waits observe publication without cancelling the shared loader."""

    def __init__(self) -> None:
        self._ready = anyio.Event()

    def publish(self) -> None:
        self._ready.set()

    async def wait(self, request: WaitForDataRequest) -> WaitForDataReady | WaitForDataLoading:
        if self._ready.is_set():
            return WaitForDataReady()
        with anyio.move_on_after(request.timeout_seconds) as wait_scope:
            await self._ready.wait()
        if wait_scope.cancel_called:
            return WaitForDataLoading(waited_seconds=request.timeout_seconds)
        return WaitForDataReady()
