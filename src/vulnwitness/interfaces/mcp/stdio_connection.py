"""Treat stdin EOF as a half-close: received requests can still write their replies."""

from collections import Counter

import anyio
from anyio.abc import ObjectReceiveStream
from mcp.shared._stream_protocols import ReadStream, WriteStream
from mcp.shared.dispatcher import as_request_id, coerce_request_id
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCError, JSONRPCNotification, JSONRPCRequest, JSONRPCResponse, RequestId


class StdioConnection(ObjectReceiveStream[SessionMessage | Exception]):
    """Keep the SDK's duplex connection open until every received request settles.

    The SDK cancels handlers at EOF. Stdin closing only ends client writes, so EOF
    reaches the SDK after replies have reached the transport or the client has
    cancelled the requests. Closing this adapter closes both halves together.
    """

    def __init__(
        self,
        read_stream: ReadStream[SessionMessage | Exception],
        write_stream: WriteStream[SessionMessage],
        stdin_closed: anyio.Event,
    ) -> None:
        self._read_stream = read_stream
        self._write_stream = write_stream
        self._stdin_closed = stdin_closed
        self._pending: Counter[RequestId] = Counter()
        self._drained = anyio.Event()
        self._drained.set()

    async def receive(self) -> SessionMessage | Exception:
        try:
            frame = await self._read_stream.receive()
        except anyio.EndOfStream:
            self._stdin_closed.set()
            await self._drained.wait()
            raise
        if isinstance(frame, SessionMessage):
            message = frame.message
            if isinstance(message, JSONRPCRequest):
                if not self._pending:
                    self._drained = anyio.Event()
                self._pending[coerce_request_id(message.id)] += 1
            elif (
                isinstance(message, JSONRPCNotification)
                and message.method == "notifications/cancelled"
                and message.params is not None
            ):
                request_id = as_request_id(message.params.get("requestId"))
                if request_id is not None:
                    self.settle(coerce_request_id(request_id), cancelled=True)
        return frame

    async def send(self, frame: SessionMessage) -> None:
        await self._write_stream.send(frame)
        if (
            isinstance(frame.message, JSONRPCResponse | JSONRPCError)
            and frame.message.id is not None
        ):
            self.settle(coerce_request_id(frame.message.id))

    def settle(self, request_id: RequestId, *, cancelled: bool = False) -> None:
        if self._pending[request_id] > 1 and not cancelled:
            self._pending[request_id] -= 1
        else:
            self._pending.pop(request_id, None)
        if not self._pending:
            self._drained.set()

    async def aclose(self) -> None:
        await self._read_stream.aclose()
        await self._write_stream.aclose()
