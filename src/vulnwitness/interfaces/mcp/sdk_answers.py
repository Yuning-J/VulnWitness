"""Restates what the SDK's Streamable HTTP transport answers in the server's own words
before it leaves the server.

The SDK answers some requests itself: plain-text refusals (a missing content type, a
method its transport does not serve) and JSON-RPC errors, some of which quote the
request, such as a validation error repeating the value sent. A JSON-RPC error is
restated with its code, its ``id`` (which JSON-RPC requires a reply to repeat) and a
fixed message; any other answer with status 400 or above becomes an ``HttpRejection``.
"""

import json
from dataclasses import dataclass

from starlette.types import ASGIApp, Receive, Scope, Send

from vulnwitness.domain.http_rejection import HttpRejectionCode
from vulnwitness.domain.tool_contracts import ToolFailureCode
from vulnwitness.interfaces.http.guard import (
    JSON_CONTENT_TYPE,
    RecordedResponse,
    send_recorded_response,
    send_rejection,
)
from vulnwitness.interfaces.knowledge_tools import build_tool_failure
from vulnwitness.interfaces.mcp.server import INVALID_PARAMETERS_MESSAGE, UNKNOWN_TOOL_MESSAGE

# Messages a JSON-RPC error keeps as they are: this server's own, and the SDK's fixed
# sentences.
FIXED_ERROR_MESSAGES = frozenset(
    {
        UNKNOWN_TOOL_MESSAGE,
        "Method not found",
        INVALID_PARAMETERS_MESSAGE,
        "unknown prompt",
        "Invalid prompt arguments",
        "Resource not found",
    }
)
# The message any other error of a JSON-RPC code is restated with.
ERROR_CODE_MESSAGES: dict[int, str] = {
    -32700: "Parse error",
    -32600: "Invalid Request",
    -32601: "Method not found",
    -32602: "Invalid params",
    -32603: "Internal error",
}
OTHER_ERROR_MESSAGE = "Request failed"


@dataclass(frozen=True)
class RestatedError:
    """A JSON-RPC error response as the server restates it: the request's ``id``, the
    error's code and a fixed message."""

    request_id: str | int | None
    code: int
    message: str

    def encode(self) -> bytes:
        restated_answer = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "error": {"code": self.code, "message": self.message},
        }
        return json.dumps(restated_answer, separators=(",", ":"), ensure_ascii=False).encode()


def is_fixed_error_message(message: object) -> bool:
    """Only exact server-authored failures survive HTTP error sanitization."""
    if not isinstance(message, str):
        return False
    if message in FIXED_ERROR_MESSAGES:
        return True
    for code in (
        ToolFailureCode.INVALID_ARGUMENTS,
        ToolFailureCode.UNKNOWN_INVESTIGATION,
        ToolFailureCode.INVESTIGATION_BUSY,
        ToolFailureCode.SESSION_RECORDING_FAILED,
        ToolFailureCode.INTERNAL_ERROR,
    ):
        if message == build_tool_failure(code).model_dump_json():
            return True
    return False


def restate_json_rpc_error(body: bytes) -> RestatedError | None:
    """``body`` restated when it is a JSON-RPC error response: its message kept only when
    it is a fixed server-authored message or typed failure, else its code's sentence.
    An ``id`` other than a string or integer reads as none; ``None`` when ``body`` is
    no such response."""
    try:
        answer = json.loads(body)
    except ValueError:
        return None
    if not isinstance(answer, dict):
        return None
    error = answer.get("error")
    if not isinstance(error, dict):
        return None
    code = error.get("code")
    if isinstance(code, bool) or not isinstance(code, int):
        return None
    message = error.get("message")
    if not is_fixed_error_message(message):
        message = ERROR_CODE_MESSAGES.get(code, OTHER_ERROR_MESSAGE)
    request_id = answer.get("id")
    if isinstance(request_id, bool) or not isinstance(request_id, str | int):
        request_id = None
    assert isinstance(message, str)
    return RestatedError(request_id=request_id, code=code, message=message)


class SdkAnswersRestated:
    """Runs the SDK's transport and sends its answer restated (module docstring)."""

    def __init__(self, sdk_app: ASGIApp) -> None:
        self._sdk_app = sdk_app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        recorded_response = RecordedResponse()
        await self._sdk_app(scope, receive, recorded_response.record)
        if recorded_response.start is None:
            return
        status: int = recorded_response.start["status"]
        restated_error = restate_json_rpc_error(b"".join(recorded_response.body_parts))
        if restated_error is not None:
            body = restated_error.encode()
            headers = [JSON_CONTENT_TYPE, (b"content-length", str(len(body)).encode())]
            await send({"type": "http.response.start", "status": status, "headers": headers})
            await send({"type": "http.response.body", "body": body})
        elif status >= 500:
            await send_rejection(send, HttpRejectionCode.INTERNAL_ERROR)
        elif status >= 400:
            await send_rejection(send, HttpRejectionCode.INVALID_REQUEST)
        else:
            await send_recorded_response(send, recorded_response)
