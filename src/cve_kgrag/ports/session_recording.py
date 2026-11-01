"""The recording boundary transports invoke before releasing an answer."""

from collections.abc import Callable
from typing import Literal, Protocol, TypeVar

from pydantic import JsonValue

from cve_kgrag.domain.tool_contracts import ToolFailureCode

AnswerT = TypeVar("AnswerT")


class SessionRecording(Protocol):
    def run(
        self,
        interface: Literal["cli", "mcp"],
        command: str,
        request: dict[str, JsonValue] | None,
        operation: Callable[[], AnswerT],
        encode: Callable[[AnswerT], tuple[bytes, Literal["ok"] | ToolFailureCode, str]],
    ) -> AnswerT:
        """Execute and persist the call, or raise SessionRecordingError without an answer."""
        ...
