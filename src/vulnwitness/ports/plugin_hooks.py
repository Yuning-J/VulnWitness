"""Conversation persistence and saved checker inputs for advisory plugin hooks."""

from contextlib import AbstractContextManager
from pathlib import Path
from typing import Protocol, TypedDict


class Conversation(TypedDict):
    investigations: list[str]
    checked: dict[str, str]


class PluginHookState(Protocol):
    def conversation_path(self, session_id: str) -> Path: ...

    def conversation_lock(self, path: Path) -> AbstractContextManager[None]: ...

    def read_conversation(self, path: Path) -> Conversation: ...

    def write_conversation(self, path: Path, conversation: Conversation) -> None: ...

    def investigation_directory(self, investigation_id: str) -> Path: ...

    def input_digest(self, directory: Path) -> str: ...

    def log_error(self, error: Exception) -> None: ...
