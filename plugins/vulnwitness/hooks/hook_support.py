"""Private conversation state and process boundaries for standard-library-only hooks."""

import fcntl
import json
import os
import re
import shutil
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TypeAlias, TypedDict

JsonValue: TypeAlias = "bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None"
INVESTIGATION_PATTERN = re.compile(r"inv_[a-z2-7]{20}")
TOOL_PREFIX = "mcp__plugin_vulnwitness_vulnwitness__"


class Conversation(TypedDict):
    investigations: list[str]
    checked: dict[str, str]


def workspace_root() -> Path:
    """Resolve the wrapper's workspace setting, including its empty-value default."""
    return Path(os.environ.get("VULNWITNESS_WORKSPACE") or Path.home() / ".vulnwitness/workspace")


def plugin_data_root() -> Path:
    directory = Path(os.environ["CLAUDE_PLUGIN_DATA"])
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return directory


def log_error(error: Exception) -> None:
    """Log only the error type; CLI output and environment may contain source text or secrets."""
    try:
        with (plugin_data_root() / "hooks.log").open("a", encoding="utf-8") as stream:
            stream.write(f"Hook error: {type(error).__name__}\n")
    except Exception:
        # Hook failures cannot prevent the enclosing tool call or conversation stop.
        return


def conversation_path(event: dict[str, JsonValue]) -> Path:
    session_id = event.get("session_id")
    if not isinstance(session_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", session_id):
        raise ValueError("Invalid hook session_id")
    directory = plugin_data_root() / "conversations"
    directory.mkdir(mode=0o700, exist_ok=True)
    return directory / f"{session_id}.json"


@contextmanager
def conversation_lock(path: Path) -> Iterator[None]:
    """Serialize read/modify/replace across both hooks without waiting indefinitely."""
    with path.with_suffix(".lock").open("a", encoding="utf-8") as stream:
        deadline = time.monotonic() + 1
        while True:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)
        yield


def read_conversation(path: Path) -> Conversation:
    if not path.exists():
        return {"investigations": [], "checked": {}}
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("Invalid conversation state")
    investigations = document.get("investigations")
    checked = document.get("checked")
    if not isinstance(investigations, list) or not isinstance(checked, dict):
        raise ValueError("Invalid conversation state")
    for investigation_id in investigations:
        if not isinstance(investigation_id, str) or not INVESTIGATION_PATTERN.fullmatch(
            investigation_id
        ):
            raise ValueError("Invalid investigation ID")
    for investigation_id, digest in checked.items():
        if not isinstance(investigation_id, str) or not isinstance(digest, str):
            raise ValueError("Invalid checked digest")
    return {"investigations": investigations, "checked": checked}


def write_conversation(path: Path, conversation: Conversation) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=".conversation-", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(conversation, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def read_event(text: str) -> dict[str, JsonValue]:
    event: JsonValue = json.loads(text)
    if not isinstance(event, dict):
        raise ValueError("Expected hook object")
    return event


def cli_binary() -> str:
    binary = os.environ.get("VULNWITNESS_BIN") or "vulnwitness"
    executable = shutil.which(binary)
    if executable is None:
        raise FileNotFoundError("Install vulnwitness[mcp] or set VULNWITNESS_BIN")
    return executable


def cli_environment() -> dict[str, str]:
    """Mirror the demo wrapper, preventing invalid inherited settings from blocking checks."""
    environment = dict(os.environ)
    if environment.get("VULNWITNESS_PLUGIN_REAL_DATA") == "1":
        return environment
    for name in tuple(environment):
        if name.startswith("VULNWITNESS_PLANNER_") or name in (
            "VULNWITNESS_STORE_ROOT",
            "VULNWITNESS_FIGHT_SNAPSHOT_PATH",
            "VULNWITNESS_MITRE_SNAPSHOT_PATH",
            "VULNWITNESS_FIGHT_SNAPSHOT_SHA256",
            "VULNWITNESS_MITRE_SNAPSHOT_SHA256",
            "VULNWITNESS_SEMANTIC_ENABLED",
        ):
            del environment[name]
    return environment
