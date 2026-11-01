"""Private atomic conversation state and checker inputs for Claude Code hooks."""

import fcntl
import hashlib
import json
import os
import re
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from vulnwitness.domain.workspace import INVESTIGATION_ID_PATTERN
from vulnwitness.ports.plugin_hooks import Conversation


class LocalPluginHookState:
    """Keep private conversation state and checker inputs outside the served store."""

    def __init__(
        self,
        plugin_data: Path | None,
        workspace: Path,
        monotonic: Callable[[], float],
        sleep: Callable[[float], None],
    ) -> None:
        self.plugin_data = plugin_data
        self.workspace = workspace
        self.monotonic = monotonic
        self.sleep = sleep

    def plugin_data_root(self) -> Path:
        if self.plugin_data is None:
            raise ValueError("CLAUDE_PLUGIN_DATA is required")
        directory = self.plugin_data
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        return directory

    def log_error(self, error: Exception) -> None:
        """Log only the exception type, keeping source text and credentials private."""
        if self.plugin_data is None:
            return
        try:
            with (self.plugin_data_root() / "hooks.log").open("a", encoding="utf-8") as stream:
                stream.write(f"Hook error: {type(error).__name__}\n")
        except Exception:
            # Hook failures cannot prevent the enclosing tool call or conversation stop.
            return

    def conversation_path(self, session_id: str) -> Path:
        if not isinstance(session_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", session_id):
            raise ValueError("Invalid hook session_id")
        directory = self.plugin_data_root() / "conversations"
        directory.mkdir(mode=0o700, exist_ok=True)
        return directory / f"{session_id}.json"

    @contextmanager
    def conversation_lock(self, path: Path) -> Iterator[None]:
        """Serialize read/modify/replace across both hooks without waiting indefinitely."""
        with path.with_suffix(".lock").open("a", encoding="utf-8") as stream:
            deadline = self.monotonic() + 1
            while True:
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if self.monotonic() >= deadline:
                        raise
                    self.sleep(0.01)
            yield

    def read_conversation(self, path: Path) -> Conversation:
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
            if not isinstance(investigation_id, str) or not re.fullmatch(
                INVESTIGATION_ID_PATTERN, investigation_id
            ):
                raise ValueError("Invalid investigation ID")
        for investigation_id, digest in checked.items():
            if not isinstance(investigation_id, str) or not isinstance(digest, str):
                raise ValueError("Invalid checked digest")
        return {"investigations": investigations, "checked": checked}

    def write_conversation(self, path: Path, conversation: Conversation) -> None:
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

    def investigation_directory(self, investigation_id: str) -> Path:
        root = self.workspace
        directory = root / investigation_id
        if (
            root.is_symlink()
            or directory.is_symlink()
            or directory.resolve().parent != root.resolve()
        ):
            raise ValueError("Investigation must be a direct non-symlink workspace child")
        if not directory.is_dir():
            raise FileNotFoundError("Investigation is missing")
        return directory

    def input_digest(self, directory: Path) -> str:
        """Bind all checker inputs, including response bytes, never report or lock files."""
        names = ["session.json", "findings.yaml"]
        for subdirectory in ("calls", "responses"):
            folder = directory / subdirectory
            if folder.is_symlink():
                raise ValueError("Symlink checker input")
            if folder.is_dir():
                for path in sorted(folder.iterdir()):
                    names.append(f"{subdirectory}/{path.name}")
            else:
                names.append(subdirectory)
        digest = hashlib.sha256()
        for name in names:
            path = directory / name
            if path.is_symlink():
                raise ValueError("Symlink checker input")
            digest.update(name.encode() + b"\0")
            if not path.exists():
                digest.update(b"missing\0")
                continue
            digest.update(str(path.stat().st_size).encode() + b"\0")
            with path.open("rb") as stream:
                while chunk := stream.read(65536):
                    digest.update(chunk)
        return digest.hexdigest()
