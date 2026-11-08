"""Private direct-child investigations and bounded cross-process creation locks."""

import contextlib
import fcntl
import hashlib
import os
import re
import stat
import time
from collections.abc import Callable, Iterator
from pathlib import Path

from vulnwitness.adapters.regular_files import open_regular_file
from vulnwitness.adapters.session.check import SessionChecker
from vulnwitness.adapters.session.files import (
    atomic_write,
    check_session_path,
    hold_session_lock,
    make_private_directory,
    read_session_file,
)
from vulnwitness.adapters.session.triage_artifacts import serialize_findings
from vulnwitness.adapters.session.validation import parse_session_document
from vulnwitness.domain.session_record import (
    SessionCheckReport,
    SessionFindings,
    SessionRecord,
    SessionRecordingError,
    SessionSelections,
)
from vulnwitness.domain.session_report import CheckedSession
from vulnwitness.domain.tool_contracts import ToolFailureCode
from vulnwitness.domain.workspace import (
    INVESTIGATION_ID_PATTERN,
    MAX_WORKSPACE_FINDINGS_BYTES,
    RequestRecord,
)


def check_private_directory(directory: Path) -> None:
    """Refuse unsafe existing directories without changing their permissions."""
    check_session_path(directory)
    metadata = directory.stat()
    if metadata.st_uid != os.getuid():
        raise ValueError("workspace directories must be owned by the current user")
    if metadata.st_mode & 0o022:
        raise ValueError("workspace directories must not be group or other writable")


def check_workspace_root(root: Path, store_root: Path | None = None) -> None:
    """Validate a workspace path without creating directories before dataset binding."""
    check_session_path(root, store_root)
    if store_root is not None and root.resolve().is_relative_to(store_root.resolve()):
        raise ValueError("workspace directory must be outside the store root")
    if root.exists():
        check_private_directory(root)


class LocalWorkspaceFiles:
    """All investigation paths are validated before reads, writes or lock acquisition."""

    def __init__(
        self,
        root: Path,
        store_root: Path | None = None,
        *,
        lock_wait: float = 2.0,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        check_workspace_root(root, store_root)
        if not root.exists():
            make_private_directory(root)
        check_private_directory(root)
        self.root = root.resolve()
        self._lock_wait = lock_wait
        self._monotonic = monotonic
        self._sleep = sleep
        make_private_directory(self.root / "requests")

    def resolve(self, session_id: str) -> Path:
        check_private_directory(self.root)
        if re.fullmatch(INVESTIGATION_ID_PATTERN, session_id) is None:
            raise SessionRecordingError(ToolFailureCode.INVALID_ARGUMENTS)
        directory = self.root / session_id
        if self.root.is_symlink() or directory.is_symlink():
            raise SessionRecordingError(ToolFailureCode.UNKNOWN_INVESTIGATION)
        if directory.resolve().parent != self.root or not directory.is_dir():
            raise SessionRecordingError(ToolFailureCode.UNKNOWN_INVESTIGATION)
        check_private_directory(directory)
        return directory

    @contextlib.contextmanager
    def workspace_lock(self) -> Iterator[None]:
        check_private_directory(self.root)
        descriptor = os.open(
            self.root / ".workspace.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
        )
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("workspace lock must be regular")
            os.fchmod(descriptor, 0o600)
            deadline = self._monotonic() + self._lock_wait
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if self._monotonic() >= deadline:
                        raise SessionRecordingError(ToolFailureCode.WORKSPACE_BUSY) from None
                    self._sleep(min(0.01, max(0, deadline - self._monotonic())))
            yield
        finally:
            os.close(descriptor)

    @contextlib.contextmanager
    def investigation_lock(self, session_id: str) -> Iterator[None]:
        directory = self.resolve(session_id)
        try:
            with hold_session_lock(directory):
                yield
        except BlockingIOError:
            raise SessionRecordingError(ToolFailureCode.INVESTIGATION_BUSY) from None

    def is_busy(self, session_id: str) -> bool:
        try:
            with self.investigation_lock(session_id):
                return False
        except SessionRecordingError as error:
            if error.code == ToolFailureCode.INVESTIGATION_BUSY:
                return True
            raise

    def list_ids(self) -> tuple[str, ...]:
        check_session_path(self.root)
        session_ids: list[str] = []
        for path in sorted(self.root.iterdir()):
            if re.fullmatch(INVESTIGATION_ID_PATTERN, path.name):
                self.resolve(path.name)
                session_ids.append(path.name)
        return tuple(session_ids)

    def _request_path(self, key: str) -> Path:
        check_private_directory(self.root)
        if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", key) is None:
            raise SessionRecordingError(ToolFailureCode.INVALID_ARGUMENTS)
        directory = self.root / "requests"
        check_session_path(directory)
        return directory / (key + ".json")

    def read_request(self, key: str) -> RequestRecord | None:
        path = self._request_path(key)
        if not path.exists() and not path.is_symlink():
            return None
        return parse_session_document(read_session_file(path), RequestRecord)

    def write_request(self, key: str, record: RequestRecord) -> None:
        atomic_write(self._request_path(key), record.model_dump_json().encode())

    def create(self, session: SessionRecord) -> None:
        check_private_directory(self.root)
        if re.fullmatch(INVESTIGATION_ID_PATTERN, session.name) is None:
            raise ValueError("invalid investigation ID")
        directory = self.root / session.name
        directory.mkdir(mode=0o700)
        for name in ("calls", "responses"):
            make_private_directory(directory / name)
        self.write(session.name, "session.json", session.model_dump_json().encode())
        findings = SessionFindings(findings=(), selections=SessionSelections(), open_questions=())
        self.write_findings(session.name, findings)

    def _file_path(self, session_id: str, name: str) -> Path:
        directory = self.resolve(session_id)
        # Names come from application code, never from a model-supplied file path.
        path = directory / name
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError("workspace files must not be symlinks")
        if path.parent != directory and path.parent.parent != directory:
            raise ValueError("file must belong to the investigation")
        return path

    def read_response(self, session_id: str, sequence: int) -> bytes:
        path = self._file_path(session_id, f"responses/{sequence:04d}.json")
        with open_regular_file(path) as stream:
            return stream.read(1024 * 1024 + 1)

    def read(self, session_id: str, name: str) -> bytes:
        return read_session_file(self._file_path(session_id, name))

    def write_findings(self, session_id: str, findings: SessionFindings) -> None:
        content = serialize_findings(findings)
        if len(content) > MAX_WORKSPACE_FINDINGS_BYTES:
            raise SessionRecordingError(ToolFailureCode.FINDINGS_TOO_LARGE)
        self.write(session_id, "findings.yaml", content)

    def write(self, session_id: str, name: str, content: bytes) -> None:
        atomic_write(self._file_path(session_id, name), content)

    def exists(self, session_id: str, name: str) -> bool:
        return self._file_path(session_id, name).exists()

    def input_digest(self, session_id: str) -> str:
        directory = self.resolve(session_id)
        check_session_path(directory / "calls")
        names = ["session.json", "findings.yaml"]
        if (directory / "priority.json").exists() or (directory / "priority.json").is_symlink():
            names.append("priority.json")
        for path in sorted((directory / "calls").iterdir()):
            names.append("calls/" + path.name)
        digest = hashlib.sha256()
        for name in names:
            try:
                content = self.read(session_id, name)
            except (OSError, ValueError):
                if name != "priority.json":
                    raise
                # Optional invalid decisions render as a finding, without reading a link target.
                digest.update(name.encode() + b"\0unreadable\0")
                continue
            digest.update(name.encode() + b"\0" + str(len(content)).encode() + b"\0" + content)
        return digest.hexdigest()

    def check_findings(self, session_id: str, findings: SessionFindings) -> SessionCheckReport:
        return SessionChecker(self.resolve(session_id), findings).check()

    def check(self, session_id: str) -> CheckedSession:
        return SessionChecker(self.resolve(session_id)).check_with_contents()

    def local_path(self, session_id: str, name: str) -> str:
        return str(self._file_path(session_id, name))

    def is_orphan(self, session_id: str) -> bool:
        self.resolve(session_id)
        # Only investigations with a request key can have an unindexed creation.
        session = parse_session_document(self.read(session_id, "session.json"), SessionRecord)
        if session.request_key is None:
            return False
        indexed = self.read_request(session.request_key)
        return indexed is None or indexed.session_id != session_id
