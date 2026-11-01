"""Record a call before releasing its answer; serialize writers with a file lock."""

from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import Literal, TypeVar

from pydantic import JsonValue

from vulnwitness.adapters.session.files import (
    atomic_write,
    check_session_path,
    hold_session_lock,
    make_private_directory,
    read_session_file,
)
from vulnwitness.adapters.session.validation import parse_session_document
from vulnwitness.domain.hashing import sha256_hex
from vulnwitness.domain.session_record import (
    SessionCall,
    SessionDatasetIdentity,
    SessionRecord,
    SessionRecordingError,
)
from vulnwitness.domain.session_response import SESSION_RESPONSE_MODELS
from vulnwitness.domain.tool_contracts import ToolFailureCode

AnswerT = TypeVar("AnswerT")


class SessionRecorder:
    """The operator's session, with an injected clock and dataset identity.

    The response is committed first and the call last. An interrupted pair is visible to
    the checker and blocks further appends. No answer escapes a failed write.
    """

    def __init__(
        self,
        directory: Path,
        dataset: SessionDatasetIdentity,
        clock: Callable[[], datetime],
        *,
        store_root: Path | None = None,
        call_limit: int | None = None,
        goal: str | None = None,
        scope: str | None = None,
        lock: Callable[[], AbstractContextManager[None]] | None = None,
        allow_incomplete_triage: bool = False,
        record_response_digest: bool = False,
    ) -> None:
        self._lock = lock or partial(hold_session_lock, directory)
        self._allow_incomplete_triage = allow_incomplete_triage
        self._record_response_digest = record_response_digest
        self.directory = directory
        self._dataset = dataset
        self._clock = clock
        self._store_root = store_root
        self._call_limit = call_limit
        self._goal = goal
        self._scope = scope

    def run(
        self,
        interface: Literal["cli", "mcp"],
        command: str,
        request: dict[str, JsonValue] | None,
        operation: Callable[[], AnswerT],
        encode: Callable[[AnswerT], tuple[bytes, Literal["ok"] | ToolFailureCode, str]],
    ) -> AnswerT:
        try:
            check_session_path(self.directory, self._store_root)
            make_private_directory(self.directory)
            with self._lock():
                session = self._open_session()
                sequence = self._next_sequence(session)
                started_at = self._clock()
                answer = operation()
                response_bytes, outcome, response_schema = encode(answer)
                call = SessionCall(
                    sequence=sequence,
                    interface=interface,
                    command=command,
                    request=request,
                    dataset=self._dataset,
                    outcome=outcome,
                    response_file=f"responses/{sequence:04d}.json",
                    response_schema=response_schema,
                    response_sha256=(
                        sha256_hex(response_bytes) if self._record_response_digest else None
                    ),
                    started_at=started_at,
                    finished_at=self._clock(),
                )
                atomic_write(self.directory / call.response_file, response_bytes)
                atomic_write(
                    self.directory / "calls" / f"{sequence:04d}.json",
                    (call.model_dump_json(indent=2) + "\n").encode("utf-8"),
                )
                return answer
        except SessionRecordingError:
            raise
        except (OSError, ValueError, RecursionError):
            raise SessionRecordingError(ToolFailureCode.SESSION_RECORDING_FAILED) from None

    def _open_session(self) -> SessionRecord:
        session_file = self.directory / "session.json"
        if session_file.exists() or session_file.is_symlink():
            session = parse_session_document(read_session_file(session_file), SessionRecord)
            if (
                session.origin == "triage"
                and not (self.directory / "triage.json").is_file()
                and not self._allow_incomplete_triage
            ):
                raise SessionRecordingError(ToolFailureCode.INVESTIGATION_INTERRUPTED)
            if session.dataset != self._dataset:
                raise SessionRecordingError(ToolFailureCode.SESSION_DATASET_MISMATCH)
            if self._call_limit is not None and self._call_limit != session.call_limit:
                raise ValueError("an existing session's call limit cannot change")
            if self._goal is not None and self._goal != session.goal:
                raise ValueError("an existing session's goal cannot change")
            if self._scope is not None and self._scope != session.scope:
                raise ValueError("an existing session's scope cannot change")
        else:
            if any(path.name != ".lock" for path in self.directory.iterdir()):
                raise ValueError("a new session directory must be empty")
            session = SessionRecord(
                name=self.directory.resolve().name,
                created_at=self._clock(),
                dataset=self._dataset,
                call_limit=100 if self._call_limit is None else self._call_limit,
                goal=self._goal,
                scope=self._scope,
            )
            atomic_write(session_file, (session.model_dump_json(indent=2) + "\n").encode())
        for name in ("calls", "responses"):
            make_private_directory(self.directory / name)
        return session

    def _next_sequence(self, session: SessionRecord) -> int:
        call_files = sorted((self.directory / "calls").iterdir())
        response_files = sorted((self.directory / "responses").iterdir())
        if len(call_files) != len(response_files):
            raise ValueError("incomplete session call")
        for sequence, (call_file, response_file) in enumerate(
            zip(call_files, response_files, strict=True), start=1
        ):
            if call_file.name != f"{sequence:04d}.json" or response_file.name != call_file.name:
                raise ValueError("session sequence is not contiguous")
            call = parse_session_document(read_session_file(call_file), SessionCall)
            if call.sequence != sequence or call.dataset != session.dataset:
                raise ValueError("session call identity differs")
            if call.response_file != f"responses/{sequence:04d}.json":
                raise ValueError("response filename differs from sequence")
            response_model = SESSION_RESPONSE_MODELS.get(call.response_schema)
            if response_model is None:
                raise ValueError("unknown response schema")
            parse_session_document(read_session_file(response_file), response_model)
        if len(call_files) >= session.call_limit:
            raise SessionRecordingError(ToolFailureCode.SESSION_CALL_LIMIT)
        return len(call_files) + 1
