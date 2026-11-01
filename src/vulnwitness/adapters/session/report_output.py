"""Validate report destinations and publish private files atomically."""

import contextlib
import json
import os
from pathlib import Path
from tempfile import mkstemp

from vulnwitness.adapters.session.files import read_session_file
from vulnwitness.adapters.session.validation import reject_duplicate_keys


def read_triage_scope(directory: Path) -> str | None:
    """Optional workflow metadata is scope context only, never evidence or findings."""
    path = directory / "triage.json"
    if not os.path.lexists(path):
        return None
    try:
        document = json.loads(read_session_file(path), object_pairs_hook=reject_duplicate_keys)
        if not isinstance(document, dict):
            raise ValueError("workflow summary must be an object")
    except (OSError, ValueError, RecursionError):
        return "triage.json is unreadable or invalid; inventory and deep-dive scope unavailable."
    # The workflow artefact contains scope facts only. Keeping it verbatim avoids depending
    # on its versioned shape; nothing here participates in checker verdicts or other sections.
    return json.dumps(document, ensure_ascii=True, sort_keys=True, indent=2)


def validate_report_output(directory: Path, target: Path | None, force: bool) -> None:
    if target is None:
        if force:
            raise ValueError("--force requires --output")
        return
    destination = target.resolve()
    session_directory = directory.resolve()
    if destination.is_relative_to(session_directory) and not (
        target.absolute().parent == directory.absolute()
        and destination.parent == session_directory
        and destination.name.startswith("report.")
        and len(destination.name) > len("report.")
        and not target.is_symlink()
    ):
        raise ValueError("inside a session, --output must explicitly name DIR/report.*")
    if target.is_symlink():
        raise ValueError("report output must not be a symlink")
    if target.exists() and not target.is_file():
        raise ValueError("report output must be a regular file")
    if os.path.lexists(target) and not force:
        raise ValueError("report file already exists; use --force to overwrite")


def write_report(target: Path, content: str, force: bool) -> None:
    """Use link for atomic no-clobber publication, replace for explicit overwrites."""
    descriptor, temporary_name = mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        if force:
            os.replace(temporary, target)
        else:
            os.link(temporary, target)
            temporary.unlink()
        directory_descriptor = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
