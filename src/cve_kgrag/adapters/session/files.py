"""Bounded regular-file reads, private atomic writes and directory locks."""

import contextlib
import fcntl
import os
import secrets
import stat
from collections.abc import Iterator
from pathlib import Path

from cve_kgrag.adapters.regular_files import open_regular_file
from cve_kgrag.adapters.store.store_root import lies_in_store_root

MAX_SESSION_FILE_BYTES = 64 * 1024 * 1024


def check_session_path(directory: Path, store_root: Path | None = None) -> None:
    if directory.is_symlink():
        raise ValueError("session directory must not be a symlink")
    if store_root is not None and lies_in_store_root(directory.resolve(), store_root):
        raise ValueError("session directory must be outside the store root")
    if directory.exists() and not directory.is_dir():
        raise ValueError("session path must be a directory")


def make_private_directory(directory: Path) -> None:
    if directory.is_symlink():
        raise ValueError("session subdirectories must not be symlinks")
    if not directory.exists():
        if not directory.parent.exists():
            make_private_directory(directory.parent)
        directory.mkdir(mode=0o700)
    if not directory.is_dir():
        raise ValueError("session path must be a directory")
    os.chmod(directory, 0o700)


def read_session_file(path: Path) -> bytes:
    if path.parent.is_symlink():
        raise ValueError("session file parent must not be a symlink")
    with open_regular_file(path) as stream:
        content = stream.read(MAX_SESSION_FILE_BYTES + 1)
    if len(content) > MAX_SESSION_FILE_BYTES:
        raise ValueError("session file exceeds the size limit")
    return content


def atomic_write(path: Path, content: bytes) -> None:
    temporary = path.parent / f".{path.name}.tmp-{secrets.token_hex(8)}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


@contextlib.contextmanager
def hold_session_lock(directory: Path) -> Iterator[None]:
    descriptor = os.open(
        directory / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
    )
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("session lock must be a regular file")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)
