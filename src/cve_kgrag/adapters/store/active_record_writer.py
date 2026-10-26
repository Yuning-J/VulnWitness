"""Changing ``<root>/ACTIVE``: the root's lock, and the write that replaces the record
(ADR 0009 §6).

The write has a check, a point of no return and a confirmation. The root is synced once
first, so a root that cannot be synced fails before anything changes; the new record is
written to a temporary file and synced; ``os.replace`` onto ``ACTIVE`` is the point of no
return; the root is synced again to confirm it. Any failure before the replace leaves
``ACTIVE`` as it was. A failure of the confirming sync leaves the outcome unknown, and
is reported so, never as an unchanged record.

The file operations reach the write through ``ActiveRecordFiles``, so tests can fail
each point and see what ``ACTIVE`` then holds.
"""

import contextlib
import errno
import fcntl
import os
import secrets
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Protocol

from cve_kgrag.adapters.store.active_record import ActiveRecord, encode_active_record
from cve_kgrag.domain.store_status import (
    ACTIVE_RECORD_NAME,
    StoreOperationFailed,
    StoreOperationFailure,
)

LOCK_FILE = ".lock"
ACTIVE_TEMPORARY_PREFIX = ".ACTIVE.tmp-"
# Readable by every user, so by a server whichever user runs it; set explicitly, so the
# umask of the run never narrows it.
ACTIVE_FILE_MODE = 0o644


class ActiveRecordFiles(Protocol):
    """The file operations a write of ``ACTIVE`` makes."""

    def sync_directory(self, directory: Path) -> None:
        """Open ``directory`` and fsync it."""
        ...

    def write_new_file(self, path: Path, content: bytes) -> None:
        """Create ``path``, which must not exist, with ``ACTIVE_FILE_MODE``, write
        ``content`` and fsync it."""
        ...

    def replace(self, source: Path, target: Path) -> None:
        """Rename ``source`` onto ``target`` in one step (``os.replace``)."""
        ...

    def remove(self, path: Path) -> None:
        """Remove ``path`` if it is there."""
        ...


class OsActiveRecordFiles:
    """The operating system's file operations."""

    def sync_directory(self, directory: Path) -> None:
        directory_descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)

    def write_new_file(self, path: Path, content: bytes) -> None:
        file_descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, ACTIVE_FILE_MODE
        )
        try:
            os.fchmod(file_descriptor, ACTIVE_FILE_MODE)
            written_bytes = 0
            while written_bytes < len(content):
                written_bytes += os.write(file_descriptor, content[written_bytes:])
            os.fsync(file_descriptor)
        finally:
            os.close(file_descriptor)

    def replace(self, source: Path, target: Path) -> None:
        os.replace(source, target)

    def remove(self, path: Path) -> None:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)


@contextlib.contextmanager
def hold_store_lock(store_root: Path) -> Iterator[None]:
    """Hold a non-blocking ``flock`` on ``<root>/.lock`` for the block. Raises
    ``StoreOperationFailed``: ``store_lock_held`` while another operation holds it, and
    ``active_write_failed`` for a ``.lock`` that cannot be created or opened or is not a
    regular file. A ``.lock`` this call creates gets ``ACTIVE_FILE_MODE`` set
    explicitly."""
    lock_path = store_root / LOCK_FILE
    open_flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        try:
            lock_descriptor = os.open(lock_path, open_flags | os.O_CREAT | os.O_EXCL, 0o600)
            is_created = True
        except FileExistsError:
            lock_descriptor = os.open(lock_path, open_flags)
            is_created = False
    except OSError:
        raise StoreOperationFailed(StoreOperationFailure.ACTIVE_WRITE_FAILED) from None
    try:
        try:
            if not stat.S_ISREG(os.fstat(lock_descriptor).st_mode):
                raise StoreOperationFailed(StoreOperationFailure.ACTIVE_WRITE_FAILED)
            if is_created:
                os.fchmod(lock_descriptor, ACTIVE_FILE_MODE)
        except OSError:
            raise StoreOperationFailed(StoreOperationFailure.ACTIVE_WRITE_FAILED) from None
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in {errno.EWOULDBLOCK, errno.EAGAIN}:
                raise StoreOperationFailed(StoreOperationFailure.STORE_LOCK_HELD) from None
            raise StoreOperationFailed(StoreOperationFailure.ACTIVE_WRITE_FAILED) from None
        yield
    finally:
        os.close(lock_descriptor)


def write_active_record(
    store_root: Path, active_record: ActiveRecord, files: ActiveRecordFiles
) -> None:
    """Replace ``ACTIVE`` with ``active_record``. The caller holds the root's lock.

    Raises ``StoreOperationFailed``: ``active_write_failed`` when anything before the
    replace, or the replace itself, fails, with ``ACTIVE`` as it was and the temporary
    file removed; ``active_write_unconfirmed`` when the confirming sync fails, after
    which ``ACTIVE`` may already hold the new record.
    """
    temporary_path = store_root / f"{ACTIVE_TEMPORARY_PREFIX}{secrets.token_hex(8)}"
    try:
        files.sync_directory(store_root)
        files.write_new_file(temporary_path, encode_active_record(active_record))
        files.replace(temporary_path, store_root / ACTIVE_RECORD_NAME)
    except OSError:
        # Removing the temporary file is a courtesy: one left behind is a hidden entry,
        # never a store and never read, and the failure reported stays the write's.
        with contextlib.suppress(OSError):
            files.remove(temporary_path)
        raise StoreOperationFailed(StoreOperationFailure.ACTIVE_WRITE_FAILED) from None
    try:
        files.sync_directory(store_root)
    except OSError:
        raise StoreOperationFailed(StoreOperationFailure.ACTIVE_WRITE_UNCONFIRMED) from None
