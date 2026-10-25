"""Read an import's input files: never following a link, never writing to an input, and
never holding more than the caps allow (ADR 0008 §1, §8).

An input is opened without following a symbolic link and must be a regular file. Its
container is told by its first bytes: gzip, a zip of exactly one stored or deflated
member, or plain bytes. A compressed file is capped by its size, a plain one by the
decompressed cap.

Before an input is read, it is copied into the run's own staging directory and hashed
as it is copied (``snapshot_input``); the copy must hold exactly the bytes the input was
inspected with, and every later read uses the copy. Re-hashing the operator's file
instead could never be race-free: the file could still be rewritten in place between
the hash and the parse, leaving the store manifest naming one file's hash and another
payload. The payload is read through a counting stream that hashes what it reads and
refuses to go past the per-file and total caps, or past an entry's cap from where the
parser says the entry began (``MigrationLimits``).
"""

import dataclasses
import gzip
import hashlib
import os
import struct
import zipfile
import zlib
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from cve_kgrag.adapters.migration.migration_limits import MigrationLimits
from cve_kgrag.adapters.regular_files import NotARegularFileError, open_regular_file
from cve_kgrag.domain.corpus_store_manifest import InputContainer
from cve_kgrag.domain.migration_report import MigrationFailed, MigrationFailureCode

GZIP_MAGIC = b"\x1f\x8b"
ZIP_MAGIC = b"PK\x03\x04"
HASH_CHUNK_BYTES = 1024 * 1024
# Only the run reads its snapshot; whatever the umask, nobody else may.
SNAPSHOT_FILE_MODE = 0o600
ZIP_ENCRYPTED_FLAG = 0x1
ZIP_METHODS = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})
# The end-of-central-directory record: its signature, then disk numbers, entry counts,
# the directory's size and offset, and the comment's length, which ends the file.
ZIP_END_RECORD = struct.Struct("<4s4H2LH")
ZIP_END_SIGNATURE = b"PK\x05\x06"
ZIP_MAX_COMMENT_BYTES = 0xFFFF
# One central-directory header: 46 fixed bytes, then a name, an extra field and a
# comment of at most 64 KiB each.
ZIP_MAX_ONE_MEMBER_DIRECTORY_BYTES = 46 + 3 * 0xFFFF
# What zipfile raises for a damaged archive besides BadZipFile: an unsupported version,
# a name that does not decode, a bad seek, a truncated read.
ZIP_READ_ERRORS = (zipfile.BadZipFile, OSError, EOFError, NotImplementedError, ValueError)


@dataclass
class DecompressionBudget:
    """The decompressed bytes every input of one run may still read together."""

    remaining_bytes: int


@dataclass(frozen=True)
class InputFile:
    """An input file as found: its resolved path, size, container and SHA-256."""

    path: Path
    size_bytes: int
    container: InputContainer
    sha256: str


def open_input_file(
    path: Path, missing_code: MigrationFailureCode = MigrationFailureCode.INPUT_UNREADABLE
) -> IO[bytes]:
    """``path`` opened for reading if it is a regular file (``open_regular_file``); raises
    ``MigrationFailed``: ``input_not_a_regular_file``, ``missing_code`` for a path that
    does not exist, or ``input_unreadable``."""
    try:
        return open_regular_file(path)
    except NotARegularFileError:
        raise MigrationFailed(MigrationFailureCode.INPUT_NOT_A_REGULAR_FILE) from None
    except FileNotFoundError:
        raise MigrationFailed(missing_code) from None
    except OSError:
        raise MigrationFailed(MigrationFailureCode.INPUT_UNREADABLE) from None


def detect_container(first_bytes: bytes) -> InputContainer:
    if first_bytes.startswith(GZIP_MAGIC):
        return InputContainer.GZIP
    if first_bytes.startswith(ZIP_MAGIC):
        return InputContainer.ZIP
    return InputContainer.PLAIN


def read_file_sha256(input_stream: IO[bytes]) -> str:
    """SHA-256 of the stream's bytes from where it stands, read in chunks."""
    digest = hashlib.sha256()
    try:
        chunk = input_stream.read(HASH_CHUNK_BYTES)
        while chunk:
            digest.update(chunk)
            chunk = input_stream.read(HASH_CHUNK_BYTES)
    except OSError:
        raise MigrationFailed(MigrationFailureCode.INPUT_UNREADABLE) from None
    return digest.hexdigest()


def inspect_input_file(path: Path, limits: MigrationLimits) -> InputFile:
    """The file's container and SHA-256; raises ``MigrationFailed`` for a file that is
    not regular, cannot be read, or is over its cap: the compressed cap for gzip and zip,
    the decompressed cap for plain bytes, which are their own payload."""
    with open_input_file(path) as input_stream:
        size_bytes = os.fstat(input_stream.fileno()).st_size
        try:
            container = detect_container(input_stream.read(len(ZIP_MAGIC)))
            input_stream.seek(0)
        except OSError:
            raise MigrationFailed(MigrationFailureCode.INPUT_UNREADABLE) from None
        if container is InputContainer.PLAIN:
            if size_bytes > limits.max_decompressed_file_bytes:
                raise MigrationFailed(MigrationFailureCode.DECOMPRESSED_FILE_TOO_LARGE)
        elif size_bytes > limits.max_compressed_file_bytes:
            raise MigrationFailed(MigrationFailureCode.COMPRESSED_FILE_TOO_LARGE)
        sha256 = read_file_sha256(input_stream)
    return InputFile(path=path, size_bytes=size_bytes, container=container, sha256=sha256)


def read_input_chunk(input_stream: IO[bytes], size: int) -> bytes:
    try:
        return input_stream.read(size)
    except OSError:
        raise MigrationFailed(MigrationFailureCode.INPUT_UNREADABLE) from None


def write_snapshot_chunk(snapshot_stream: IO[bytes], chunk: bytes) -> None:
    try:
        snapshot_stream.write(chunk)
    except OSError:
        raise MigrationFailed(MigrationFailureCode.STAGING_FAILED) from None


def create_snapshot_file(snapshot_path: Path) -> IO[bytes]:
    """A new, empty file at ``snapshot_path`` that only this run created and can read;
    raises ``MigrationFailed`` (``staging_failed``)."""
    try:
        file_descriptor = os.open(
            snapshot_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            SNAPSHOT_FILE_MODE,
        )
    except OSError:
        raise MigrationFailed(MigrationFailureCode.STAGING_FAILED) from None
    return os.fdopen(file_descriptor, "wb")


def snapshot_input(input_file: InputFile, snapshot_path: Path) -> InputFile:
    """The input copied to ``snapshot_path``, a path in the run's staging directory, and
    described as ``input_file`` with the copy's path. The copy is hashed as it is written
    and must hold exactly the inspected bytes, so whatever happens to the input later
    never reaches the import; raises ``MigrationFailed``: ``input_changed`` when the
    input is no longer those bytes, ``input_unreadable``, or ``staging_failed`` when the
    copy cannot be written. At most one chunk past the inspected size is copied."""
    digest = hashlib.sha256()
    copied_bytes = 0
    try:
        with (
            open_input_file(input_file.path) as input_stream,
            create_snapshot_file(snapshot_path) as snapshot_stream,
        ):
            while copied_bytes <= input_file.size_bytes:
                chunk = read_input_chunk(input_stream, HASH_CHUNK_BYTES)
                if not chunk:
                    break
                write_snapshot_chunk(snapshot_stream, chunk)
                digest.update(chunk)
                copied_bytes += len(chunk)
    except OSError:
        # Opening, reading and writing raise MigrationFailed themselves; what is left is
        # closing the copy, whose buffered tail can meet a full disk only then.
        raise MigrationFailed(MigrationFailureCode.STAGING_FAILED) from None
    is_unchanged = copied_bytes == input_file.size_bytes and (
        digest.hexdigest() == input_file.sha256
    )
    if not is_unchanged:
        raise MigrationFailed(MigrationFailureCode.INPUT_CHANGED)
    return dataclasses.replace(input_file, path=snapshot_path)


class PayloadStream:
    """A read-only stream over an input's decompressed payload that hashes every byte it
    hands out and stops at the caps: the file's, the run's total, and, once the parser
    marks where an entry began, the entry's (``begin_entry``).

    The entry cap is checked as bytes are read, before the parser sees them, so a huge
    entry or a single huge string is never held whole; the parser reads ahead by at most
    one buffer of ``limits.parser_buffer_bytes``, which the check allows for.
    """

    def __init__(
        self, source: IO[bytes], budget: DecompressionBudget, limits: MigrationLimits
    ) -> None:
        self.source = source
        self.budget = budget
        self.limits = limits
        self.position = 0
        self.entry_started_at: int | None = None
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        try:
            chunk = self.source.read(size)
        except (*ZIP_READ_ERRORS, zlib.error):
            # A zip member failing its CRC raises BadZipFile at its end.
            raise MigrationFailed(MigrationFailureCode.BAD_COMPRESSION) from None
        self.position += len(chunk)
        self.budget.remaining_bytes -= len(chunk)
        if self.position > self.limits.max_decompressed_file_bytes:
            raise MigrationFailed(MigrationFailureCode.DECOMPRESSED_FILE_TOO_LARGE)
        if self.budget.remaining_bytes < 0:
            raise MigrationFailed(MigrationFailureCode.TOTAL_TOO_LARGE)
        if self.entry_started_at is not None:
            entry_bytes = self.position - self.entry_started_at
            if entry_bytes > self.limits.max_entry_bytes + self.limits.parser_buffer_bytes:
                raise MigrationFailed(MigrationFailureCode.ENTRY_TOO_LARGE)
        self.digest.update(chunk)
        return chunk

    def begin_entry(self) -> None:
        """Count the next reads against the entry cap, from the parser's read position:
        at most one buffer past where the entry began."""
        self.entry_started_at = self.position

    def end_entry(self) -> None:
        self.entry_started_at = None

    def read_payload_sha256(self) -> str:
        return self.digest.hexdigest()


def check_zip_directory(input_stream: IO[bytes]) -> None:
    """Raise ``MigrationFailed`` (``bad_compression``) unless the archive's end record
    declares one member and a central directory no larger than one member needs, so
    ``zipfile`` never reads a large directory into memory. Rewinds the stream."""
    try:
        file_bytes = os.fstat(input_stream.fileno()).st_size
        tail_bytes = min(file_bytes, ZIP_END_RECORD.size + ZIP_MAX_COMMENT_BYTES)
        input_stream.seek(file_bytes - tail_bytes)
        tail = input_stream.read(tail_bytes)
        input_stream.seek(0)
    except OSError:
        raise MigrationFailed(MigrationFailureCode.INPUT_UNREADABLE) from None
    record_start = tail.rfind(ZIP_END_SIGNATURE)
    if record_start < 0 or len(tail) - record_start < ZIP_END_RECORD.size:
        raise MigrationFailed(MigrationFailureCode.BAD_COMPRESSION)
    end_record = ZIP_END_RECORD.unpack_from(tail, record_start)
    member_count = end_record[4]
    directory_bytes = end_record[5]
    if member_count != 1 or directory_bytes > ZIP_MAX_ONE_MEMBER_DIRECTORY_BYTES:
        raise MigrationFailed(MigrationFailureCode.BAD_COMPRESSION)


def open_zip_member(input_stream: IO[bytes]) -> IO[bytes]:
    """The one member of a zip input; raises ``MigrationFailed`` unless the archive holds
    exactly one non-directory member, unencrypted, stored or deflated."""
    check_zip_directory(input_stream)
    try:
        archive = zipfile.ZipFile(input_stream)
    except ZIP_READ_ERRORS:
        raise MigrationFailed(MigrationFailureCode.BAD_COMPRESSION) from None
    members = archive.infolist()
    if len(members) != 1:
        raise MigrationFailed(MigrationFailureCode.BAD_COMPRESSION)
    (member,) = members
    is_encrypted = bool(member.flag_bits & ZIP_ENCRYPTED_FLAG)
    if member.is_dir() or is_encrypted or member.compress_type not in ZIP_METHODS:
        raise MigrationFailed(MigrationFailureCode.BAD_COMPRESSION)
    try:
        return archive.open(member)
    except (*ZIP_READ_ERRORS, RuntimeError):
        raise MigrationFailed(MigrationFailureCode.BAD_COMPRESSION) from None


@contextmanager
def open_payload(
    input_file: InputFile, budget: DecompressionBudget, limits: MigrationLimits
) -> Iterator[PayloadStream]:
    """The input's decompressed payload as a ``PayloadStream``. The importer passes the
    input's snapshot (``snapshot_input``), so the payload is the inspected bytes."""
    with open_input_file(input_file.path) as input_stream:
        decompressed: IO[bytes] = input_stream
        if input_file.container is InputContainer.GZIP:
            decompressed = gzip.GzipFile(fileobj=input_stream, mode="rb")  # type: ignore[assignment]
        elif input_file.container is InputContainer.ZIP:
            decompressed = open_zip_member(input_stream)
        with decompressed:
            yield PayloadStream(source=decompressed, budget=budget, limits=limits)
