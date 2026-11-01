"""``inspect_input_file``, ``snapshot_input`` and ``open_payload`` on real files under
``tmp_path``: an input is read only when it is a regular file reached without a symbolic
link; its container is told by its bytes; its file SHA-256 covers the bytes as supplied
while its payload SHA-256 is the same whichever container holds the payload; its snapshot
is a new owner-only file holding exactly the inspected bytes, and an input whose bytes
changed since inspection is refused as ``input_changed`` without copying more than one
chunk past its inspected size; a zip must hold exactly one unencrypted, stored or
deflated file, which its end record must declare before ``zipfile`` reads it; damaged
compression fails as ``bad_compression``; and the compressed, decompressed, total and
per-entry caps (ADR 0008 §1, §2, §8) hold at their boundaries."""

import gzip
import os
import stat
import struct
import subprocess
import sys
import threading
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from tests.support.legacy_inputs import (
    build_v2_entry,
    build_v2_feed,
    encode_feed,
    write_gzip_feed,
    write_plain_feed,
    write_zip_feed,
)
from vulnwitness.adapters.migration.input_files import (
    HASH_CHUNK_BYTES,
    ZIP_END_SIGNATURE,
    ZIP_MAX_ONE_MEMBER_DIRECTORY_BYTES,
    DecompressionBudget,
    InputFile,
    PayloadStream,
    check_zip_directory,
    inspect_input_file,
    open_payload,
    snapshot_input,
)
from vulnwitness.adapters.migration.migration_limits import MigrationLimits
from vulnwitness.domain.corpus_store_manifest import InputContainer
from vulnwitness.domain.migration_report import MigrationFailed, MigrationFailureCode

FEED = build_v2_feed([build_v2_entry(1), build_v2_entry(2)])
FEED_PAYLOAD = encode_feed(FEED)
OTHER_FEED_PAYLOAD = encode_feed(build_v2_feed([build_v2_entry(1), build_v2_entry(3)]))
# Small enough that every payload here is read in several chunks.
READ_CHUNK_BYTES = 97
# SHA-256 of the three bytes ``abc`` (FIPS 180-2, appendix B.1).
ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
DEFAULT_LIMITS = MigrationLimits()
# Long enough for any open that does not block; a blocking one never returns.
FIFO_OPEN_TIMEOUT_SECONDS = 5
# Where the central directory's size sits in the end-of-central-directory record, after
# its signature and four two-byte counts.
ZIP_DIRECTORY_SIZE_FIELD = struct.Struct("<L")
ZIP_DIRECTORY_SIZE_OFFSET = 12
# "Version needed to extract" in a central-directory header, after its signature and the
# "version made by" field; 166 reads as version 16.6, past any ``zipfile`` supports.
ZIP_CENTRAL_HEADER_SIGNATURE = b"PK\x01\x02"
ZIP_VERSION_NEEDED_OFFSET = 6
UNSUPPORTED_ZIP_VERSION = 166

FeedWriter = Callable[[Path, dict[str, Any]], Path]
FileWriter = Callable[[Path], Path]


def inspect_with_default_cap(path: Path) -> InputFile:
    return inspect_input_file(path, DEFAULT_LIMITS)


def drain(payload: PayloadStream) -> bytes:
    """Everything ``payload`` still holds, read a chunk at a time as a parser reads."""
    chunks: list[bytes] = []
    chunk = payload.read(READ_CHUNK_BYTES)
    while chunk:
        chunks.append(chunk)
        chunk = payload.read(READ_CHUNK_BYTES)
    return b"".join(chunks)


def read_whole_payload(
    input_file: InputFile,
    limits: MigrationLimits = DEFAULT_LIMITS,
    budget: DecompressionBudget | None = None,
) -> tuple[bytes, str]:
    """The input's decompressed payload and its payload SHA-256."""
    if budget is None:
        budget = DecompressionBudget(remaining_bytes=limits.max_total_decompressed_bytes)
    with open_payload(input_file, budget, limits) as payload:
        payload_bytes = drain(payload)
        return payload_bytes, payload.read_payload_sha256()


def write_payload_in(container: InputContainer, path: Path, payload_bytes: bytes) -> Path:
    """``payload_bytes`` written at ``path`` plain, gzipped or as a zip's one member."""
    if container is InputContainer.GZIP:
        path.write_bytes(gzip.compress(payload_bytes, mtime=0))
    elif container is InputContainer.ZIP:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("feed.json", payload_bytes)
    else:
        path.write_bytes(payload_bytes)
    return path


def link_to_file(path: Path) -> Path:
    target = write_plain_feed(path.with_name("real.json"), FEED)
    path.symlink_to(target)
    return path


def link_to_nothing(path: Path) -> Path:
    path.symlink_to(path.with_name("missing.json"))
    return path


def link_to_directory(path: Path) -> Path:
    target = path.with_name("real-directory")
    target.mkdir()
    path.symlink_to(target, target_is_directory=True)
    return path


def make_directory(path: Path) -> Path:
    path.mkdir()
    return path


def name_character_device(path: Path) -> Path:
    return Path(os.devnull)


def write_two_member_zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("feed.json", FEED_PAYLOAD)
        archive.writestr("second.json", FEED_PAYLOAD)
    return path


def write_zip_with_directory_and_file(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("feeds/", b"")
        archive.writestr("feeds/feed.json", FEED_PAYLOAD)
    return path


def write_directory_only_zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("feeds/", b"")
    return path


def write_encrypted_flag_zip(path: Path) -> Path:
    """A zip whose one member's general-purpose flag marks it encrypted, in both its local
    and its central directory header (``zipfile`` cannot write an encrypted member)."""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("feed.json", FEED_PAYLOAD)
    archive_bytes = bytearray(path.read_bytes())
    local_header_at = archive_bytes.find(b"PK\x03\x04")
    central_header_at = archive_bytes.find(b"PK\x01\x02")
    archive_bytes[local_header_at + 6] |= 0x1
    archive_bytes[central_header_at + 8] |= 0x1
    path.write_bytes(bytes(archive_bytes))
    return path


def write_bzip2_zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_BZIP2) as archive:
        archive.writestr("feed.json", FEED_PAYLOAD)
    return path


def write_lzma_zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_LZMA) as archive:
        archive.writestr("feed.json", FEED_PAYLOAD)
    return path


def write_zip_magic_then_junk(path: Path) -> Path:
    path.write_bytes(b"PK\x03\x04" + b"not a zip archive at all")
    return path


def write_zip_with_crc_mismatch(path: Path) -> Path:
    """A stored member one byte of whose data no longer matches its recorded CRC-32."""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("feed.json", FEED_PAYLOAD)
    archive_bytes = bytearray(path.read_bytes())
    payload_at = archive_bytes.find(FEED_PAYLOAD)
    archive_bytes[payload_at] = ord("[")
    path.write_bytes(bytes(archive_bytes))
    return path


def write_zip_with_corrupt_deflate(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("feed.json", FEED_PAYLOAD)
    archive_bytes = bytearray(path.read_bytes())
    data_at = archive_bytes.find(b"feed.json") + len("feed.json")
    for offset in range(4):
        archive_bytes[data_at + offset] ^= 0xFF
    path.write_bytes(bytes(archive_bytes))
    return path


def write_gzip_magic_then_junk(path: Path) -> Path:
    path.write_bytes(b"\x1f\x8b" + b"not a gzip stream at all")
    return path


def write_truncated_gzip(path: Path) -> Path:
    path.write_bytes(gzip.compress(FEED_PAYLOAD, mtime=0)[:-12])
    return path


def write_gzip_with_crc_mismatch(path: Path) -> Path:
    gzip_bytes = bytearray(gzip.compress(FEED_PAYLOAD, mtime=0))
    # The trailer is the payload's CRC-32 then its length, four bytes each.
    gzip_bytes[-8] ^= 0xFF
    path.write_bytes(bytes(gzip_bytes))
    return path


def write_zip_needing_an_unsupported_version(path: Path) -> Path:
    """A one-member zip whose central directory asks for a version ``zipfile`` refuses
    with ``NotImplementedError``."""
    write_zip_feed(path, FEED)
    archive_bytes = bytearray(path.read_bytes())
    central_header_at = archive_bytes.find(ZIP_CENTRAL_HEADER_SIGNATURE)
    archive_bytes[central_header_at + ZIP_VERSION_NEEDED_OFFSET] = UNSUPPORTED_ZIP_VERSION
    path.write_bytes(bytes(archive_bytes))
    return path


def write_zip_declaring_directory_bytes(path: Path, directory_bytes: int) -> Path:
    """A one-member zip whose end record declares a central directory of
    ``directory_bytes``, whatever the directory really holds."""
    write_zip_feed(path, FEED)
    archive_bytes = bytearray(path.read_bytes())
    size_field_at = archive_bytes.rfind(ZIP_END_SIGNATURE) + ZIP_DIRECTORY_SIZE_OFFSET
    ZIP_DIRECTORY_SIZE_FIELD.pack_into(archive_bytes, size_field_at, directory_bytes)
    path.write_bytes(bytes(archive_bytes))
    return path


def write_zip_declaring_the_largest_one_member_directory(path: Path) -> Path:
    return write_zip_declaring_directory_bytes(path, ZIP_MAX_ONE_MEMBER_DIRECTORY_BYTES)


def write_zip_declaring_a_directory_past_one_member(path: Path) -> Path:
    return write_zip_declaring_directory_bytes(path, ZIP_MAX_ONE_MEMBER_DIRECTORY_BYTES + 1)


def write_zip_with_its_end_record_cut_short(path: Path) -> Path:
    write_zip_feed(path, FEED)
    path.write_bytes(path.read_bytes()[:-4])
    return path


def write_one_member_zip(path: Path) -> Path:
    return write_zip_feed(path, FEED)


def rewrite_in_place_with_other_bytes_of_the_same_size(path: Path) -> None:
    with path.open("r+b") as input_stream:
        input_stream.write(OTHER_FEED_PAYLOAD)


def replace_by_rename(path: Path) -> None:
    replacement_path = path.with_name("replacement.json")
    replacement_path.write_bytes(OTHER_FEED_PAYLOAD)
    replacement_path.replace(path)


def truncate_by_one_byte(path: Path) -> None:
    os.truncate(path, path.stat().st_size - 1)


def grow_by_one_byte(path: Path) -> None:
    with path.open("ab") as input_stream:
        input_stream.write(b" ")


def grow_by_more_than_a_chunk(path: Path) -> None:
    with path.open("ab") as input_stream:
        input_stream.write(b" " * (HASH_CHUNK_BYTES + 1))


@dataclass
class InspectionOutcome:
    """What an inspection run on another thread raised, once it has returned."""

    raised: BaseException | None = None


def inspect_recording_what_it_raises(path: Path, outcome: InspectionOutcome) -> None:
    try:
        inspect_with_default_cap(path)
    except BaseException as error:
        outcome.raised = error


@pytest.mark.parametrize(
    ("write_feed", "expected_container"),
    [
        (write_plain_feed, InputContainer.PLAIN),
        (write_gzip_feed, InputContainer.GZIP),
        (write_zip_feed, InputContainer.ZIP),
    ],
    ids=["plain", "gzip", "zip"],
)
def test_inspect_input_file_tells_the_container_by_its_first_bytes(
    tmp_path: Path, write_feed: FeedWriter, expected_container: InputContainer
) -> None:
    # The name says nothing of the container; only the bytes do.
    path = write_feed(tmp_path / "feed.bin", FEED)

    input_file = inspect_with_default_cap(path)

    assert input_file.container is expected_container


def test_inspect_input_file_records_path_size_and_sha256_of_the_file_bytes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "abc.json"
    path.write_bytes(b"abc")

    input_file = inspect_with_default_cap(path)

    assert input_file == InputFile(
        path=path, size_bytes=3, container=InputContainer.PLAIN, sha256=ABC_SHA256
    )


@pytest.mark.parametrize("write_feed", [write_gzip_feed, write_zip_feed], ids=["gzip", "zip"])
def test_input_file_sha256_of_a_compressed_input_differs_from_its_payload_sha256(
    tmp_path: Path, write_feed: FeedWriter
) -> None:
    input_file = inspect_with_default_cap(write_feed(tmp_path / "feed.bin", FEED))

    _, payload_sha256 = read_whole_payload(input_file)

    assert input_file.sha256 != payload_sha256


@pytest.mark.parametrize(
    "make_path",
    [link_to_file, link_to_nothing, link_to_directory, make_directory, name_character_device],
    ids=[
        "symlink_to_a_file",
        "dangling_symlink",
        "symlink_to_a_directory",
        "directory",
        "character_device",
    ],
)
def test_inspect_input_file_refuses_anything_but_a_regular_file_as_not_a_regular_file(
    tmp_path: Path, make_path: FileWriter
) -> None:
    path = make_path(tmp_path / "input.json")

    with pytest.raises(MigrationFailed) as failure:
        inspect_with_default_cap(path)

    assert failure.value.code is MigrationFailureCode.INPUT_NOT_A_REGULAR_FILE


def test_inspect_input_file_refuses_a_fifo_without_a_writer_at_once(tmp_path: Path) -> None:
    """Opening a FIFO for reading would wait for a writer; the input is opened without
    blocking and refused before any read. The inspection runs on a daemon thread, so an
    open that blocks fails the test instead of hanging the suite."""
    fifo_path = tmp_path / "feed.json"
    os.mkfifo(fifo_path)
    outcome = InspectionOutcome()
    inspection = threading.Thread(
        target=inspect_recording_what_it_raises, args=(fifo_path, outcome), daemon=True
    )

    inspection.start()
    inspection.join(timeout=FIFO_OPEN_TIMEOUT_SECONDS)

    assert not inspection.is_alive()
    assert isinstance(outcome.raised, MigrationFailed)
    assert outcome.raised.code is MigrationFailureCode.INPUT_NOT_A_REGULAR_FILE


def test_inspect_input_file_reports_a_missing_file_as_unreadable(tmp_path: Path) -> None:
    path = tmp_path / "missing.json"

    with pytest.raises(MigrationFailed) as failure:
        inspect_with_default_cap(path)

    assert failure.value.code is MigrationFailureCode.INPUT_UNREADABLE


def test_inspect_input_file_reports_a_file_without_read_permission_as_unreadable(
    tmp_path: Path,
) -> None:
    path = write_plain_feed(tmp_path / "feed.json", FEED)
    path.chmod(0o000)

    try:
        with pytest.raises(MigrationFailed) as failure:
            inspect_with_default_cap(path)
    finally:
        path.chmod(0o600)

    assert failure.value.code is MigrationFailureCode.INPUT_UNREADABLE


# A compressed file is capped by its size; plain bytes are their own payload, so the
# decompressed cap bounds them.
SIZE_CAPS = [
    (
        write_plain_feed,
        "max_decompressed_file_bytes",
        MigrationFailureCode.DECOMPRESSED_FILE_TOO_LARGE,
    ),
    (write_gzip_feed, "max_compressed_file_bytes", MigrationFailureCode.COMPRESSED_FILE_TOO_LARGE),
    (write_zip_feed, "max_compressed_file_bytes", MigrationFailureCode.COMPRESSED_FILE_TOO_LARGE),
]


@pytest.mark.parametrize(
    ("write_feed", "cap_name", "code"), SIZE_CAPS, ids=["plain", "gzip", "zip"]
)
def test_inspect_input_file_accepts_a_file_exactly_at_its_container_cap(
    tmp_path: Path, write_feed: FeedWriter, cap_name: str, code: MigrationFailureCode
) -> None:
    path = write_feed(tmp_path / "feed.bin", FEED)
    file_size = path.stat().st_size

    input_file = inspect_input_file(path, MigrationLimits(**{cap_name: file_size}))

    assert input_file.size_bytes == file_size


@pytest.mark.parametrize(
    ("write_feed", "cap_name", "code"), SIZE_CAPS, ids=["plain", "gzip", "zip"]
)
def test_inspect_input_file_refuses_a_file_one_byte_over_its_container_cap(
    tmp_path: Path, write_feed: FeedWriter, cap_name: str, code: MigrationFailureCode
) -> None:
    path = write_feed(tmp_path / "feed.bin", FEED)
    file_size = path.stat().st_size

    with pytest.raises(MigrationFailed) as failure:
        inspect_input_file(path, MigrationLimits(**{cap_name: file_size - 1}))

    assert failure.value.code is code


def test_inspect_input_file_lets_a_plain_feed_past_the_compressed_cap(tmp_path: Path) -> None:
    path = write_plain_feed(tmp_path / "feed.json", FEED)
    file_size = path.stat().st_size

    input_file = inspect_input_file(
        path,
        MigrationLimits(
            max_compressed_file_bytes=file_size - 1, max_decompressed_file_bytes=file_size
        ),
    )

    assert input_file.size_bytes == file_size


@pytest.mark.parametrize(
    "write_feed", [write_plain_feed, write_gzip_feed, write_zip_feed], ids=["plain", "gzip", "zip"]
)
def test_open_payload_yields_the_decompressed_payload_bytes(
    tmp_path: Path, write_feed: FeedWriter
) -> None:
    input_file = inspect_with_default_cap(write_feed(tmp_path / "feed.bin", FEED))

    payload_bytes, _ = read_whole_payload(input_file)

    assert payload_bytes == FEED_PAYLOAD


@pytest.mark.parametrize("write_feed", [write_gzip_feed, write_zip_feed], ids=["gzip", "zip"])
def test_payload_sha256_of_a_compressed_input_equals_that_of_the_same_payload_plain(
    tmp_path: Path, write_feed: FeedWriter
) -> None:
    plain_file = inspect_with_default_cap(write_plain_feed(tmp_path / "plain.json", FEED))
    compressed_file = inspect_with_default_cap(write_feed(tmp_path / "feed.bin", FEED))

    _, plain_payload_sha256 = read_whole_payload(plain_file)
    _, compressed_payload_sha256 = read_whole_payload(compressed_file)

    assert compressed_payload_sha256 == plain_payload_sha256


def test_payload_sha256_of_a_plain_input_equals_its_file_sha256(tmp_path: Path) -> None:
    input_file = inspect_with_default_cap(write_plain_feed(tmp_path / "feed.json", FEED))

    _, payload_sha256 = read_whole_payload(input_file)

    assert payload_sha256 == input_file.sha256


def test_open_payload_reads_a_zip_member_whatever_its_name(tmp_path: Path) -> None:
    path = write_zip_feed(tmp_path / "feed.zip", FEED, member_name="renamed/anything.txt")
    input_file = inspect_with_default_cap(path)

    payload_bytes, _ = read_whole_payload(input_file)

    assert payload_bytes == FEED_PAYLOAD


@pytest.mark.parametrize(
    "write_input",
    [
        write_two_member_zip,
        write_zip_with_directory_and_file,
        write_directory_only_zip,
        write_encrypted_flag_zip,
        write_bzip2_zip,
        write_lzma_zip,
        write_zip_magic_then_junk,
        write_zip_with_crc_mismatch,
        write_zip_with_corrupt_deflate,
        write_gzip_magic_then_junk,
        write_truncated_gzip,
        write_gzip_with_crc_mismatch,
        write_zip_needing_an_unsupported_version,
    ],
    ids=[
        "zip_with_two_members",
        "zip_with_a_directory_and_a_file",
        "zip_with_only_a_directory_member",
        "zip_member_flagged_encrypted",
        "zip_member_bzip2_compressed",
        "zip_member_lzma_compressed",
        "zip_magic_then_junk",
        "zip_member_failing_its_crc",
        "zip_member_with_corrupt_deflate_data",
        "gzip_magic_then_junk",
        "truncated_gzip",
        "gzip_failing_its_crc",
        "zip_needing_an_unsupported_version",
    ],
)
def test_reading_a_container_that_is_not_one_clean_member_fails_as_bad_compression(
    tmp_path: Path, write_input: FileWriter
) -> None:
    input_file = inspect_with_default_cap(write_input(tmp_path / "feed.bin"))

    with pytest.raises(MigrationFailed) as failure:
        read_whole_payload(input_file)

    assert failure.value.code is MigrationFailureCode.BAD_COMPRESSION


@pytest.mark.parametrize(
    "write_input",
    [write_one_member_zip, write_zip_declaring_the_largest_one_member_directory],
    ids=["one_member_zip", "directory_declared_at_the_one_member_maximum"],
)
def test_check_zip_directory_accepts_one_member_and_rewinds_the_stream(
    tmp_path: Path, write_input: FileWriter
) -> None:
    path = write_input(tmp_path / "feed.zip")

    with path.open("rb") as zip_stream:
        check_zip_directory(zip_stream)
        stream_position = zip_stream.tell()

    assert stream_position == 0


@pytest.mark.parametrize(
    "write_input",
    [
        write_two_member_zip,
        write_zip_declaring_a_directory_past_one_member,
        write_zip_magic_then_junk,
        write_zip_with_its_end_record_cut_short,
    ],
    ids=[
        "end_record_declaring_two_members",
        "directory_one_byte_past_one_member",
        "no_end_record",
        "end_record_cut_short",
    ],
)
def test_check_zip_directory_refuses_an_end_record_not_for_one_member_as_bad_compression(
    tmp_path: Path, write_input: FileWriter
) -> None:
    """The end record is checked before ``zipfile`` reads the central directory, so a
    huge directory is never read into memory."""
    path = write_input(tmp_path / "feed.zip")

    with path.open("rb") as zip_stream, pytest.raises(MigrationFailed) as failure:
        check_zip_directory(zip_stream)

    assert failure.value.code is MigrationFailureCode.BAD_COMPRESSION


# Copies an inspected input under a file-size limit, as a full disk would cut it short,
# and prints the failure code. It runs in its own process, so the limit binds no other
# test; SIGXFSZ is ignored so the write fails with EFBIG instead of killing the process.
SNAPSHOT_UNDER_A_SIZE_LIMIT = """
import resource
import signal
import sys
from pathlib import Path

from vulnwitness.adapters.migration.input_files import inspect_input_file, snapshot_input
from vulnwitness.adapters.migration.migration_limits import MigrationLimits
from vulnwitness.domain.migration_report import MigrationFailed

input_path, snapshot_path, size_limit = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
input_file = inspect_input_file(input_path, MigrationLimits())
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
resource.setrlimit(resource.RLIMIT_FSIZE, (size_limit, size_limit))
try:
    snapshot_input(input_file, snapshot_path)
except MigrationFailed as failure:
    print(failure.code.value)
"""


@pytest.fixture
def snapshot_path(tmp_path: Path) -> Path:
    """Where the copy goes: a path in an empty directory standing in for a run's staging
    directory."""
    staging_dir = tmp_path / "staging"
    staging_dir.mkdir()
    return staging_dir / "input.snapshot"


@pytest.fixture
def umask_zero() -> Iterator[None]:
    """The process umask cleared for the test, so a file's mode is the one it was created
    with; the previous umask comes back afterwards."""
    previous_umask = os.umask(0)
    try:
        yield
    finally:
        os.umask(previous_umask)


@pytest.mark.parametrize(
    "write_feed",
    [write_plain_feed, write_gzip_feed, write_zip_feed],
    ids=["plain", "gzip", "zip"],
)
def test_snapshot_input_copies_an_unchanged_input_byte_for_byte(
    tmp_path: Path, snapshot_path: Path, write_feed: FeedWriter
) -> None:
    path = write_feed(tmp_path / "feed.bin", FEED)
    input_file = inspect_with_default_cap(path)

    snapshot_input(input_file, snapshot_path)

    assert snapshot_path.read_bytes() == path.read_bytes()


@pytest.mark.parametrize(
    "write_feed",
    [write_plain_feed, write_gzip_feed, write_zip_feed],
    ids=["plain", "gzip", "zip"],
)
def test_snapshot_input_describes_the_copy_with_the_inspected_size_container_and_sha256(
    tmp_path: Path, snapshot_path: Path, write_feed: FeedWriter
) -> None:
    input_file = inspect_with_default_cap(write_feed(tmp_path / "feed.bin", FEED))

    snapshot = snapshot_input(input_file, snapshot_path)

    assert snapshot == InputFile(
        path=snapshot_path,
        size_bytes=input_file.size_bytes,
        container=input_file.container,
        sha256=input_file.sha256,
    )


# OTHER_FEED_PAYLOAD is exactly as long as FEED_PAYLOAD, so only the bytes tell a file
# rewritten with it apart.
@pytest.mark.parametrize(
    "alter_input",
    [
        rewrite_in_place_with_other_bytes_of_the_same_size,
        replace_by_rename,
        truncate_by_one_byte,
        grow_by_one_byte,
        grow_by_more_than_a_chunk,
    ],
    ids=[
        "rewritten_in_place",
        "renamed_over",
        "truncated",
        "grown_by_one_byte",
        "grown_by_more_than_a_chunk",
    ],
)
def test_snapshot_input_refuses_an_input_altered_since_inspection_as_input_changed(
    tmp_path: Path, snapshot_path: Path, alter_input: Callable[[Path], None]
) -> None:
    path = write_plain_feed(tmp_path / "feed.json", FEED)
    input_file = inspect_with_default_cap(path)
    alter_input(path)

    with pytest.raises(MigrationFailed) as failure:
        snapshot_input(input_file, snapshot_path)

    assert failure.value.code is MigrationFailureCode.INPUT_CHANGED


def test_snapshot_input_never_copies_past_the_inspected_size_of_a_grown_input(
    tmp_path: Path, snapshot_path: Path
) -> None:
    # The staging budget makes room for the inspected size, so the copy must stay within it.
    path = write_plain_feed(tmp_path / "feed.json", FEED)
    input_file = inspect_with_default_cap(path)
    with path.open("ab") as input_stream:
        input_stream.write(b" " * (3 * HASH_CHUNK_BYTES))

    with pytest.raises(MigrationFailed) as failure:
        snapshot_input(input_file, snapshot_path)

    assert failure.value.code is MigrationFailureCode.INPUT_CHANGED
    assert snapshot_path.stat().st_size == input_file.size_bytes


def test_snapshot_input_reports_an_input_removed_since_inspection_as_unreadable(
    tmp_path: Path, snapshot_path: Path
) -> None:
    path = write_plain_feed(tmp_path / "feed.json", FEED)
    input_file = inspect_with_default_cap(path)
    path.unlink()

    with pytest.raises(MigrationFailed) as failure:
        snapshot_input(input_file, snapshot_path)

    assert failure.value.code is MigrationFailureCode.INPUT_UNREADABLE


def test_snapshot_input_refuses_an_existing_snapshot_path_as_staging_failed_leaving_it_as_it_was(
    tmp_path: Path, snapshot_path: Path
) -> None:
    input_file = inspect_with_default_cap(write_plain_feed(tmp_path / "feed.json", FEED))
    snapshot_path.write_bytes(b"left by another process")

    with pytest.raises(MigrationFailed) as failure:
        snapshot_input(input_file, snapshot_path)

    assert failure.value.code is MigrationFailureCode.STAGING_FAILED
    assert snapshot_path.read_bytes() == b"left by another process"


def test_snapshot_input_refuses_a_symlink_at_the_snapshot_path_leaving_its_target_as_it_was(
    tmp_path: Path, snapshot_path: Path
) -> None:
    input_file = inspect_with_default_cap(write_plain_feed(tmp_path / "feed.json", FEED))
    link_target = tmp_path / "elsewhere.json"
    link_target.write_bytes(b"not the run's to write")
    snapshot_path.symlink_to(link_target)

    with pytest.raises(MigrationFailed) as failure:
        snapshot_input(input_file, snapshot_path)

    assert failure.value.code is MigrationFailureCode.STAGING_FAILED
    assert link_target.read_bytes() == b"not the run's to write"


def test_snapshot_input_never_creates_the_target_of_a_dangling_symlink_at_the_snapshot_path(
    tmp_path: Path, snapshot_path: Path
) -> None:
    input_file = inspect_with_default_cap(write_plain_feed(tmp_path / "feed.json", FEED))
    link_target = tmp_path / "elsewhere.json"
    snapshot_path.symlink_to(link_target)

    with pytest.raises(MigrationFailed) as failure:
        snapshot_input(input_file, snapshot_path)

    assert failure.value.code is MigrationFailureCode.STAGING_FAILED
    assert not link_target.exists()


@pytest.mark.usefixtures("umask_zero")
def test_snapshot_input_creates_the_copy_readable_by_its_owner_alone_even_under_umask_zero(
    tmp_path: Path, snapshot_path: Path
) -> None:
    input_file = inspect_with_default_cap(write_plain_feed(tmp_path / "feed.json", FEED))

    snapshot_input(input_file, snapshot_path)

    assert stat.S_IMODE(snapshot_path.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "write_feed",
    [write_plain_feed, write_gzip_feed, write_zip_feed],
    ids=["plain", "gzip", "zip"],
)
def test_open_payload_reads_the_snapshot_it_is_given_once_the_input_is_gone(
    tmp_path: Path, snapshot_path: Path, write_feed: FeedWriter
) -> None:
    path = write_feed(tmp_path / "feed.bin", FEED)
    snapshot = snapshot_input(inspect_with_default_cap(path), snapshot_path)
    path.unlink()

    payload_bytes, _ = read_whole_payload(snapshot)

    assert payload_bytes == FEED_PAYLOAD


def test_open_payload_refuses_an_input_replaced_by_a_symlink_after_inspection(
    tmp_path: Path,
) -> None:
    path = write_plain_feed(tmp_path / "feed.json", FEED)
    input_file = inspect_with_default_cap(path)
    other_path = write_plain_feed(tmp_path / "other.json", FEED)
    path.unlink()
    path.symlink_to(other_path)

    with pytest.raises(MigrationFailed) as failure:
        read_whole_payload(input_file)

    assert failure.value.code is MigrationFailureCode.INPUT_NOT_A_REGULAR_FILE


@pytest.mark.parametrize(
    "container",
    [InputContainer.PLAIN, InputContainer.GZIP, InputContainer.ZIP],
    ids=["plain", "gzip", "zip"],
)
def test_payload_exactly_at_the_decompressed_file_cap_is_read_whole(
    tmp_path: Path, container: InputContainer
) -> None:
    payload_bytes = b" " * 4096
    limits = MigrationLimits(max_decompressed_file_bytes=len(payload_bytes))
    input_file = inspect_with_default_cap(
        write_payload_in(container, tmp_path / "f", payload_bytes)
    )

    read_bytes, _ = read_whole_payload(input_file, limits)

    assert read_bytes == payload_bytes


@pytest.mark.parametrize(
    "container",
    [InputContainer.PLAIN, InputContainer.GZIP, InputContainer.ZIP],
    ids=["plain", "gzip", "zip"],
)
def test_payload_one_byte_over_the_decompressed_file_cap_fails_as_too_large(
    tmp_path: Path, container: InputContainer
) -> None:
    payload_bytes = b" " * 4097
    limits = MigrationLimits(max_decompressed_file_bytes=4096)
    input_file = inspect_with_default_cap(
        write_payload_in(container, tmp_path / "f", payload_bytes)
    )

    with pytest.raises(MigrationFailed) as failure:
        read_whole_payload(input_file, limits)

    assert failure.value.code is MigrationFailureCode.DECOMPRESSED_FILE_TOO_LARGE


@pytest.mark.parametrize(
    "container", [InputContainer.GZIP, InputContainer.ZIP], ids=["gzip", "zip"]
)
def test_decompressed_cap_counts_bytes_inflated_not_the_compressed_size(
    tmp_path: Path, container: InputContainer
) -> None:
    # A megabyte of zeros compresses to about a kilobyte: the compressed cap lets it in,
    # the decompressed cap stops it.
    path = write_payload_in(container, tmp_path / "f", b"\0" * (1024 * 1024))
    limits = MigrationLimits(
        max_compressed_file_bytes=16 * 1024, max_decompressed_file_bytes=64 * 1024
    )
    input_file = inspect_input_file(path, limits)

    with pytest.raises(MigrationFailed) as failure:
        read_whole_payload(input_file, limits)

    assert failure.value.code is MigrationFailureCode.DECOMPRESSED_FILE_TOO_LARGE


def test_inputs_sharing_a_budget_may_read_exactly_the_total_together(tmp_path: Path) -> None:
    first_file = inspect_with_default_cap(
        write_payload_in(InputContainer.GZIP, tmp_path / "a", b"a" * 600)
    )
    second_file = inspect_with_default_cap(
        write_payload_in(InputContainer.ZIP, tmp_path / "b", b"b" * 400)
    )
    limits = MigrationLimits(max_total_decompressed_bytes=1000)
    budget = DecompressionBudget(remaining_bytes=limits.max_total_decompressed_bytes)

    read_whole_payload(first_file, limits, budget)
    read_whole_payload(second_file, limits, budget)

    assert budget.remaining_bytes == 0


def test_input_reading_past_the_shared_total_fails_as_total_too_large(tmp_path: Path) -> None:
    first_file = inspect_with_default_cap(
        write_payload_in(InputContainer.GZIP, tmp_path / "a", b"a" * 600)
    )
    second_file = inspect_with_default_cap(
        write_payload_in(InputContainer.ZIP, tmp_path / "b", b"b" * 401)
    )
    # Each file is under the per-file cap; together they are one byte over the total.
    limits = MigrationLimits(max_decompressed_file_bytes=1000, max_total_decompressed_bytes=1000)
    budget = DecompressionBudget(remaining_bytes=limits.max_total_decompressed_bytes)
    read_whole_payload(first_file, limits, budget)

    with pytest.raises(MigrationFailed) as failure:
        read_whole_payload(second_file, limits, budget)

    assert failure.value.code is MigrationFailureCode.TOTAL_TOO_LARGE


ENTRY_LIMITS = MigrationLimits(max_entry_bytes=10, parser_buffer_bytes=4)
ENTRY_PAYLOAD = bytes(range(100))


def test_entry_may_read_its_cap_plus_one_parser_buffer(tmp_path: Path) -> None:
    input_file = inspect_with_default_cap(
        write_payload_in(InputContainer.PLAIN, tmp_path / "f", ENTRY_PAYLOAD)
    )
    budget = DecompressionBudget(remaining_bytes=ENTRY_LIMITS.max_total_decompressed_bytes)

    with open_payload(input_file, budget, ENTRY_LIMITS) as payload:
        payload.read(50)
        payload.begin_entry()
        entry_bytes = payload.read(14)

    assert entry_bytes == ENTRY_PAYLOAD[50:64]


def test_entry_reading_one_byte_past_its_cap_plus_one_buffer_fails_as_too_large(
    tmp_path: Path,
) -> None:
    input_file = inspect_with_default_cap(
        write_payload_in(InputContainer.PLAIN, tmp_path / "f", ENTRY_PAYLOAD)
    )
    budget = DecompressionBudget(remaining_bytes=ENTRY_LIMITS.max_total_decompressed_bytes)

    with open_payload(input_file, budget, ENTRY_LIMITS) as payload:
        payload.read(50)
        payload.begin_entry()
        payload.read(14)
        with pytest.raises(MigrationFailed) as failure:
            payload.read(1)

    assert failure.value.code is MigrationFailureCode.ENTRY_TOO_LARGE


def test_single_read_larger_than_the_entry_cap_fails_as_too_large(tmp_path: Path) -> None:
    input_file = inspect_with_default_cap(
        write_payload_in(InputContainer.PLAIN, tmp_path / "f", ENTRY_PAYLOAD)
    )
    budget = DecompressionBudget(remaining_bytes=ENTRY_LIMITS.max_total_decompressed_bytes)

    with open_payload(input_file, budget, ENTRY_LIMITS) as payload:
        payload.begin_entry()
        with pytest.raises(MigrationFailed) as failure:
            payload.read(15)

    assert failure.value.code is MigrationFailureCode.ENTRY_TOO_LARGE


def test_reads_after_end_entry_are_not_counted_against_the_entry_cap(tmp_path: Path) -> None:
    input_file = inspect_with_default_cap(
        write_payload_in(InputContainer.PLAIN, tmp_path / "f", ENTRY_PAYLOAD)
    )
    budget = DecompressionBudget(remaining_bytes=ENTRY_LIMITS.max_total_decompressed_bytes)

    with open_payload(input_file, budget, ENTRY_LIMITS) as payload:
        payload.begin_entry()
        payload.read(14)
        payload.end_entry()
        rest_bytes = drain(payload)

    assert rest_bytes == ENTRY_PAYLOAD[14:]


def test_each_begin_entry_starts_a_fresh_entry_count(tmp_path: Path) -> None:
    input_file = inspect_with_default_cap(
        write_payload_in(InputContainer.PLAIN, tmp_path / "f", ENTRY_PAYLOAD)
    )
    budget = DecompressionBudget(remaining_bytes=ENTRY_LIMITS.max_total_decompressed_bytes)

    with open_payload(input_file, budget, ENTRY_LIMITS) as payload:
        payload.begin_entry()
        payload.read(14)
        payload.end_entry()
        payload.begin_entry()
        second_entry_bytes = payload.read(14)

    assert second_entry_bytes == ENTRY_PAYLOAD[14:28]


@pytest.mark.parametrize(
    ("input_bytes", "size_limit"),
    [(5_000, 4_000), (3 * 1024 * 1024, 1024 * 1024)],
    ids=["failing_when_the_copy_is_closed", "failing_while_the_copy_is_written"],
)
def test_snapshot_input_cut_short_by_a_full_disk_fails_as_staging_failed(
    tmp_path: Path, snapshot_path: Path, input_bytes: int, size_limit: int
) -> None:
    # A small copy fits the write buffer whole, so the disk refuses it only when the copy
    # is closed; a large one is refused by a write.
    input_path = tmp_path / "feed.json"
    input_path.write_bytes(b"x" * input_bytes)

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            SNAPSHOT_UNDER_A_SIZE_LIMIT,
            str(input_path),
            str(snapshot_path),
            str(size_limit),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert (completed.returncode, completed.stdout.strip()) == (0, "staging_failed")
