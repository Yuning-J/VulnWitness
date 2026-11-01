"""Walk a legacy data tree read-only and count what it holds that is never imported: legacy
derived files and files never deserialized (ADR 0008 §1).

The walk is bounded like every input (``MigrationLimits``): it follows no symbolic link it
lists, descends a bounded number of levels and examines a bounded number of entries,
counted as each directory is listed. It reads a short prefix of a file to check its
magic bytes and, for a file that looks like JSON, a bounded prefix of it, within a total,
to tell its structure. A missing or unreadable root, passing a bound, an entry that
cannot be read, and one that changes or disappears during the walk each fail the run: a
partial count is never reported as the tree's. A directory is listed by path, so one
replaced by a symbolic link between being listed and being entered is not detected; the
walk assumes the operator's tree holds still while it runs.
"""

import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from operator import attrgetter
from pathlib import Path

from vulnwitness.adapters.migration.input_files import open_input_file
from vulnwitness.adapters.migration.migration_limits import MigrationLimits
from vulnwitness.domain.migration_report import (
    LegacyFileKind,
    MigrationFailed,
    MigrationFailureCode,
)

NUMPY_MAGIC = b"\x93NUMPY"
# Pickle protocols 2 to 5 open with PROTO and the protocol number.
PICKLE_PROTOCOL_PREFIXES = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05")
PICKLE_SUFFIXES = frozenset({".pkl", ".pickle"})
NUMPY_SUFFIXES = frozenset({".npy", ".npz"})
MODEL_SUFFIXES = frozenset({".pt", ".pth", ".bin", ".safetensors", ".h5", ".onnx", ".model"})
JSON_OPENERS = (b"{", b"[")

JsonClassifier = Callable[[bytes], LegacyFileKind | None]


@dataclass
class WalkBudget:
    entries_left: int
    fingerprint_bytes_left: int


def classify_by_magic(name: str, prefix: bytes) -> LegacyFileKind | None:
    """A file never to deserialize, by its name or its first bytes."""
    lower_name = name.lower()
    suffix = os.path.splitext(lower_name)[1]
    if suffix in PICKLE_SUFFIXES or prefix.startswith(PICKLE_PROTOCOL_PREFIXES):
        return LegacyFileKind.PICKLE
    if suffix in NUMPY_SUFFIXES or prefix.startswith(NUMPY_MAGIC):
        return LegacyFileKind.NUMPY_ARRAY
    if suffix in MODEL_SUFFIXES or lower_name.endswith(".model.zip"):
        return LegacyFileKind.MODEL_ARCHIVE
    return None


def read_file_prefix(path: Path, prefix_bytes: int) -> bytes:
    """At most ``prefix_bytes`` of the file; raises ``MigrationFailed``: changed when the
    listed file is gone or no longer a regular file, unreadable otherwise."""
    try:
        with open_input_file(path, MigrationFailureCode.LEGACY_ROOT_CHANGED) as file_stream:
            return file_stream.read(prefix_bytes)
    except MigrationFailed as failure:
        code = MigrationFailureCode.LEGACY_ROOT_UNREADABLE
        if failure.code in {
            MigrationFailureCode.INPUT_NOT_A_REGULAR_FILE,
            MigrationFailureCode.LEGACY_ROOT_CHANGED,
        }:
            code = MigrationFailureCode.LEGACY_ROOT_CHANGED
        raise MigrationFailed(code) from None
    except OSError:
        raise MigrationFailed(MigrationFailureCode.LEGACY_ROOT_UNREADABLE) from None


def classify_file(
    path: Path, classify_json_prefix: JsonClassifier, budget: WalkBudget, limits: MigrationLimits
) -> LegacyFileKind | None:
    prefix = read_file_prefix(path, limits.magic_prefix_bytes)
    magic_kind = classify_by_magic(path.name, prefix)
    if magic_kind is not None:
        return magic_kind
    if not prefix.lstrip().startswith(JSON_OPENERS):
        return None
    # The budget is charged what is read, so it fails only once the reading would pass it.
    readable_bytes = min(limits.max_fingerprint_file_bytes, budget.fingerprint_bytes_left + 1)
    json_prefix = read_file_prefix(path, readable_bytes)
    if len(json_prefix) > budget.fingerprint_bytes_left:
        raise MigrationFailed(MigrationFailureCode.LEGACY_ROOT_READ_BUDGET)
    budget.fingerprint_bytes_left -= len(json_prefix)
    return classify_json_prefix(json_prefix)


def list_directory(directory: Path, budget: WalkBudget) -> list[os.DirEntry[str]]:
    """The directory's entries by name, each charged to the budget as it is listed, so a
    huge directory fails before it is held whole."""
    listed_entries: list[os.DirEntry[str]] = []
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                budget.entries_left -= 1
                if budget.entries_left < 0:
                    raise MigrationFailed(MigrationFailureCode.LEGACY_ROOT_TOO_MANY_ENTRIES)
                listed_entries.append(entry)
    except FileNotFoundError:
        raise MigrationFailed(MigrationFailureCode.LEGACY_ROOT_CHANGED) from None
    except OSError:
        raise MigrationFailed(MigrationFailureCode.LEGACY_ROOT_UNREADABLE) from None
    listed_entries.sort(key=attrgetter("name"))
    return listed_entries


def check_legacy_root(legacy_root: Path) -> None:
    """Raise ``MigrationFailed`` (``legacy_root_unreadable``) unless the root is a
    directory, itself no symbolic link."""
    try:
        root_mode = os.lstat(legacy_root).st_mode
    except OSError:
        raise MigrationFailed(MigrationFailureCode.LEGACY_ROOT_UNREADABLE) from None
    if not stat.S_ISDIR(root_mode):
        raise MigrationFailed(MigrationFailureCode.LEGACY_ROOT_UNREADABLE)


def scan_legacy_root(
    legacy_root: Path, classify_json_prefix: JsonClassifier, limits: MigrationLimits
) -> dict[LegacyFileKind, int]:
    """How many files of each kind the tree under ``legacy_root`` holds; every kind is
    listed. Raises ``MigrationFailed`` when the walk passes a bound or meets an entry it
    cannot read or that changes."""
    findings: dict[LegacyFileKind, int] = dict.fromkeys(LegacyFileKind, 0)
    budget = WalkBudget(
        entries_left=limits.max_walk_entries,
        fingerprint_bytes_left=limits.max_fingerprint_total_bytes,
    )
    check_legacy_root(legacy_root)
    directories: list[tuple[Path, int]] = [(legacy_root, 0)]
    while directories:
        directory, depth = directories.pop()
        for entry in list_directory(directory, budget):
            try:
                if entry.is_symlink():
                    continue
                is_directory = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
            except OSError:
                raise MigrationFailed(MigrationFailureCode.LEGACY_ROOT_UNREADABLE) from None
            entry_path = Path(entry.path)
            if is_directory:
                if depth + 1 > limits.max_walk_depth:
                    raise MigrationFailed(MigrationFailureCode.LEGACY_ROOT_TOO_DEEP)
                directories.append((entry_path, depth + 1))
            elif is_file:
                file_kind = classify_file(entry_path, classify_json_prefix, budget, limits)
                if file_kind is not None:
                    findings[file_kind] += 1
    return findings
