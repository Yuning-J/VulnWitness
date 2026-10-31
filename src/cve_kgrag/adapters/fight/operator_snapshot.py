"""Load the operator's FiGHT snapshot: the full upstream ``fight.yaml`` an operator
supplies with an optional expected SHA-256 (ADR 0009 §11).

The file is opened once, as a regular file never reached through a symbolic link, and
every check runs on the bytes of that one open, never on a second open of the path: a
read within ``MAX_FIGHT_SNAPSHOT_BYTES`` checked while reading, the SHA-256 against the
optional expected value, the lookup in the reviewed catalog, and then the strict YAML parse.
The catalog is the one trust root: only a catalogued hash reaches the parser, and adding
a snapshot to it is a reviewed change that confirms the file holds no YAML anchor or
alias. A configured snapshot that fails any check is never replaced by the packaged
excerpt.
"""

from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import IO

from cve_kgrag.adapters.fight.pinned_yaml import FightSnapshotError, PinnedFightYamlSource
from cve_kgrag.adapters.regular_files import NotARegularFileError, open_regular_file
from cve_kgrag.domain.hashing import sha256_hex
from cve_kgrag.domain.threat_context import FightSnapshotCatalog

# The catalogued full 3.1.0 file is 1.1 MiB.
MAX_FIGHT_SNAPSHOT_BYTES = 4 * 1024 * 1024


class FightSnapshotFailure(StrEnum):
    """Why a configured FiGHT snapshot cannot be served; a command that uses FiGHT refuses
    to start."""

    MISSING = "fight_snapshot_missing"
    NOT_REGULAR_FILE = "fight_snapshot_not_regular_file"
    UNREADABLE = "fight_snapshot_unreadable"
    TOO_LARGE = "fight_snapshot_too_large"
    HASH_MISMATCH = "fight_snapshot_hash_mismatch"
    NOT_CATALOGUED = "fight_snapshot_not_catalogued"
    INVALID = "fight_snapshot_invalid"


class FightSnapshotUnavailable(Exception):
    """The configured snapshot cannot be served, for ``failure``; the message is the code
    alone, never a path, file content or the underlying error's text."""

    def __init__(self, failure: FightSnapshotFailure) -> None:
        super().__init__(failure.value)
        self.failure = failure


def read_snapshot_bytes(path: Path, open_file: Callable[[Path], IO[bytes]]) -> bytes:
    """At most ``MAX_FIGHT_SNAPSHOT_BYTES`` of the file, from one open."""
    try:
        snapshot_stream = open_file(path)
    except FileNotFoundError:
        raise FightSnapshotUnavailable(FightSnapshotFailure.MISSING) from None
    except NotARegularFileError:
        raise FightSnapshotUnavailable(FightSnapshotFailure.NOT_REGULAR_FILE) from None
    except OSError:
        raise FightSnapshotUnavailable(FightSnapshotFailure.UNREADABLE) from None
    try:
        with snapshot_stream:
            snapshot_bytes = snapshot_stream.read(MAX_FIGHT_SNAPSHOT_BYTES + 1)
    except OSError:
        raise FightSnapshotUnavailable(FightSnapshotFailure.UNREADABLE) from None
    if len(snapshot_bytes) > MAX_FIGHT_SNAPSHOT_BYTES:
        raise FightSnapshotUnavailable(FightSnapshotFailure.TOO_LARGE)
    return snapshot_bytes


def read_operator_fight_snapshot(
    path: Path,
    expected_sha256: str | None,
    snapshot_catalog: FightSnapshotCatalog,
    open_file: Callable[[Path], IO[bytes]] = open_regular_file,
) -> bytes:
    """Read once, compare an expected digest if supplied, and require the computed digest
    in the reviewed catalog. Raises ``FightSnapshotUnavailable``."""
    snapshot_bytes = read_snapshot_bytes(path, open_file)
    snapshot_sha256 = sha256_hex(snapshot_bytes)
    if expected_sha256 is not None and snapshot_sha256 != expected_sha256:
        raise FightSnapshotUnavailable(FightSnapshotFailure.HASH_MISMATCH)
    if snapshot_catalog.find(snapshot_sha256) is None:
        raise FightSnapshotUnavailable(FightSnapshotFailure.NOT_CATALOGUED)
    return snapshot_bytes


def load_operator_fight_snapshot(
    path: Path,
    expected_sha256: str | None,
    snapshot_catalog: FightSnapshotCatalog,
    clock: Callable[[], datetime],
    open_file: Callable[[Path], IO[bytes]] = open_regular_file,
) -> PinnedFightYamlSource:
    """The snapshot at ``path`` (``read_operator_fight_snapshot``), served as a FiGHT
    source. Raises ``FightSnapshotUnavailable``."""
    snapshot_bytes = read_operator_fight_snapshot(
        path, expected_sha256, snapshot_catalog, open_file
    )
    try:
        return PinnedFightYamlSource(
            snapshot_bytes, sha256_hex(snapshot_bytes), snapshot_catalog, clock
        )
    except FightSnapshotError:
        raise FightSnapshotUnavailable(FightSnapshotFailure.INVALID) from None
