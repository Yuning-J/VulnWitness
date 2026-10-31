"""Proves the operator FiGHT snapshot's load (ADR 0009 §11): one open of a regular file,
then the cap, the pin, the catalog and the strict parse on those same bytes; every
failure is one fixed code with no path, content or exception text, and a configured
snapshot is never replaced by the packaged excerpt."""

import io
import os
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import IO

import pytest

from cve_kgrag.adapters.fight.operator_snapshot import (
    MAX_FIGHT_SNAPSHOT_BYTES,
    FightSnapshotFailure,
    FightSnapshotUnavailable,
    load_operator_fight_snapshot,
)
from cve_kgrag.adapters.fight.snapshot_catalog import (
    default_fight_snapshot_catalog_file,
    load_fight_snapshot_catalog,
)
from cve_kgrag.adapters.regular_files import open_regular_file
from cve_kgrag.composition import load_fight_source
from cve_kgrag.domain.hashing import sha256_hex
from cve_kgrag.domain.threat_context import FightSnapshotCatalog, SnapshotCoverage
from cve_kgrag.settings import FightSnapshotSettings
from tests.support.builders import build_catalog, build_known_snapshot
from tests.support.clocks import read_fixed_clock
from tests.support.fight_excerpt import EXCERPT_BYTES, EXCERPT_SHA256


@pytest.fixture
def packaged_catalog() -> FightSnapshotCatalog:
    return load_fight_snapshot_catalog(default_fight_snapshot_catalog_file())


@pytest.fixture
def snapshot_path(tmp_path: Path) -> Path:
    """The packaged excerpt, copied where an operator would put a snapshot."""
    snapshot_path = tmp_path / "fight.yaml"
    snapshot_path.write_bytes(EXCERPT_BYTES)
    return snapshot_path


def expect_failure(
    load: Callable[[], object], failure: FightSnapshotFailure, *absent_texts: str
) -> None:
    with pytest.raises(FightSnapshotUnavailable) as raised:
        load()
    assert raised.value.failure is failure
    described_error = "".join(traceback.format_exception(raised.value))
    assert str(raised.value) == failure.value
    for absent_text in absent_texts:
        assert absent_text not in described_error


def test_catalogued_snapshot_at_its_pin_is_served_with_its_catalog_coverage(
    snapshot_path: Path, packaged_catalog: FightSnapshotCatalog
) -> None:
    fight_source = load_operator_fight_snapshot(
        snapshot_path, EXCERPT_SHA256, packaged_catalog, read_fixed_clock
    )

    snapshot_info = fight_source.describe()
    assert snapshot_info.snapshot_sha256 == EXCERPT_SHA256
    assert snapshot_info.coverage is SnapshotCoverage.EXCERPT
    assert len(fight_source.list_techniques()) == snapshot_info.technique_count


def test_settings_without_a_snapshot_serve_the_packaged_excerpt() -> None:
    fight_source, pinned_snapshot = load_fight_source(None, read_fixed_clock)

    assert pinned_snapshot is not None
    assert pinned_snapshot.snapshot_sha256 == EXCERPT_SHA256
    assert fight_source.describe() is not None


def test_settings_with_a_snapshot_serve_it_and_its_catalog_entry(snapshot_path: Path) -> None:
    fight_source, pinned_snapshot = load_fight_source(
        FightSnapshotSettings(path=snapshot_path, sha256=EXCERPT_SHA256), read_fixed_clock
    )

    assert pinned_snapshot is not None
    assert pinned_snapshot.snapshot_sha256 == EXCERPT_SHA256
    assert fight_source.describe() is not None


def test_missing_snapshot_is_refused_and_never_replaced_by_the_excerpt(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.yaml"

    expect_failure(
        lambda: load_fight_source(
            FightSnapshotSettings(path=missing_path, sha256=EXCERPT_SHA256), read_fixed_clock
        ),
        FightSnapshotFailure.MISSING,
        str(missing_path),
    )


@pytest.mark.parametrize("kind", ["symbolic_link", "directory", "fifo"])
def test_snapshot_that_is_not_a_regular_file_is_refused(
    tmp_path: Path, snapshot_path: Path, packaged_catalog: FightSnapshotCatalog, kind: str
) -> None:
    configured_path = tmp_path / "configured.yaml"
    if kind == "symbolic_link":
        configured_path.symlink_to(snapshot_path)
    elif kind == "directory":
        configured_path.mkdir()
    else:
        os.mkfifo(configured_path)

    expect_failure(
        lambda: load_operator_fight_snapshot(
            configured_path, EXCERPT_SHA256, packaged_catalog, read_fixed_clock
        ),
        FightSnapshotFailure.NOT_REGULAR_FILE,
        str(configured_path),
    )


@pytest.mark.skipif(os.geteuid() == 0, reason="the superuser reads through any mode")
def test_snapshot_without_read_permission_is_unreadable(
    snapshot_path: Path, packaged_catalog: FightSnapshotCatalog
) -> None:
    snapshot_path.chmod(0o000)
    try:
        expect_failure(
            lambda: load_operator_fight_snapshot(
                snapshot_path, EXCERPT_SHA256, packaged_catalog, read_fixed_clock
            ),
            FightSnapshotFailure.UNREADABLE,
            str(snapshot_path),
            "Permission denied",
        )
    finally:
        snapshot_path.chmod(0o644)


class FailingRead(io.BytesIO):
    """A stream opened from a regular file whose read then fails, as on a broken disk."""

    def read(self, size: int | None = -1) -> bytes:
        raise OSError(5, "Input/output error: /secret/device")


def open_failing_part_way(path: Path) -> IO[bytes]:
    open_regular_file(path).close()
    return FailingRead()


def test_read_that_fails_part_way_is_unreadable_without_the_error_text(
    snapshot_path: Path, packaged_catalog: FightSnapshotCatalog
) -> None:
    expect_failure(
        lambda: load_operator_fight_snapshot(
            snapshot_path,
            EXCERPT_SHA256,
            packaged_catalog,
            read_fixed_clock,
            open_file=open_failing_part_way,
        ),
        FightSnapshotFailure.UNREADABLE,
        "/secret/device",
        "Input/output error",
    )


@pytest.mark.parametrize(
    ("size_bytes", "failure"),
    [
        (MAX_FIGHT_SNAPSHOT_BYTES, FightSnapshotFailure.HASH_MISMATCH),
        (MAX_FIGHT_SNAPSHOT_BYTES + 1, FightSnapshotFailure.TOO_LARGE),
    ],
    ids=["at_the_cap_read_whole", "one_byte_over_refused"],
)
def test_snapshot_is_read_up_to_its_cap_and_refused_past_it(
    tmp_path: Path,
    packaged_catalog: FightSnapshotCatalog,
    size_bytes: int,
    failure: FightSnapshotFailure,
) -> None:
    snapshot_path = tmp_path / "sized.yaml"
    snapshot_path.write_bytes(b"#" * size_bytes)

    expect_failure(
        lambda: load_operator_fight_snapshot(
            snapshot_path, EXCERPT_SHA256, packaged_catalog, read_fixed_clock
        ),
        failure,
    )


def test_snapshot_that_differs_from_its_pin_is_refused(
    snapshot_path: Path, packaged_catalog: FightSnapshotCatalog
) -> None:
    snapshot_path.write_bytes(EXCERPT_BYTES + b"\n")

    expect_failure(
        lambda: load_operator_fight_snapshot(
            snapshot_path, EXCERPT_SHA256, packaged_catalog, read_fixed_clock
        ),
        FightSnapshotFailure.HASH_MISMATCH,
    )


def test_snapshot_at_its_pin_that_the_catalog_does_not_list_is_refused(
    snapshot_path: Path,
) -> None:
    other_catalog = build_catalog(build_known_snapshot(b"another snapshot"))

    expect_failure(
        lambda: load_operator_fight_snapshot(
            snapshot_path, EXCERPT_SHA256, other_catalog, read_fixed_clock
        ),
        FightSnapshotFailure.NOT_CATALOGUED,
    )


def test_catalogued_bytes_that_do_not_parse_are_invalid(tmp_path: Path) -> None:
    broken_bytes = b"techniques: [unclosed\n"
    broken_path = tmp_path / "broken.yaml"
    broken_path.write_bytes(broken_bytes)
    catalog = build_catalog(build_known_snapshot(broken_bytes))

    expect_failure(
        lambda: load_operator_fight_snapshot(
            broken_path, sha256_hex(broken_bytes), catalog, read_fixed_clock
        ),
        FightSnapshotFailure.INVALID,
        "unclosed",
    )


def test_path_without_expected_digest_serves_computed_catalogued_identity(
    snapshot_path: Path,
) -> None:
    # Arrange
    settings = FightSnapshotSettings(path=snapshot_path)

    # Act
    source, catalog_entry = load_fight_source(settings, read_fixed_clock)

    # Assert
    assert source.describe().snapshot_sha256 == sha256_hex(EXCERPT_BYTES)
    assert catalog_entry is not None
    assert catalog_entry.snapshot_sha256 == source.describe().snapshot_sha256


def test_snapshot_without_expected_digest_still_requires_reviewed_catalog(
    snapshot_path: Path, packaged_catalog: FightSnapshotCatalog
) -> None:
    # Arrange
    snapshot_path.write_bytes(EXCERPT_BYTES + b"\n")

    # Act / Assert
    with pytest.raises(FightSnapshotUnavailable) as raised:
        load_operator_fight_snapshot(snapshot_path, None, packaged_catalog, read_fixed_clock)
    assert raised.value.failure is FightSnapshotFailure.NOT_CATALOGUED
