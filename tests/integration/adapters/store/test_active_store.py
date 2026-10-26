"""Proves startup's store loading (ADR 0009 §9): a configured root serves exactly the store
``ACTIVE`` names, under the digest it records, and anything else refuses with a closed
reason and never falls back to the fixture; startup writes nothing under the root, so a
read-only root serves."""

import json
import os
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from cve_kgrag.adapters.store.active_record import (
    ActiveRecord,
    StorePointer,
    encode_active_record,
)
from cve_kgrag.adapters.store.active_record_writer import OsActiveRecordFiles
from cve_kgrag.adapters.store.active_store import load_active_store
from cve_kgrag.adapters.store.corpus_store import load_corpus_store
from cve_kgrag.adapters.store.store_activation import StoreActivation
from cve_kgrag.composition import load_served_corpus
from cve_kgrag.domain.hashing import sha256_hex
from cve_kgrag.domain.served_dataset import ServedDatasetKind
from cve_kgrag.domain.store_status import StoreUnavailable, StoreUnavailableReason
from tests.support.corpus_stores import import_store
from tests.support.legacy_inputs import snapshot_tree


@pytest.fixture
def store_root(tmp_path: Path) -> Path:
    store_root = tmp_path / "stores"
    store_root.mkdir()
    return store_root


@pytest.fixture
def active_store(store_root: Path) -> Path:
    store_dir = import_store(store_root, "first")
    StoreActivation(store_root, OsActiveRecordFiles()).activate("first")
    return store_dir


@pytest.fixture
def read_only_root(store_root: Path, active_store: Path) -> Iterator[Path]:
    """The root and the active store with every write permission removed."""
    read_only_dirs = [store_root, active_store]
    for read_only_dir in read_only_dirs:
        read_only_dir.chmod(0o555)
    yield store_root
    for read_only_dir in read_only_dirs:
        read_only_dir.chmod(0o755)


def expect_unavailable(store_root: Path, reason: StoreUnavailableReason) -> None:
    with pytest.raises(StoreUnavailable) as raised:
        load_active_store(store_root)
    assert raised.value.reason is reason


def test_active_store_is_loaded_as_recorded(store_root: Path, active_store: Path) -> None:
    corpus_store = load_active_store(store_root)

    assert corpus_store == load_corpus_store(active_store)


def test_served_corpus_without_a_root_is_the_packaged_fixture() -> None:
    served_dataset = load_served_corpus(None).describe_served_dataset()

    assert served_dataset.kind is ServedDatasetKind.SYNTHETIC_FIXTURE


def test_served_corpus_with_a_root_is_its_active_store(
    store_root: Path, active_store: Path
) -> None:
    served_dataset = load_served_corpus(store_root).describe_served_dataset()

    assert served_dataset == load_corpus_store(active_store).describe_served_dataset()


def test_root_without_active_refuses_rather_than_serving_the_fixture(
    store_root: Path,
) -> None:
    import_store(store_root, "first")

    expect_unavailable(store_root, StoreUnavailableReason.NO_ACTIVE_STORE)


def test_unreadable_active_refuses_to_start(store_root: Path, active_store: Path) -> None:
    (store_root / "ACTIVE").write_bytes(b"first\n")

    expect_unavailable(store_root, StoreUnavailableReason.ACTIVE_UNREADABLE)


def move_store(store_dir: Path) -> None:
    store_dir.rename(store_dir.with_name("moved"))


def rewrite_manifest(store_dir: Path) -> None:
    manifest_path = store_dir / "manifest.json"
    manifest_path.write_text(json.dumps(json.loads(manifest_path.read_bytes()), indent=1))


def tamper_with_anchors(store_dir: Path) -> None:
    anchors_path = store_dir / "anchors.jsonl"
    anchors_bytes = anchors_path.read_bytes()
    assert b"2026-10-24" in anchors_bytes
    anchors_path.write_bytes(anchors_bytes.replace(b"2026-10-24", b"2026-10-23"))


def move_to_a_later_format(store_dir: Path) -> None:
    """A store a later release wrote: same digest recorded, format version 2."""
    manifest_path = store_dir / "manifest.json"
    manifest_fields = json.loads(manifest_path.read_bytes())
    manifest_fields["store_format_version"] = 2
    manifest_path.write_text(json.dumps(manifest_fields, sort_keys=True, separators=(",", ":")))


@pytest.mark.parametrize(
    ("break_store", "reason"),
    [
        (move_store, StoreUnavailableReason.ACTIVE_STORE_MISSING),
        (rewrite_manifest, StoreUnavailableReason.ACTIVE_STORE_CHANGED),
        (tamper_with_anchors, StoreUnavailableReason.STORE_INVALID),
    ],
    ids=["missing", "replaced", "tampered"],
)
def test_active_store_that_is_not_as_recorded_refuses_to_start(
    store_root: Path,
    active_store: Path,
    break_store: Callable[[Path], None],
    reason: StoreUnavailableReason,
) -> None:
    break_store(active_store)

    expect_unavailable(store_root, reason)


def test_active_store_of_a_later_format_refuses_as_unsupported(
    store_root: Path, active_store: Path
) -> None:
    move_to_a_later_format(active_store)
    record_later_store(store_root, active_store)

    expect_unavailable(store_root, StoreUnavailableReason.STORE_FORMAT_UNSUPPORTED)


def record_later_store(store_root: Path, store_dir: Path) -> None:
    """``ACTIVE`` naming the store under its present manifest digest, as the later
    release that wrote it would have recorded it."""
    active_record = ActiveRecord(
        active=StorePointer(
            name=store_dir.name,
            store_manifest_sha256=sha256_hex((store_dir / "manifest.json").read_bytes()),
        ),
        previous=None,
    )
    (store_root / "ACTIVE").write_bytes(encode_active_record(active_record))


@pytest.mark.parametrize("root_kind", ["missing", "file", "symbolic_link"])
def test_unusable_root_refuses_to_start(tmp_path: Path, root_kind: str) -> None:
    store_root = tmp_path / "stores"
    if root_kind == "file":
        store_root.write_bytes(b"")
    elif root_kind == "symbolic_link":
        (tmp_path / "real-stores").mkdir()
        store_root.symlink_to(tmp_path / "real-stores")

    expect_unavailable(store_root, StoreUnavailableReason.STORE_ROOT_UNUSABLE)


@pytest.mark.skipif(os.geteuid() == 0, reason="the superuser writes through any mode")
def test_read_only_root_serves_and_startup_writes_nothing(read_only_root: Path) -> None:
    tree_before = snapshot_tree(read_only_root)
    entries_before = sorted(os.listdir(read_only_root))

    corpus_store = load_active_store(read_only_root)

    assert corpus_store.records
    assert snapshot_tree(read_only_root) == tree_before
    assert sorted(os.listdir(read_only_root)) == entries_before
