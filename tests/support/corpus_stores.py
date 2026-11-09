"""Corpus stores under a store root for the store operations and serving tests: stores
imported from synthetic feeds, the file operations ``ACTIVE`` is written through with a
chosen point failing, and readers of what the root holds."""

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from tests.support.legacy_inputs import (
    build_declaration,
    build_kev_row,
    build_v2_entry,
    build_v2_feed,
    run_test_migration,
    write_gzip_feed,
    write_inputs_manifest,
    write_kev_csv,
)
from vulnwitness.adapters.store.active_record_writer import OsActiveRecordFiles
from vulnwitness.domain.migration_report import MigrationOutcome

COMPATIBILITY_STORE = (
    Path(__file__).resolve().parents[1]
    / "contract"
    / "data"
    / "corpus_store_format1_28e5b4d"
    / "store"
)


def import_store(
    store_root: Path,
    name: str,
    cve_numbers: tuple[int, ...] = (1, 2),
    description: str = "SYNTHETIC: democorp gateway mishandles input.",
    *,
    include_kev: bool = True,
) -> Path:
    """A store named ``name`` under ``store_root``, imported from a 2.0 feed holding
    ``CVE-9999-<n>`` for each of ``cve_numbers`` and, optionally, KEV listing the first. Its
    inputs are written beside the root, never in it."""
    inputs_dir = store_root.parent / f"inputs-{name}"
    inputs_dir.mkdir()
    entries = []
    for cve_number in cve_numbers:
        entries.append(build_v2_entry(cve_number, description=description))
    write_gzip_feed(inputs_dir / "nvdcve-2.0-2099.json.gz", build_v2_feed(entries))
    declarations = [build_declaration("nvdcve-2.0-2099.json.gz")]
    if include_kev:
        write_kev_csv(inputs_dir / "kev.csv", [build_kev_row(cve_numbers[0])])
        declarations.append(build_declaration("kev.csv", source="cisa-kev"))
    manifest_path = write_inputs_manifest(inputs_dir, declarations)
    store_dir = store_root / name
    report = run_test_migration(manifest_path, store_dir, store_root=store_root)
    assert report.outcome is MigrationOutcome.IMPORTED, report.failure
    return store_dir


def copy_compatibility_store(store_root: Path, name: str) -> Path:
    """The format-1 compatibility store, copied under ``store_root`` as ``name``."""
    store_dir = store_root / name
    shutil.copytree(COMPATIBILITY_STORE, store_dir)
    return store_dir


def read_active_bytes(store_root: Path) -> bytes | None:
    """The bytes of ``<root>/ACTIVE``, ``None`` when there is none."""
    active_path = store_root / "ACTIVE"
    if not os.path.lexists(active_path):
        return None
    return active_path.read_bytes()


def list_hidden_entries(store_root: Path) -> list[str]:
    """The root's entries whose names start with a dot, ``.lock`` aside."""
    hidden_names: list[str] = []
    for entry in sorted(store_root.iterdir()):
        if entry.name.startswith(".") and entry.name != ".lock":
            hidden_names.append(entry.name)
    return hidden_names


def move_store(store_dir: Path) -> None:
    """The store moved away: nothing is left under its name."""
    store_dir.rename(store_dir.with_name("moved"))


def rewrite_manifest(store_dir: Path) -> None:
    """The manifest rewritten with the same fields, indented: the store still verifies,
    but its manifest no longer hashes to a digest recorded for it."""
    manifest_path = store_dir / "manifest.json"
    manifest_path.write_text(json.dumps(json.loads(manifest_path.read_bytes()), indent=1))


def tamper_with_records(store_dir: Path) -> None:
    """One record line changed, so the records file no longer matches its pin."""
    records_path = store_dir / "records.jsonl"
    records_bytes = records_path.read_bytes()
    assert b"democorp" in records_bytes
    records_path.write_bytes(records_bytes.replace(b"democorp", b"DEMOCORP"))


def tamper_with_anchors(store_dir: Path) -> None:
    """The anchors' retrieval time changed, so the anchors file no longer matches its pin."""
    anchors_path = store_dir / "anchors.jsonl"
    anchors_bytes = anchors_path.read_bytes()
    assert b"2026-10-24" in anchors_bytes
    anchors_path.write_bytes(anchors_bytes.replace(b"2026-10-24", b"2026-10-23"))


def declare_later_format(store_dir: Path) -> None:
    """The manifest declaring store format 4, as a later release would write it."""
    manifest_path = store_dir / "manifest.json"
    manifest_fields = json.loads(manifest_path.read_bytes())
    manifest_fields["store_format_version"] = 4
    manifest_path.write_text(json.dumps(manifest_fields, sort_keys=True, separators=(",", ":")))


def make_root_missing(store_root: Path) -> None:
    store_root.rmdir()


def make_root_a_file(store_root: Path) -> None:
    store_root.rmdir()
    store_root.write_bytes(b"")


def make_root_a_symbolic_link(store_root: Path) -> None:
    real_root = store_root.with_name("real-stores")
    store_root.rename(real_root)
    store_root.symlink_to(real_root)


ROOT_BREAKERS = [make_root_missing, make_root_a_file, make_root_a_symbolic_link]


@dataclass
class FailingActiveRecordFiles(OsActiveRecordFiles):
    """The operating system's file operations, with the one named by ``failing_point``
    raising ``OSError`` instead: ``check`` (the first sync of the root), ``temporary``
    (writing the new record), ``replace`` or ``confirm`` (the sync after the replace)."""

    failing_point: str
    root_syncs: int = 0

    def sync_directory(self, directory: Path) -> None:
        self.root_syncs += 1
        is_check = self.root_syncs == 1
        if (self.failing_point == "check" and is_check) or (
            self.failing_point == "confirm" and not is_check
        ):
            raise OSError(5, "injected sync failure")
        super().sync_directory(directory)

    def write_new_file(self, path: Path, content: bytes) -> None:
        if self.failing_point == "temporary":
            # The file exists when the write fails part way, as after a full disk.
            super().write_new_file(path, content[: len(content) // 2])
            raise OSError(28, "injected write failure")
        super().write_new_file(path, content)

    def replace(self, source: Path, target: Path) -> None:
        if self.failing_point == "replace":
            raise OSError(18, "injected rename failure")
        super().replace(source, target)
