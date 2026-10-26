"""Corpus stores under a store root for the store operations and serving tests: stores
imported from synthetic feeds, the file operations ``ACTIVE`` is written through with a
chosen point failing, and readers of what the root holds."""

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from cve_kgrag.adapters.store.active_record_writer import OsActiveRecordFiles
from cve_kgrag.domain.migration_report import MigrationOutcome
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
) -> Path:
    """A store named ``name`` under ``store_root``, imported from a 2.0 feed holding
    ``CVE-9999-<n>`` for each of ``cve_numbers`` and a KEV catalog listing the first. Its
    inputs are written beside the root, never in it."""
    inputs_dir = store_root.parent / f"inputs-{name}"
    inputs_dir.mkdir()
    entries = []
    for cve_number in cve_numbers:
        entries.append(build_v2_entry(cve_number, description=description))
    write_gzip_feed(inputs_dir / "nvdcve-2.0-2099.json.gz", build_v2_feed(entries))
    write_kev_csv(inputs_dir / "kev.csv", [build_kev_row(cve_numbers[0])])
    manifest_path = write_inputs_manifest(
        inputs_dir,
        [
            build_declaration("nvdcve-2.0-2099.json.gz"),
            build_declaration("kev.csv", source="cisa-kev"),
        ],
    )
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
