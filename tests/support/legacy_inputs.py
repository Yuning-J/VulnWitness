"""Builders for the legacy-data importer's inputs, all synthetic (``CVE-9999-*``): NVD 2.0
and 1.1 feed entries and feeds, written plain, gzipped or zipped; KEV catalog rows and
CSV files; input manifests; and a run of the importer under injected limits and a fixed
clock. Also a snapshot of a tree's contents and modification times, to show a run left
it as it was."""

import csv
import gzip
import io
import json
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from vulnwitness.adapter_discovery import InterfaceUnavailable, discover_migration_parsers
from vulnwitness.adapters.migration.inputs_manifest import load_inputs_manifest
from vulnwitness.adapters.migration.legacy_migration import (
    MigrationDependencies,
    MigrationRequest,
    run_migration,
)
from vulnwitness.adapters.migration.migration_limits import MigrationLimits
from vulnwitness.composition import build_nvd_normalizer, load_packaged_source_registry
from vulnwitness.domain.hashing import sha256_hex
from vulnwitness.domain.migration_report import MigrationReport

# After every retrieval time the builders use, so none is in the future.
FIXED_NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
TEST_IMPORTER_VERSION = "2.0.0.dev0"
RETRIEVED_AT = "2026-10-24T08:30:00Z"
V2_FEED_TIMESTAMP = "2026-10-20T00:00:00.000"
V1_FEED_TIMESTAMP = "2026-10-20T00:00Z"
KEV_COLUMNS = [
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
    "knownRansomwareCampaignUse",
    "notes",
    "cwes",
    "forensicTriage",
]


def build_cve_id(number: int) -> str:
    return f"CVE-9999-{number:04d}"


def build_v2_entry(
    number: int,
    last_modified: str | None = "2099-01-03T00:00:00.000",
    description: str = "SYNTHETIC: democorp gateway mishandles input.",
    status: str = "Analyzed",
    **cve_fields: Any,
) -> dict[str, Any]:
    """One ``vulnerabilities[]`` element of an NVD 2.0 feed; ``cve_fields`` override the
    ``cve`` object's fields."""
    cve: dict[str, Any] = {
        "id": build_cve_id(number),
        "sourceIdentifier": "cna@democorp.example",
        "vulnStatus": status,
        "published": "2099-01-02T03:04:05.000",
        "descriptions": [{"lang": "en", "value": description}],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:democorp:gateway:1.0:*:*:*:*:*:*:*",
                            }
                        ]
                    }
                ]
            }
        ],
    }
    if last_modified is not None:
        cve["lastModified"] = last_modified
    cve.update(cve_fields)
    return {"cve": cve}


def build_v2_feed(
    entries: list[dict[str, Any]], timestamp: str | None = V2_FEED_TIMESTAMP
) -> dict[str, Any]:
    feed: dict[str, Any] = {
        "resultsPerPage": len(entries),
        "startIndex": 0,
        "totalResults": len(entries),
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": entries,
    }
    if timestamp is not None:
        feed["timestamp"] = timestamp
    return feed


def build_v1_item(
    number: int,
    last_modified: str | None = "2099-01-03T00:00Z",
    description: str = "SYNTHETIC: democorp gateway mishandles input.",
) -> dict[str, Any]:
    """One ``CVE_Items[]`` element of an NVD 1.1 feed."""
    item: dict[str, Any] = {
        "cve": {
            "data_type": "CVE",
            "data_format": "MITRE",
            "data_version": "4.0",
            "CVE_data_meta": {"ID": build_cve_id(number), "ASSIGNER": "cna@democorp.example"},
            "description": {"description_data": [{"lang": "en", "value": description}]},
        },
        "configurations": {
            "CVE_data_version": "4.0",
            "nodes": [
                {
                    "operator": "OR",
                    "cpe_match": [
                        {
                            "vulnerable": True,
                            "cpe23Uri": "cpe:2.3:a:democorp:gateway:1.0:*:*:*:*:*:*:*",
                        }
                    ],
                }
            ],
        },
        "publishedDate": "2099-01-02T03:04Z",
    }
    if last_modified is not None:
        item["lastModifiedDate"] = last_modified
    return item


def build_v1_feed(
    items: list[dict[str, Any]], timestamp: str | None = V1_FEED_TIMESTAMP
) -> dict[str, Any]:
    feed: dict[str, Any] = {
        "CVE_data_type": "CVE",
        "CVE_data_format": "MITRE",
        "CVE_data_version": "4.0",
        "CVE_data_numberOfCVEs": str(len(items)),
        "CVE_Items": items,
    }
    if timestamp is not None:
        feed["CVE_data_timestamp"] = timestamp
    return feed


def encode_feed(feed: object) -> bytes:
    """The feed, or any other JSON document such as a legacy derived file, as JSON."""
    return json.dumps(feed).encode()


def write_plain_feed(path: Path, feed: object) -> Path:
    path.write_bytes(encode_feed(feed))
    return path


def write_gzip_feed(path: Path, feed: dict[str, Any]) -> Path:
    path.write_bytes(gzip.compress(encode_feed(feed), mtime=0))
    return path


def write_zip_feed(path: Path, feed: dict[str, Any], member_name: str = "feed.json") -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(member_name, encode_feed(feed))
    return path


def build_kev_row(number: int, **columns: str) -> dict[str, str]:
    """One KEV catalog row for ``CVE-9999-<number>``; ``columns`` override its values."""
    row = {
        "cveID": build_cve_id(number),
        "vendorProject": "Democorp",
        "product": "Gateway",
        "vulnerabilityName": "Democorp Gateway Input Flaw",
        "dateAdded": "2099-01-05",
        "shortDescription": "SYNTHETIC: exploited input flaw.",
        "requiredAction": "Apply the vendor update.",
        "dueDate": "2099-01-26",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "",
        "cwes": "",
        "forensicTriage": "No",
    }
    row.update(columns)
    return row


def encode_kev_csv(rows: list[dict[str, str]], columns: list[str] = KEV_COLUMNS) -> bytes:
    """The catalog as CISA writes it: a header row, then one row per entry, CRLF ends."""
    text_stream = io.StringIO(newline="")
    writer = csv.writer(text_stream, dialect="excel")
    writer.writerow(columns)
    for row in rows:
        values: list[str] = []
        for column in columns:
            values.append(row.get(column, ""))
        writer.writerow(values)
    return text_stream.getvalue().encode()


def write_kev_csv(path: Path, rows: list[dict[str, str]], columns: list[str] = KEV_COLUMNS) -> Path:
    path.write_bytes(encode_kev_csv(rows, columns))
    return path


def build_declaration(
    path: str, source: str = "nvd", retrieved_at: str = RETRIEVED_AT, **fields: Any
) -> dict[str, Any]:
    return {"source": source, "path": path, "retrieved_at": retrieved_at, **fields}


def write_inputs_manifest(directory: Path, declarations: list[dict[str, Any]]) -> Path:
    manifest_path = directory / "inputs.yaml"
    manifest_path.write_text(
        yaml.safe_dump({"format_version": 1, "inputs": declarations}), encoding="utf-8"
    )
    return manifest_path


@dataclass(frozen=True)
class FixedClock:
    """A clock that always reads ``now``."""

    now: datetime

    def read(self) -> datetime:
        return self.now


def build_migration_dependencies(
    limits: MigrationLimits | None = None, now: datetime = FIXED_NOW
) -> MigrationDependencies:
    """The dependencies a CLI run builds, with a fixed clock and the given limits. The
    parsers come through discovery, so a module importing this one needs no ijson unless
    it runs the importer."""
    parsers = discover_migration_parsers()
    if isinstance(parsers, InterfaceUnavailable):
        raise RuntimeError(parsers.detail)
    source_registry = load_packaged_source_registry()
    return MigrationDependencies(
        parsers=parsers,
        normalizer=build_nvd_normalizer(source_registry),
        source_registry=source_registry,
        clock=FixedClock(now).read,
        importer_version=TEST_IMPORTER_VERSION,
        limits=limits or MigrationLimits(),
    )


def run_test_migration(
    manifest_path: Path,
    target: Path,
    legacy_root: Path | None = None,
    is_dry_run: bool = False,
    dependencies: MigrationDependencies | None = None,
    store_root: Path | None = None,
) -> MigrationReport:
    """The importer run on the manifest at ``manifest_path``, with ``store_root`` as the
    configured store root (none by default)."""
    manifest_bytes = manifest_path.read_bytes()
    return run_migration(
        MigrationRequest(
            manifest=load_inputs_manifest(manifest_bytes),
            manifest_bytes=manifest_bytes,
            manifest_path=manifest_path,
            target=target,
            legacy_root=legacy_root,
            is_dry_run=is_dry_run,
            store_root=store_root,
        ),
        dependencies or build_migration_dependencies(),
    )


def snapshot_tree(root: Path) -> dict[str, tuple[str, int]]:
    """Every file under ``root``: its SHA-256 and modification time, by relative path."""
    snapshot: dict[str, tuple[str, int]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            snapshot[path.relative_to(root).as_posix()] = (
                sha256_hex(path.read_bytes()),
                path.stat().st_mtime_ns,
            )
    return snapshot


def list_names(directory: Path) -> list[str]:
    names: list[str] = []
    for entry in sorted(directory.iterdir()):
        names.append(entry.name)
    return names
