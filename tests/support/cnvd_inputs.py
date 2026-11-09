"""Synthetic CNVD Parquet inputs and injected catalogs for importer and store tests."""

import dataclasses
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pyarrow
import pyarrow.parquet

from tests.support.legacy_inputs import (
    build_cve_id,
    build_declaration,
    build_migration_dependencies,
    build_v2_entry,
    build_v2_feed,
    run_test_migration,
    write_inputs_manifest,
    write_plain_feed,
)
from vulnwitness.adapters.migration.cnvd_types import CNVD_COLUMNS
from vulnwitness.adapters.migration.input_files import inspect_input_file
from vulnwitness.adapters.migration.legacy_migration import MigrationDependencies
from vulnwitness.adapters.migration.migration_limits import MigrationLimits
from vulnwitness.adapters.store.corpus_store import CorpusStore, load_corpus_store
from vulnwitness.domain.cnvd_snapshot import CnvdSnapshot, CnvdSnapshotCatalog, CnvdSnapshotFile
from vulnwitness.domain.hashing import canonical_json_bytes, sha256_hex
from vulnwitness.domain.migration_report import MigrationOutcome

TEST_REVISION = "a" * 40
LOOKUP_REVISION = "986160c9b1c910049f64a166ab4056de191f6de7"


@dataclass(frozen=True)
class CnvdImport:
    inputs_dir: Path
    target: Path


def build_cnvd_row(number: int, **fields: Any) -> dict[str, Any]:
    row = {
        "id": f"CNVD-9999-{number:05d}",
        "title": "SYNTHETIC: 示例标题",
        "description": "SYNTHETIC: fictional vulnerability description.",
        "severity": "中",
        "cve_id": build_cve_id(number),
        "source": "cnvd",
    }
    row.update(fields)
    return row


def build_cnvd_table(rows: list[dict[str, Any]]) -> pyarrow.Table:
    schema_fields = []
    for column in CNVD_COLUMNS:
        schema_fields.append(pyarrow.field(column, pyarrow.string()))
    return pyarrow.Table.from_pylist(rows, schema=pyarrow.schema(schema_fields))


def write_cnvd_file(directory: Path, name: str, rows: list[dict[str, Any]]) -> Path:
    path = directory / name
    pyarrow.parquet.write_table(build_cnvd_table(rows), path)
    return path


def build_test_catalog(
    paths: list[Path], row_counts: list[int], revision: str = TEST_REVISION
) -> CnvdSnapshotCatalog:
    snapshot_files: list[CnvdSnapshotFile] = []
    for index, (path, row_count) in enumerate(zip(paths, row_counts, strict=True)):
        inspected_file = inspect_input_file(path, MigrationLimits())
        snapshot_files.append(
            CnvdSnapshotFile(
                upstream_path=f"data/part-{index}.parquet",
                sha256=inspected_file.sha256,
                row_count=row_count,
            )
        )
    return CnvdSnapshotCatalog(
        snapshots=(CnvdSnapshot(revision=revision, files=tuple(snapshot_files)),)
    )


def build_cnvd_dependencies(
    catalog: CnvdSnapshotCatalog, limits: MigrationLimits | None = None
) -> MigrationDependencies:
    return dataclasses.replace(build_migration_dependencies(limits), cnvd_catalog=catalog)


def write_cnvd_manifest(cnvd_import: CnvdImport, paths: list[Path]) -> Path:
    declarations = [build_declaration("nvdcve-2.0-9999.json")]
    for path in paths:
        declarations.append(build_declaration(path.name, source="circl-cnvd"))
    return write_inputs_manifest(cnvd_import.inputs_dir, declarations)


@dataclass(frozen=True)
class CnvdScenario:
    manifest: Path
    target: Path
    dependencies: MigrationDependencies
    rows: tuple[dict[str, Any], ...]


def write_cnvd_nvd_inputs(
    directory: Path,
    *,
    nvd_status: str = "Analyzed",
    metrics: dict[str, Any] | None = None,
    extra_nvd_entries: tuple[dict[str, Any], ...] = (),
) -> tuple[Path, Path]:
    """NVD winners, rejected and conflicting candidates shared by both CNVD sources."""
    inputs_dir = directory / "inputs"
    inputs_dir.mkdir()
    stores_dir = directory / "stores"
    stores_dir.mkdir()
    write_plain_feed(
        inputs_dir / "nvdcve-2.0-9999.json",
        build_v2_feed(
            [
                build_v2_entry(1, status=nvd_status, metrics=metrics or {}),
                build_v2_entry(2, status="Rejected"),
                build_v2_entry(3),
                *extra_nvd_entries,
            ]
        ),
    )
    write_plain_feed(
        inputs_dir / "nvdcve-2.0-modified.json",
        build_v2_feed([build_v2_entry(3, description="SYNTHETIC: conflicting text.")]),
    )
    return inputs_dir, stores_dir


def build_cnvd_scenario(
    directory: Path,
    *,
    cnvd_title: str = "SYNTHETIC: 示例标题",
    nvd_status: str = "Analyzed",
    metrics: dict[str, Any] | None = None,
    extra_nvd_entries: tuple[dict[str, Any], ...] = (),
    retain_cnvd: bool = True,
    revision: str = TEST_REVISION,
) -> CnvdScenario:
    """One merged CVE with two entries, all pending outcomes and both unstored outcomes."""
    inputs_dir, stores_dir = write_cnvd_nvd_inputs(
        directory, nvd_status=nvd_status, metrics=metrics, extra_nvd_entries=extra_nvd_entries
    )
    rows = (
        build_cnvd_row(7, cve_id=build_cve_id(1), severity="低", title=cnvd_title),
        build_cnvd_row(4, title=cnvd_title),
        build_cnvd_row(3, severity="高"),
        build_cnvd_row(2),
        build_cnvd_row(1, title=cnvd_title),
        build_cnvd_row(5, cve_id=""),
        build_cnvd_row(6, cve_id="CVE-9999-0001\n"),
    )
    if not retain_cnvd:
        unlinked_rows = []
        for row in rows:
            unlinked_rows.append({**row, "cve_id": ""})
        rows = tuple(unlinked_rows)
    train = write_cnvd_file(inputs_dir, "train.parquet", list(rows[:3]))
    test = write_cnvd_file(inputs_dir, "test.parquet", list(rows[3:]))
    manifest = write_inputs_manifest(
        inputs_dir,
        [
            build_declaration("nvdcve-2.0-9999.json"),
            build_declaration("nvdcve-2.0-modified.json"),
            build_declaration(train.name, source="circl-cnvd"),
            build_declaration(test.name, source="circl-cnvd"),
        ],
    )
    return CnvdScenario(
        manifest,
        stores_dir / "cnvd",
        build_cnvd_dependencies(build_test_catalog([train, test], [3, 4], revision=revision)),
        rows,
    )


def import_cnvd_lookup_corpus(
    directory: Path,
    *,
    cnvd_title: str = "SYNTHETIC: 示例标题",
    nvd_status: str = "Analyzed",
    with_metrics: bool = True,
    retain_cnvd: bool = True,
    revision: str = LOOKUP_REVISION,
) -> CorpusStore:
    """A served corpus with same/lower merged entries, every pending state and a
    record without CNVD. Only synthetic inputs are written to the temporary directory.
    """
    metrics = {}
    if with_metrics:
        metrics = {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                        "baseScore": 5.3,
                        "baseSeverity": "MEDIUM",
                    },
                }
            ]
        }
    scenario = build_cnvd_scenario(
        directory,
        cnvd_title=cnvd_title,
        nvd_status=nvd_status,
        metrics=metrics,
        extra_nvd_entries=(build_v2_entry(8),),
        retain_cnvd=retain_cnvd,
        revision=revision,
    )
    report = run_test_migration(
        scenario.manifest,
        scenario.target,
        dependencies=scenario.dependencies,
    )
    assert report.outcome is MigrationOutcome.IMPORTED, report.failure
    return load_corpus_store(scenario.target)


def build_raw_cnvd_record(record_number: int, **fields: Any) -> dict[str, Any]:
    """A fictional raw record using the same CNVD values as the Parquet builders."""
    row = build_cnvd_row(record_number)
    record = {
        "number": row["id"],
        "title": row["title"],
        "description": row["description"],
        "serverity": row["severity"],
        "cves": {"cve": {"cveNumber": row["cve_id"]}},
        "products": {"product": "SYNTHETIC: Example Gateway <2.0"},
        "submitTime": "2026-10-01",
        "openTime": "2026-10-02",
        "formalWay": "SYNTHETIC: 升级到修复版本。",
    }
    record.update(fields)
    return record


def write_raw_cnvd_file(directory: Path, name: str, records: list[Any]) -> Path:
    """Write only synthetic NDJSON in the test's temporary directory."""
    lines = []
    for record in records:
        lines.append(json.dumps(record, ensure_ascii=False))
    path = directory / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def build_raw_cnvd_scenario(
    directory: Path,
    base_records: list[Any],
    *,
    increment_records: list[Any] | None = None,
    increment_retrieved_at: str = "2026-10-24T09:30:00Z",
    reverse_manifest: bool = False,
) -> CnvdScenario:
    """Synthetic raw base/increments with the shared NVD candidate and outcome builders."""
    inputs_dir, stores_dir = write_cnvd_nvd_inputs(directory)
    base = write_raw_cnvd_file(inputs_dir, "base.ndjson", base_records)
    cnvd_declarations = [build_declaration(base.name, source="vulnerability-lookup-cnvd")]
    if increment_records is not None:
        increment = write_raw_cnvd_file(inputs_dir, "increment.ndjson", increment_records)
        cnvd_declarations.append(
            build_declaration(
                increment.name,
                source="vulnerability-lookup-cnvd",
                retrieved_at=increment_retrieved_at,
            )
        )
    if reverse_manifest:
        cnvd_declarations.reverse()
    manifest = write_inputs_manifest(
        inputs_dir,
        [
            build_declaration("nvdcve-2.0-9999.json"),
            build_declaration("nvdcve-2.0-modified.json"),
            *cnvd_declarations,
        ],
    )
    return CnvdScenario(manifest, stores_dir / "cnvd", build_migration_dependencies(), ())


def write_format_2_cnvd_store(store_dir: Path) -> None:
    """Represent a synthetic Parquet store with format 2's persisted CNVD fields."""
    manifest_path = store_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    for pin in manifest["files"]:
        if pin["path"] not in {"records.jsonl", "pending_cnvd.jsonl"}:
            continue
        path = store_dir / pin["path"]
        lines = []
        for line in path.read_bytes().splitlines():
            record = json.loads(line)
            entries = record["cnvd"] if pin["path"] == "records.jsonl" else [record["entry"]]
            for entry in entries:
                for field_name in ("products", "submit_time", "open_time", "handling_advice"):
                    del entry[field_name]
            lines.append(canonical_json_bytes(record))
        file_bytes = b"\n".join(lines) + b"\n"
        path.write_bytes(file_bytes)
        pin["sha256"] = sha256_hex(file_bytes)
        pin["size_bytes"] = len(file_bytes)
    manifest["store_format_version"] = 2
    manifest["schema_version"] = "2.0.0-dev.57"
    manifest_path.write_bytes(canonical_json_bytes(manifest))
