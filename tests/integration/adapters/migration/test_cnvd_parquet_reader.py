"""CNVD inputs at the importer boundary, with synthetic Parquet and injected catalogs.

PyArrow is required here, beside the ijson tests excluded from the core-only lane.
Every file is built in tmp_path; no upstream row or binary fixture is committed.
"""

import dataclasses
import gzip
from pathlib import Path

import pyarrow
import pyarrow.parquet
import pytest

from tests.support.cnvd_inputs import (
    TEST_REVISION,
    CnvdImport,
    build_cnvd_dependencies,
    build_cnvd_row,
    build_cnvd_table,
    build_test_catalog,
    write_cnvd_file,
    write_cnvd_manifest,
)
from tests.support.legacy_inputs import (
    build_declaration,
    build_v2_entry,
    build_v2_feed,
    run_test_migration,
    write_inputs_manifest,
    write_plain_feed,
)
from vulnwitness.adapters.migration.cnvd_snapshot_catalog import (
    default_cnvd_snapshot_catalog_file,
    load_cnvd_snapshot_catalog,
)
from vulnwitness.adapters.migration.migration_limits import MigrationLimits
from vulnwitness.adapters.store.corpus_store import load_corpus_store, read_store_manifest
from vulnwitness.domain.cnvd_snapshot import CnvdSnapshotCatalog, CnvdSnapshotFile
from vulnwitness.domain.corpus_store_manifest import InputContainer, StoreSource
from vulnwitness.domain.migration_report import (
    MIGRATION_FAILURE_MESSAGES,
    CnvdOutcome,
    MigrationFailureCode,
    MigrationOutcome,
)


@pytest.fixture
def cnvd_import(tmp_path: Path) -> CnvdImport:
    inputs_dir = tmp_path / "inputs"
    inputs_dir.mkdir()
    stores_dir = tmp_path / "stores"
    stores_dir.mkdir()
    write_plain_feed(inputs_dir / "nvdcve-2.0-9999.json", build_v2_feed([build_v2_entry(1)]))
    return CnvdImport(inputs_dir, stores_dir / "target")


def write_faulty_cnvd(path: Path, fault: str) -> int:
    rows = [build_cnvd_row(1)]
    table = build_cnvd_table(rows)
    if fault == "missing-column":
        table = table.drop(["title"])
    elif fault == "extra-column":
        table = table.append_column("unexpected", pyarrow.array(["SYNTHETIC"]))
    elif fault == "repeated-column":
        table = table.append_column("title", pyarrow.array(["SYNTHETIC"]))
    elif fault == "mistyped-column":
        table = table.set_column(0, "id", pyarrow.array([1]))
    elif fault == "large-string-column":
        table = table.set_column(0, "id", pyarrow.array([rows[0]["id"]], pyarrow.large_string()))
    elif fault == "null-value":
        table = build_cnvd_table([build_cnvd_row(1, cve_id=None)])
    elif fault == "invalid-id":
        table = build_cnvd_table([build_cnvd_row(1, id="CNVD-9999-001")])
    elif fault == "id-trailing-newline":
        table = build_cnvd_table([build_cnvd_row(1, id="CNVD-9999-00001\n")])
    elif fault == "repeated-id":
        table = build_cnvd_table([build_cnvd_row(1), build_cnvd_row(1)])
    elif fault == "empty-title":
        table = build_cnvd_table([build_cnvd_row(1, title="")])
    elif fault == "empty-description":
        table = build_cnvd_table([build_cnvd_row(1, description="")])
    elif fault == "invalid-severity":
        table = build_cnvd_table([build_cnvd_row(1, severity="high")])
    elif fault == "invalid-source":
        table = build_cnvd_table([build_cnvd_row(1, source="CNVD")])
    pyarrow.parquet.write_table(table, path)
    if fault == "not-parquet":
        path.write_bytes(b"SYNTHETIC: not Parquet")
    elif fault == "broken-parquet":
        path.write_bytes(b"PAR1SYNTHETIC: truncated ParquetPAR1")
    elif fault == "compressed-parquet":
        path.write_bytes(gzip.compress(path.read_bytes()))
    return table.num_rows


@pytest.mark.parametrize(
    ("fault", "code"),
    [
        ("not-parquet", MigrationFailureCode.CNVD_INVALID_PARQUET),
        ("broken-parquet", MigrationFailureCode.CNVD_INVALID_PARQUET),
        ("compressed-parquet", MigrationFailureCode.CNVD_INVALID_PARQUET),
        ("missing-column", MigrationFailureCode.CNVD_MISSING_COLUMN),
        ("extra-column", MigrationFailureCode.CNVD_EXTRA_COLUMN),
        ("repeated-column", MigrationFailureCode.CNVD_EXTRA_COLUMN),
        ("mistyped-column", MigrationFailureCode.CNVD_MISTYPED_COLUMN),
        ("large-string-column", MigrationFailureCode.CNVD_MISTYPED_COLUMN),
        ("null-value", MigrationFailureCode.CNVD_NULL_VALUE),
        ("invalid-id", MigrationFailureCode.CNVD_INVALID_ID),
        ("id-trailing-newline", MigrationFailureCode.CNVD_INVALID_ID),
        ("repeated-id", MigrationFailureCode.CNVD_REPEATED_ID),
        ("empty-title", MigrationFailureCode.CNVD_EMPTY_TITLE),
        ("empty-description", MigrationFailureCode.CNVD_EMPTY_DESCRIPTION),
        ("invalid-severity", MigrationFailureCode.CNVD_INVALID_SEVERITY),
        ("invalid-source", MigrationFailureCode.CNVD_INVALID_SOURCE),
        ("file-byte-cap", MigrationFailureCode.CNVD_FILE_TOO_LARGE),
        ("total-row-cap", MigrationFailureCode.CNVD_TOO_MANY_ROWS),
        ("catalog-row-count", MigrationFailureCode.CNVD_ROW_COUNT_MISMATCH),
    ],
    ids=[
        "not-parquet",
        "broken-parquet",
        "compressed-parquet",
        "missing-column",
        "extra-column",
        "repeated-column",
        "mistyped-column",
        "large-string-column",
        "null-value",
        "invalid-id",
        "id-trailing-newline",
        "repeated-id",
        "empty-title",
        "empty-description",
        "invalid-severity",
        "invalid-source",
        "file-byte-cap",
        "total-row-cap",
        "catalog-row-count",
    ],
)
def test_structural_fault_fails_the_run_without_publishing(
    cnvd_import: CnvdImport, fault: str, code: MigrationFailureCode
) -> None:
    cnvd_path = cnvd_import.inputs_dir / "cnvd.bin"
    row_count = write_faulty_cnvd(cnvd_path, fault)
    limits = MigrationLimits()
    if fault == "file-byte-cap":
        limits = dataclasses.replace(limits, max_cnvd_bytes=cnvd_path.stat().st_size - 1)
    elif fault == "total-row-cap":
        limits = dataclasses.replace(limits, max_cnvd_rows=0)
    elif fault == "catalog-row-count":
        row_count += 1
    catalog = build_test_catalog([cnvd_path], [row_count])
    manifest = write_cnvd_manifest(cnvd_import, [cnvd_path])

    report = run_test_migration(
        manifest, cnvd_import.target, dependencies=build_cnvd_dependencies(catalog, limits)
    )

    assert report.outcome is MigrationOutcome.FAILED
    assert report.failure is not None
    assert report.failure.code is code
    assert report.failure.message == MIGRATION_FAILURE_MESSAGES[code]
    assert report.failure.input_position == 0
    assert not cnvd_import.target.exists()
    assert list(cnvd_import.target.parent.iterdir()) == []


@pytest.mark.parametrize("fault", ["uncatalogued", "incomplete", "mixed-revisions"], ids=str)
def test_file_set_outside_one_complete_revision_fails_the_run(
    cnvd_import: CnvdImport, fault: str
) -> None:
    train = write_cnvd_file(cnvd_import.inputs_dir, "train", [build_cnvd_row(1)])
    test = write_cnvd_file(cnvd_import.inputs_dir, "test", [build_cnvd_row(2)])
    catalog = build_test_catalog([train, test], [1, 1])
    paths = [train]
    expected_code = MigrationFailureCode.CNVD_INCOMPLETE_SNAPSHOT
    if fault == "uncatalogued":
        paths = [write_cnvd_file(cnvd_import.inputs_dir, "other", [build_cnvd_row(3)])]
        expected_code = MigrationFailureCode.CNVD_UNCATALOGUED_FILE
    elif fault == "mixed-revisions":
        other = write_cnvd_file(cnvd_import.inputs_dir, "other", [build_cnvd_row(3)])
        other_catalog = build_test_catalog([other], [1], revision="b" * 40)
        catalog = CnvdSnapshotCatalog(snapshots=catalog.snapshots + other_catalog.snapshots)
        paths = [train, other]
    manifest = write_cnvd_manifest(cnvd_import, paths)

    report = run_test_migration(
        manifest, cnvd_import.target, dependencies=build_cnvd_dependencies(catalog)
    )

    assert report.outcome is MigrationOutcome.FAILED
    assert report.failure is not None
    assert report.failure.code is expected_code
    assert report.failure.message == MIGRATION_FAILURE_MESSAGES[expected_code]
    assert not cnvd_import.target.exists()


@pytest.mark.parametrize(
    ("fault", "code"),
    [
        ("repeated-id", MigrationFailureCode.CNVD_REPEATED_ID),
        ("total-row-cap", MigrationFailureCode.CNVD_TOO_MANY_ROWS),
    ],
    ids=["repeated-id-across-files", "total-row-cap-across-files"],
)
def test_cross_file_fault_fails_the_run(
    cnvd_import: CnvdImport, fault: str, code: MigrationFailureCode
) -> None:
    train = write_cnvd_file(cnvd_import.inputs_dir, "train", [build_cnvd_row(1)])
    test_row = build_cnvd_row(2)
    if fault == "repeated-id":
        test_row = build_cnvd_row(1, title="SYNTHETIC: distinct bytes, same ID")
    test = write_cnvd_file(cnvd_import.inputs_dir, "test", [test_row])
    catalog = build_test_catalog([train, test], [1, 1])
    limits = MigrationLimits()
    if fault == "total-row-cap":
        limits = dataclasses.replace(limits, max_cnvd_rows=1)
    manifest = write_cnvd_manifest(cnvd_import, [train, test])

    report = run_test_migration(
        manifest, cnvd_import.target, dependencies=build_cnvd_dependencies(catalog, limits)
    )

    assert report.outcome is MigrationOutcome.FAILED
    assert report.failure is not None
    assert report.failure.code is code
    assert report.failure.input_position == 1
    assert not cnvd_import.target.exists()


@pytest.mark.parametrize("is_dry_run", [False, True], ids=["published", "dry-run"])
def test_both_files_are_accepted_by_content_and_report_all_rows(
    cnvd_import: CnvdImport, is_dry_run: bool
) -> None:
    train = write_cnvd_file(cnvd_import.inputs_dir, "renamed.bin", [build_cnvd_row(1)])
    test = write_cnvd_file(cnvd_import.inputs_dir, "another.bin", [build_cnvd_row(2)])
    catalog = build_test_catalog([train, test], [1, 1])
    manifest = write_cnvd_manifest(cnvd_import, [test, train])
    dependencies = build_cnvd_dependencies(catalog)

    report = run_test_migration(
        manifest, cnvd_import.target, dependencies=dependencies, is_dry_run=is_dry_run
    )

    expected_outcome = MigrationOutcome.DRY_RUN if is_dry_run else MigrationOutcome.IMPORTED
    assert report.outcome is expected_outcome
    assert report.cnvd_outcomes[CnvdOutcome.MERGED] == 1
    assert report.cnvd_outcomes[CnvdOutcome.WITHOUT_NVD_RECORD] == 1
    assert sum(report.cnvd_outcomes.values()) == 2
    if is_dry_run:
        assert not cnvd_import.target.exists()
    else:
        store_manifest = read_store_manifest(cnvd_import.target).manifest
        cnvd_inputs = []
        for store_input in store_manifest.inputs:
            if store_input.source is StoreSource.CIRCL_CNVD:
                cnvd_inputs.append(store_input)
                assert store_input.container is InputContainer.PLAIN
                assert store_input.artifact is None
                assert store_input.payload_sha256 is None
                assert store_input.source_generated_at is None
                assert store_input.source_version == f"sha256:{store_input.input_file_sha256}"
                assert f"/resolve/{TEST_REVISION}/data/part-" in store_input.source_uri
        assert len(cnvd_inputs) == 2
        assert load_corpus_store(cnvd_import.target).manifest.record_count == 1
        repeated_report = run_test_migration(
            manifest, cnvd_import.target, dependencies=dependencies
        )
        assert repeated_report.outcome is MigrationOutcome.ALREADY_IMPORTED


@pytest.mark.parametrize("outcome", list(CnvdOutcome), ids=str)
def test_every_cnvd_row_gets_exactly_its_outcome_after_final_nvd_resolution(
    cnvd_import: CnvdImport, outcome: CnvdOutcome
) -> None:
    write_plain_feed(
        cnvd_import.inputs_dir / "nvdcve-2.0-9999.json",
        build_v2_feed(
            [
                build_v2_entry(1),
                build_v2_entry(2, status="Rejected"),
                build_v2_entry(3, description="SYNTHETIC: one text."),
            ]
        ),
    )
    write_plain_feed(
        cnvd_import.inputs_dir / "nvdcve-2.0-modified.json",
        build_v2_feed([build_v2_entry(3, description="SYNTHETIC: conflicting text.")]),
    )
    rows = [
        build_cnvd_row(1),
        build_cnvd_row(2),
        build_cnvd_row(3),
        build_cnvd_row(4),
        build_cnvd_row(5, cve_id=""),
        build_cnvd_row(6, cve_id="CVE-9999-0001\n"),
    ]
    cnvd_path = write_cnvd_file(cnvd_import.inputs_dir, "cnvd", rows)
    catalog = build_test_catalog([cnvd_path], [6])
    manifest = write_inputs_manifest(
        cnvd_import.inputs_dir,
        [
            build_declaration("nvdcve-2.0-9999.json"),
            build_declaration("nvdcve-2.0-modified.json"),
            build_declaration(cnvd_path.name, source="circl-cnvd"),
        ],
    )

    report = run_test_migration(
        manifest, cnvd_import.target, dependencies=build_cnvd_dependencies(catalog)
    )

    assert report.outcome is MigrationOutcome.IMPORTED
    assert report.cnvd_outcomes[outcome] == 1
    assert sum(report.cnvd_outcomes.values()) == 6


@pytest.mark.parametrize(
    ("cve_text", "outcome"),
    [
        ("CVE-9999-0001", CnvdOutcome.MERGED),
        ("", CnvdOutcome.WITHOUT_CVE_ID),
        (" CVE-9999-0001", CnvdOutcome.UNRECOGNISED_CVE_ID),
        ("CVE-9999-0001\n", CnvdOutcome.UNRECOGNISED_CVE_ID),
        ("cve-9999-0001", CnvdOutcome.UNRECOGNISED_CVE_ID),
        ("CVE\u20139999\u20130001", CnvdOutcome.UNRECOGNISED_CVE_ID),
        ("CVE-9999-0001\nCVE-9999-0002", CnvdOutcome.UNRECOGNISED_CVE_ID),
        ("9999-0001", CnvdOutcome.UNRECOGNISED_CVE_ID),
        ("无", CnvdOutcome.UNRECOGNISED_CVE_ID),
    ],
    ids=[
        "exact-cve",
        "empty",
        "leading-space",
        "trailing-newline",
        "lowercase",
        "en-dash",
        "multiple-cves",
        "bare-digits",
        "other-text",
    ],
)
def test_cve_id_is_classified_without_repair(
    cnvd_import: CnvdImport, cve_text: str, outcome: CnvdOutcome
) -> None:
    cnvd_path = write_cnvd_file(
        cnvd_import.inputs_dir, "cnvd", [build_cnvd_row(1, cve_id=cve_text)]
    )
    catalog = build_test_catalog([cnvd_path], [1])
    manifest = write_cnvd_manifest(cnvd_import, [cnvd_path])

    report = run_test_migration(
        manifest, cnvd_import.target, dependencies=build_cnvd_dependencies(catalog)
    )

    assert report.outcome is MigrationOutcome.IMPORTED
    assert report.cnvd_outcomes[outcome] == 1
    assert sum(report.cnvd_outcomes.values()) == 1


def test_packaged_catalog_pins_both_reviewed_files() -> None:
    catalog = load_cnvd_snapshot_catalog(default_cnvd_snapshot_catalog_file())

    assert len(catalog.snapshots) == 1
    snapshot = catalog.snapshots[0]
    assert snapshot.revision == "986160c9b1c910049f64a166ab4056de191f6de7"
    assert snapshot.language == "zh"
    assert snapshot.files == (
        CnvdSnapshotFile(
            upstream_path="data/train-00000-of-00001.parquet",
            sha256="43ba97f36b023f0155b008f5591a9c390e245937c8747f7feaefae843d06c035",
            row_count=116871,
        ),
        CnvdSnapshotFile(
            upstream_path="data/test-00000-of-00001.parquet",
            sha256="d702b92d6ef51ff506dce5895dd7a01f9df029be39baff5791bf87c4022fd940",
            row_count=12986,
        ),
    )
