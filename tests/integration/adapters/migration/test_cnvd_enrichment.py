"""NVD status participates in candidate equality before CNVD joins final records."""

from pathlib import Path

import pytest

from tests.support.cnvd_inputs import (
    build_cnvd_dependencies,
    build_cnvd_row,
    build_test_catalog,
    write_cnvd_file,
)
from tests.support.legacy_inputs import (
    build_cve_id,
    build_declaration,
    build_v1_feed,
    build_v1_item,
    build_v2_entry,
    build_v2_feed,
    run_test_migration,
    write_inputs_manifest,
    write_plain_feed,
)
from vulnwitness.adapters.store.corpus_store import load_corpus_store
from vulnwitness.composition import load_packaged_fixture
from vulnwitness.domain.migration_report import (
    CandidateOutcome,
    CnvdOutcome,
    CveOutcome,
    MigrationFailureCode,
)


@pytest.mark.parametrize(
    "status", ["Analyzed", "Awaiting Analysis", "Future status", " spaced ", "", None]
)
def test_v2_status_is_stored_verbatim(tmp_path: Path, status: str | None) -> None:
    inputs_dir = tmp_path / "inputs"
    inputs_dir.mkdir()
    write_plain_feed(
        inputs_dir / "nvdcve-2.0-9999.json", build_v2_feed([build_v2_entry(1, status=status)])
    )
    manifest = write_inputs_manifest(inputs_dir, [build_declaration("nvdcve-2.0-9999.json")])
    target = tmp_path / "store"

    run_test_migration(manifest, target)
    corpus = load_corpus_store(target)

    assert corpus.records[0].nvd_status == status


def test_v1_and_fixture_records_have_no_nvd_status(tmp_path: Path) -> None:
    inputs_dir = tmp_path / "inputs"
    inputs_dir.mkdir()
    write_plain_feed(inputs_dir / "nvdcve-1.1-9999.json", build_v1_feed([build_v1_item(1)]))
    manifest = write_inputs_manifest(inputs_dir, [build_declaration("nvdcve-1.1-9999.json")])
    target = tmp_path / "store"

    run_test_migration(manifest, target)
    records = load_corpus_store(target).records + load_packaged_fixture().records

    for record in records:
        assert record.nvd_status is None
        assert record.cnvd == ()


def test_equal_time_v2_status_drops_otherwise_equal_v1_candidate_before_cnvd_join(
    tmp_path: Path,
) -> None:
    inputs_dir = tmp_path / "inputs"
    inputs_dir.mkdir()
    write_plain_feed(inputs_dir / "nvdcve-1.1-9999.json", build_v1_feed([build_v1_item(1)]))
    write_plain_feed(
        inputs_dir / "nvdcve-2.0-9999.json",
        build_v2_feed([build_v2_entry(1, published="2099-01-02T03:04:00.000")]),
    )
    cnvd_path = write_cnvd_file(inputs_dir, "cnvd.parquet", [build_cnvd_row(1)])
    dependencies = build_cnvd_dependencies(build_test_catalog([cnvd_path], [1]))
    manifest = write_inputs_manifest(
        inputs_dir,
        [
            build_declaration("nvdcve-1.1-9999.json"),
            build_declaration("nvdcve-2.0-9999.json"),
            build_declaration(cnvd_path.name, source="circl-cnvd"),
        ],
    )
    target = tmp_path / "store"

    report = run_test_migration(manifest, target, dependencies=dependencies)
    record = load_corpus_store(target).records[0]

    assert record.nvd_status == "Analyzed"
    assert report.candidate_outcomes[CandidateOutcome.DROPPED_FOR_FORMAT] == 1
    assert len(record.cnvd) == 1
    assert report.cnvd_outcomes[CnvdOutcome.MERGED] == 1


def test_equal_time_v2_candidates_differing_only_in_status_exclude_cve_and_keep_cnvd_pending(
    tmp_path: Path,
) -> None:
    inputs_dir = tmp_path / "inputs"
    inputs_dir.mkdir()
    write_plain_feed(
        inputs_dir / "nvdcve-2.0-9999.json",
        build_v2_feed([build_v2_entry(1), build_v2_entry(2)]),
    )
    write_plain_feed(
        inputs_dir / "nvdcve-2.0-modified.json",
        build_v2_feed([build_v2_entry(1, status="Deferred")]),
    )
    cnvd_path = write_cnvd_file(inputs_dir, "cnvd.parquet", [build_cnvd_row(1)])
    dependencies = build_cnvd_dependencies(build_test_catalog([cnvd_path], [1]))
    manifest = write_inputs_manifest(
        inputs_dir,
        [
            build_declaration("nvdcve-2.0-9999.json"),
            build_declaration("nvdcve-2.0-modified.json"),
            build_declaration(cnvd_path.name, source="circl-cnvd"),
        ],
    )
    target = tmp_path / "store"

    report = run_test_migration(manifest, target, dependencies=dependencies)
    corpus = load_corpus_store(target)

    assert report.cve_outcomes[CveOutcome.CONFLICTING_DUPLICATE] == 1
    assert len(corpus.records) == 1
    assert corpus.records[0].cve_id == build_cve_id(2)
    pending = corpus.cnvd_index.pending_by_cve_id[build_cve_id(1)]
    assert pending[0].outcome == "cnvd_for_excluded_nvd_record"


def test_catalog_revision_changes_import_identity_and_refuses_reusing_existing_target(
    tmp_path: Path,
) -> None:
    inputs_dir = tmp_path / "inputs"
    inputs_dir.mkdir()
    write_plain_feed(inputs_dir / "nvdcve-2.0-9999.json", build_v2_feed([build_v2_entry(1)]))
    cnvd_path = write_cnvd_file(inputs_dir, "cnvd.parquet", [build_cnvd_row(1)])
    manifest = write_inputs_manifest(
        inputs_dir,
        [
            build_declaration("nvdcve-2.0-9999.json"),
            build_declaration(cnvd_path.name, source="circl-cnvd"),
        ],
    )
    original_dependencies = build_cnvd_dependencies(build_test_catalog([cnvd_path], [1]))
    other_dependencies = build_cnvd_dependencies(
        build_test_catalog([cnvd_path], [1], revision="b" * 40)
    )
    first = run_test_migration(manifest, tmp_path / "first", dependencies=original_dependencies)
    second = run_test_migration(manifest, tmp_path / "second", dependencies=other_dependencies)

    repeated = run_test_migration(manifest, tmp_path / "first", dependencies=other_dependencies)

    assert first.import_identity_sha256 != second.import_identity_sha256
    assert repeated.failure is not None
    assert repeated.failure.code is MigrationFailureCode.TARGET_EXISTS
