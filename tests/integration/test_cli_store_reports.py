"""``store coverage`` and ``store diff`` read named stores and print JSON; a refresh that
only rewrites ``lastModified`` shows as metadata-only, not as changed content."""

from pathlib import Path
from typing import Any

import pytest

from tests.support.legacy_inputs import (
    build_declaration,
    build_v2_entry,
    build_v2_feed,
    run_test_migration,
    write_gzip_feed,
    write_inputs_manifest,
)
from vulnwitness.cli import main
from vulnwitness.domain.migration_report import MigrationOutcome
from vulnwitness.domain.store_coverage import StoreCoverage, StoreSemanticDiff


def import_entries(store_root: Path, name: str, entries: list[dict[str, Any]]) -> None:
    inputs_dir = store_root.parent / f"inputs-{name}"
    inputs_dir.mkdir()
    write_gzip_feed(inputs_dir / "nvdcve-2.0-2099.json.gz", build_v2_feed(entries))
    manifest_path = write_inputs_manifest(
        inputs_dir, [build_declaration("nvdcve-2.0-2099.json.gz")]
    )
    report = run_test_migration(manifest_path, store_root / name, store_root=store_root)
    assert report.outcome is MigrationOutcome.IMPORTED, report.failure


@pytest.fixture
def root_settings(tmp_path: Path) -> dict[str, str]:
    store_root = tmp_path / "stores"
    store_root.mkdir()
    import_entries(
        store_root,
        "old",
        [build_v2_entry(1), build_v2_entry(2), build_v2_entry(3, status="Deferred")],
    )
    refreshed = "2099-06-17T00:00:00.000"
    import_entries(
        store_root,
        "new",
        [
            build_v2_entry(1, last_modified=refreshed),
            build_v2_entry(2, last_modified=refreshed, description="SYNTHETIC: edited."),
            build_v2_entry(3, status="Deferred"),
            build_v2_entry(4, status="Deferred", configurations=[]),
        ],
    )
    return {"VULNWITNESS_STORE_ROOT": str(store_root)}


def test_store_coverage_counts_statuses_and_cpe(
    root_settings: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["store", "coverage", "new"], root_settings)

    coverage = StoreCoverage.model_validate_json(capsys.readouterr().out)
    assert exit_code == 0
    assert coverage.records == 4
    assert coverage.total.nvd_status == {"Analyzed": 2, "Deferred": 2}
    assert coverage.total.enrichment.not_scheduled == 2
    assert coverage.total.with_vulnerable_cpe == 3


def test_store_diff_separates_timestamp_refreshes(
    root_settings: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["store", "diff", "old", "new"], root_settings)

    diff = StoreSemanticDiff.model_validate_json(capsys.readouterr().out)
    assert exit_code == 0
    assert (diff.metadata_only, diff.changed, diff.unchanged, diff.added) == (2, 1, 0, 1)
    assert diff.changed_ids == ("CVE-9999-0002",)
    assert diff.changed_fields == {"descriptions": 1}


def test_store_report_on_a_missing_store_exits_one_without_a_path(
    root_settings: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["store", "diff", "old", "missing"], root_settings)

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "vulnwitness store diff failed: missing: store_missing\n"
