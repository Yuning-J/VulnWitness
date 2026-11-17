"""``store coverage`` and ``store diff`` read named stores and print JSON; a refresh that
only rewrites ``lastModified`` shows as metadata-only, not as changed content."""

import json
from pathlib import Path
from typing import Any

import pytest

from tests.support.cnvd_inputs import build_raw_cnvd_record, build_raw_cnvd_scenario
from tests.support.corpus_stores import copy_compatibility_store, import_store
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


@pytest.mark.parametrize("store_format_version", [1, 2, 3])
def test_store_coverage_of_older_formats_reports_null_mirrored_counters(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], store_format_version: int
) -> None:
    store_root = tmp_path / "stores"
    store_root.mkdir()
    if store_format_version == 1:
        store_dir = copy_compatibility_store(store_root, "legacy")
    else:
        store_dir = import_store(store_root, "legacy", include_kev=False)
        manifest_path = store_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["store_format_version"] = store_format_version
        manifest_path.write_text(json.dumps(manifest))

    exit_code = main(["store", "coverage", "legacy"], {"VULNWITNESS_STORE_ROOT": str(store_root)})

    coverage = StoreCoverage.model_validate_json(capsys.readouterr().out)
    assert exit_code == 0
    assert coverage.store_format_version == store_format_version
    for counts in (*coverage.months, coverage.total):
        assert counts.with_source_affected is None
        assert counts.with_source_affected_versions is None
        assert counts.with_source_affected_purl is None
        assert counts.with_ssvc is None
        assert counts.ssvc_exploitation_poc is None
        assert counts.ssvc_exploitation_active is None
        assert counts.with_source_cvss >= 0


@pytest.mark.parametrize("command,names", [("coverage", ["new"]), ("diff", ["old", "new"])])
@pytest.mark.parametrize("root_kind", ["symlink", "missing", "file"])
def test_store_reports_refuse_unusable_roots_before_loading_stores(
    root_settings: dict[str, str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: str,
    names: list[str],
    root_kind: str,
) -> None:
    report_root = tmp_path / "report-root"
    if root_kind == "symlink":
        report_root.symlink_to(root_settings["VULNWITNESS_STORE_ROOT"], target_is_directory=True)
    elif root_kind == "file":
        report_root.write_text("not a directory")

    exit_code = main(["store", command, *names], {"VULNWITNESS_STORE_ROOT": str(report_root)})

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == f"vulnwitness store {command} failed: {names[0]}: store_root_unusable\n"


def test_store_command_help_lists_mirrored_coverage_counters(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["store", "--help"], {})

    help_text = capsys.readouterr().out
    assert stopped.value.code == 0
    for counter in ("source-CVSS", "source-affected", "purls", "SSVC"):
        assert counter in help_text


def test_pending_cnvd_differences_change_corpus_identity_but_not_semantic_records_identity(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    reports: list[StoreCoverage] = []
    for title in ("first", "second"):
        directory = tmp_path / title
        directory.mkdir()
        scenario = build_raw_cnvd_scenario(
            directory, [build_raw_cnvd_record(4, title=f"SYNTHETIC: {title}")]
        )
        imported = run_test_migration(
            scenario.manifest, scenario.target, dependencies=scenario.dependencies
        )
        assert imported.outcome is MigrationOutcome.IMPORTED
        assert (
            main(
                ["store", "coverage", "cnvd"],
                {"VULNWITNESS_STORE_ROOT": str(scenario.target.parent)},
            )
            == 0
        )
        printed = json.loads(capsys.readouterr().out)
        assert "semantic_records_sha256" in printed
        assert "semantic_content_sha256" not in printed
        reports.append(StoreCoverage.model_validate(printed))

    first, second = reports
    assert first.corpus_content_sha256 != second.corpus_content_sha256
    assert first.semantic_records_sha256 == second.semantic_records_sha256
