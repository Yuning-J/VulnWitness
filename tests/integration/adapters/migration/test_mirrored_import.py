"""Mirrored blocks survive import independently, with bounded data loss reported."""

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
from tests.support.mirrored_sources import build_source_affected, build_ssvc
from vulnwitness.adapters.store.corpus_store import load_corpus_store
from vulnwitness.domain.migration_report import MigrationOutcome
from vulnwitness.domain.normalization import DroppedMirroredBlocks


@pytest.mark.parametrize(
    "bad_fields,expected_drops",
    [
        (
            {"affected": [build_source_affected(versions=[{"version": "1", "status": "fixed"}])]},
            DroppedMirroredBlocks(source_affected=1),
        ),
        (
            {"affected": [build_source_affected(packageURL="invalid")]},
            DroppedMirroredBlocks(source_affected=1),
        ),
        (
            {"affected": [build_source_affected(vendor="v" * 2049)]},
            DroppedMirroredBlocks(source_affected=1),
        ),
        (
            {"metrics": {"ssvcV203": [build_ssvc(exploitation="public poc")]}},
            DroppedMirroredBlocks(ssvc=1),
        ),
        ({"cveTags": [{"tags": ["disputed"]}]}, DroppedMirroredBlocks(cve_tags=1)),
        ({"affected": {}}, DroppedMirroredBlocks(source_affected=1)),
        ({"metrics": {"ssvcV203": {}}}, DroppedMirroredBlocks(ssvc=1)),
        ({"cveTags": {}}, DroppedMirroredBlocks(cve_tags=1)),
        (
            {
                "affected": [
                    build_source_affected(
                        versions=[
                            {
                                "version": "1",
                                "status": "affected",
                                "changes": [{"at": "2", "status": "fixed"}],
                            }
                        ]
                    )
                ]
            },
            DroppedMirroredBlocks(source_affected=1),
        ),
    ],
    ids=[
        "version-status",
        "purl",
        "vendor",
        "ssvc",
        "tag-source",
        "affected-shape",
        "ssvc-shape",
        "tag-shape",
        "change-status",
    ],
)
def test_import_reports_dropped_mirrored_blocks_and_preserves_nvd_record(
    tmp_path: Path, bad_fields: dict[str, Any], expected_drops: DroppedMirroredBlocks
) -> None:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    metrics: dict[str, Any] = {
        "cvssMetricV31": [
            {
                "source": "nvd@nist.gov",
                "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N", "baseScore": 9.8},
            }
        ],
        "ssvcV203": [build_ssvc(exploitation="active")],
    }
    fields: dict[str, Any] = {
        "affected": [build_source_affected()],
        "metrics": metrics,
        "cveTags": [{"sourceIdentifier": "cna@democorp.example", "tags": ["disputed"]}],
    }
    for name, value in bad_fields.items():
        if name == "metrics":
            metrics.update(value)
        else:
            fields[name] = value
    entry = build_v2_entry(1, **fields)
    write_gzip_feed(inputs / "nvdcve-2.0-2099.json.gz", build_v2_feed([entry]))
    manifest = write_inputs_manifest(inputs, [build_declaration("nvdcve-2.0-2099.json.gz")])

    report = run_test_migration(manifest, tmp_path / "store")
    store = load_corpus_store(tmp_path / "store")

    assert report.outcome is MigrationOutcome.IMPORTED
    assert report.dropped_mirrored_blocks == expected_drops
    assert sum(report.normalization_failures.values()) == 0
    record = store.records[0]
    assert record.cvss[0].scorer == "nvd@nist.gov"
    assert record.affected[0].cpe is not None
    assert bool(record.source_affected) == (expected_drops.source_affected == 0)
    assert bool(record.ssvc) == (expected_drops.ssvc == 0)
    assert bool(record.cve_tags) == (expected_drops.cve_tags == 0)


def test_import_caps_and_counts_status_changes_and_each_name_list(tmp_path: Path) -> None:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    names: list[str] = []
    for name_number in range(19):
        names.append(f"name-{name_number}")
    changes: list[dict[str, str]] = []
    for change_number in range(67):
        changes.append({"at": f"1.{change_number}", "status": "unaffected"})
    affected = build_source_affected(
        cpes=[*names, names[0], ""],
        modules=names,
        platforms=names,
        versions=[{"version": "1", "status": "affected", "lessThan": "2", "changes": changes}],
    )
    entry = build_v2_entry(
        1,
        affected=[affected],
        cveTags=[{"sourceIdentifier": "cna@democorp.example", "tags": names}],
    )
    write_gzip_feed(inputs / "nvdcve-2.0-2099.json.gz", build_v2_feed([entry]))
    manifest = write_inputs_manifest(inputs, [build_declaration("nvdcve-2.0-2099.json.gz")])

    report = run_test_migration(manifest, tmp_path / "store")
    store = load_corpus_store(tmp_path / "store")

    assert report.outcome is MigrationOutcome.IMPORTED
    assert report.dropped_mirrored_blocks == DroppedMirroredBlocks()
    assert store.manifest.store_format_version == 4
    product = store.records[0].source_affected[0].products[0]
    version = product.versions[0]
    assert len(version.changes) == 64
    assert version.changes[0].at == "1.0"
    assert version.changes[-1].at == "1.63"
    assert version.omitted_changes == 3
    for name in ("cpes", "modules", "platforms"):
        assert getattr(product, name) == tuple(names[:16])
        assert getattr(product, f"omitted_{name}") == 3
    assert store.records[0].cve_tags[0].tags == tuple(names[:16])
    assert store.records[0].cve_tags[0].omitted_tags == 3


def test_dropped_blocks_are_counted_once_per_input_candidate_including_superseded_entries(
    tmp_path: Path,
) -> None:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    invalid_affected = [build_source_affected(packageURL="invalid")]
    entries = [
        build_v2_entry(1, affected=invalid_affected),
        build_v2_entry(1, last_modified="2099-02-01T00:00:00.000", affected=invalid_affected),
    ]
    write_gzip_feed(inputs / "nvdcve-2.0-2099.json.gz", build_v2_feed(entries))
    manifest = write_inputs_manifest(inputs, [build_declaration("nvdcve-2.0-2099.json.gz")])

    report = run_test_migration(manifest, tmp_path / "store")

    assert report.outcome is MigrationOutcome.IMPORTED
    assert report.dropped_mirrored_blocks == DroppedMirroredBlocks(source_affected=2)
    assert report.candidate_outcomes["chosen"] == 1
    assert report.candidate_outcomes["superseded"] == 1
