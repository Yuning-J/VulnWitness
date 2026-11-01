"""The product CLI over an imported store: description mentions honour an explicit vendor.

Building the store needs the migration extra, so the core-only lane skips this file.
"""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from tests.support.legacy_inputs import (
    build_declaration,
    build_v2_entry,
    build_v2_feed,
    run_test_migration,
    write_gzip_feed,
    write_inputs_manifest,
)
from tests.support.paths import REPOSITORY_SCHEMA_DIR
from tests.support.product_queries import SMF_PRODUCT_ONLY, SMF_VENDOR_AND_PRODUCT
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.cli import main
from vulnwitness.domain.migration_report import MigrationOutcome


@pytest.fixture
def smf_store_environment(
    tmp_path: Path,
    product_query_bundle: FixtureBundle,
    capsys: pytest.CaptureFixture[str],
) -> dict[str, str]:
    """An active temporary store imported from synthetic descriptions without CPEs."""
    entries = []
    for record in product_query_bundle.records:
        if record.cve_id in (SMF_PRODUCT_ONLY, SMF_VENDOR_AND_PRODUCT):
            entries.append(
                build_v2_entry(
                    int(record.cve_id.rsplit("-", 1)[1]),
                    description=record.descriptions[0].value,
                    configurations=[],
                )
            )
    feed_name = "nvdcve-2.0-2099.json.gz"
    write_gzip_feed(tmp_path / feed_name, build_v2_feed(entries))
    manifest_path = write_inputs_manifest(tmp_path, [build_declaration(feed_name)])
    store_root = tmp_path / "stores"
    store_root.mkdir()
    report = run_test_migration(manifest_path, store_root / "smf", store_root=store_root)
    assert report.outcome is MigrationOutcome.IMPORTED, report.failure
    environment = {"VULNWITNESS_STORE_ROOT": str(store_root)}
    assert main(["store", "activate", "smf"], environment=environment) == 0
    capsys.readouterr()
    return environment


@pytest.mark.parametrize(
    "vendor,expected_ids,excluded_count",
    [
        (None, [SMF_PRODUCT_ONLY, SMF_VENDOR_AND_PRODUCT], 0),
        ("free5gc", [SMF_VENDOR_AND_PRODUCT], 1),
        ("does-not-exist", [], 2),
    ],
)
def test_product_cli_exports_vendor_qualified_mentions_and_exclusion_count(
    smf_store_environment: dict[str, str],
    capsys: pytest.CaptureFixture[str],
    vendor: str | None,
    expected_ids: list[str],
    excluded_count: int,
) -> None:
    arguments = ["product", "--product", "smf"]
    if vendor is not None:
        arguments.extend(("--vendor", vendor))
    schema = json.loads((REPOSITORY_SCHEMA_DIR / "product_query_response.schema.json").read_text())

    exit_code = main(arguments, environment=smf_store_environment)

    vulnerabilities = json.loads(capsys.readouterr().out)
    Draft202012Validator(schema).validate(vulnerabilities)
    assert exit_code == (0 if expected_ids else 1)
    assert vulnerabilities["description_mentions_vendor_unconfirmed"] == excluded_count
    assert vulnerabilities["total_available"] == len(expected_ids)
    cve_ids = []
    for vulnerability in vulnerabilities["items"]:
        cve_ids.append(vulnerability["record"]["cve_id"])
    assert cve_ids == expected_ids


def test_product_text_reports_excluded_mentions_even_when_no_cves_match(
    smf_store_environment: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    arguments = ["product", "--vendor", "does-not-exist", "--product", "smf", "--format", "text"]

    exit_code = main(arguments, environment=smf_store_environment)

    summary = capsys.readouterr().out
    assert exit_code == 1
    assert "Showing 0 of 0 matching CVEs" in summary
    assert "Description mentions left out because the requested vendor was not named: 2." in summary
