"""The product CLI uses the shared fixture service and bounded JSON/text views."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.cli import main
from cve_kgrag.composition import build_product_query_service
from cve_kgrag.domain.migration_report import MigrationOutcome
from cve_kgrag.domain.product_query import ProductQueryRequest
from tests.support.legacy_inputs import (
    build_declaration,
    build_v2_entry,
    build_v2_feed,
    run_test_migration,
    write_gzip_feed,
    write_inputs_manifest,
)
from tests.support.paths import REPOSITORY_SCHEMA_DIR
from tests.support.product_queries import PRODUCT, SMF_PRODUCT_ONLY, SMF_VENDOR_AND_PRODUCT


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
    environment = {"CVE_KGRAG_STORE_ROOT": str(store_root)}
    assert main(["store", "activate", "smf"], environment=environment) == 0
    capsys.readouterr()
    return environment


def test_product_json_prints_the_shared_service_answer_with_the_requested_cap(
    fixture_bundle: FixtureBundle,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    service = build_product_query_service(fixture_bundle)
    expected = service.query(ProductQueryRequest(vendor="democorp", version="2.0", limit=1))

    # Act
    exit_code = main(
        ["product", "--vendor", "democorp", "--version", "2.0", "--limit", "1"], environment={}
    )

    # Assert
    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) == expected.model_dump(mode="json")


def test_product_text_shows_basis_severity_kev_cap_and_nvd_limits(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    arguments = ["product", "--product", "demo_gateway", "--version", "2.0", "--format", "text"]

    # Act
    exit_code = main(arguments, environment={})

    # Assert
    summary = capsys.readouterr().out
    assert exit_code == 0
    assert "Product vulnerabilities:" in summary
    assert "Showing 2 of 2 matching CVEs (cap 10)." in summary
    assert "Basis: product_field (democorp:demo_gateway)" in summary
    assert "Severity: CRITICAL" in summary
    assert "KEV:" in summary
    assert "matches an NVD CPE version condition" in summary
    assert "this does not show the version is unaffected" in " ".join(summary.split())
    assert "Affectedness: unknown" in summary
    assert max(map(len, summary.splitlines())) <= 100


def test_unknown_product_exits_one_with_an_empty_counted_list(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    arguments = ["product", "--product", PRODUCT]

    # Act
    exit_code = main(arguments, environment={})

    # Assert
    vulnerabilities = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert vulnerabilities["items"] == []
    assert vulnerabilities["total_available"] == 0


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


@pytest.mark.parametrize("arguments", [["product"], ["product", "--version", "2.0"]])
def test_missing_product_and_vendor_exit_with_usage_error(arguments: list[str]) -> None:
    # Arrange / Act
    with pytest.raises(SystemExit) as stopped:
        main(arguments, environment={})

    # Assert
    assert stopped.value.code == 2


def test_cli_capabilities_lists_product_query_tool(capsys: pytest.CaptureFixture[str]) -> None:
    # Arrange / Act
    exit_code = main(["capabilities"], environment={})

    # Assert
    assert exit_code == 0
    capabilities = json.loads(capsys.readouterr().out)
    assert "query_product_vulnerabilities" in capabilities["tools"]
