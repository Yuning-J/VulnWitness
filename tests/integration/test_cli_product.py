"""The product CLI uses the shared fixture service and bounded JSON/text views."""

import json

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.cli import main
from cve_kgrag.composition import build_product_query_service
from cve_kgrag.domain.product_query import ProductQueryRequest
from tests.support.product_queries import PRODUCT


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
