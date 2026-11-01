"""Complete CLI traversals and private, atomic exports on the synthetic fixture."""

import csv
import json
import stat
from pathlib import Path

import pytest

from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.cli import main
from vulnwitness.composition import build_product_query_service
from vulnwitness.domain.product_query import ProductQueryRequest, ProductQueryResponse

ALL_DEMOCORP = ["product", "--vendor", "democorp", "--limit", "1", "--all"]


def test_all_combines_three_unmodified_schema_valid_pages_in_order(
    fixture_bundle: FixtureBundle, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    service = build_product_query_service(fixture_bundle)
    inventory = service.query(ProductQueryRequest(vendor="democorp", version="2.0", limit=20))

    # Act
    exit_code = main([*ALL_DEMOCORP, "--version", "2.0"], environment={})

    # Assert
    documents = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert len(documents) == 3
    pages: list[ProductQueryResponse] = []
    for document in documents:
        pages.append(ProductQueryResponse.model_validate(document))
    assert pages[0].cursor is None
    assert pages[-1].next_cursor is None
    assert pages[1].cursor == pages[0].next_cursor
    assert pages[2].cursor == pages[1].next_cursor
    vulnerabilities = []
    for page in pages:
        assert (page.vendor, page.product, page.version, page.limit) == ("democorp", None, "2.0", 1)
        assert page.total_available == 3
        vulnerabilities.extend(page.items)
    assert tuple(vulnerabilities) == inventory.items


def test_all_finishes_when_last_page_exactly_equals_the_page_cap(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    arguments = [*ALL_DEMOCORP, "--max-pages", "3"]

    # Act
    exit_code = main(arguments, environment={})

    # Assert
    assert exit_code == 0
    assert len(json.loads(capsys.readouterr().out)) == 3


def test_all_cap_failure_prints_no_truncated_json(capsys: pytest.CaptureFixture[str]) -> None:
    # Arrange
    arguments = [*ALL_DEMOCORP, "--max-pages", "2"]

    # Act
    exit_code = main(arguments, environment={})

    # Assert
    terminal = capsys.readouterr()
    assert exit_code == 2
    assert terminal.out == ""
    assert "--max-pages 2 before the end" in terminal.err


def test_cap_failure_preserves_existing_export_even_with_force(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    output = tmp_path / "inventory.csv"
    output.write_text("keep existing bytes")
    arguments = [
        *ALL_DEMOCORP,
        "--max-pages",
        "1",
        "--output",
        str(output),
        "--export",
        "csv",
        "--force",
    ]

    # Act
    exit_code = main(arguments, environment={})

    # Assert
    assert exit_code == 2
    assert output.read_text() == "keep existing bytes"
    assert list(tmp_path.iterdir()) == [output]
    assert "no output written" in capsys.readouterr().err


def test_csv_exports_every_cve_without_description_text_and_with_private_permissions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    output = tmp_path / "inventory.csv"
    arguments = [
        *ALL_DEMOCORP,
        "--version",
        "2.0",
        "--output",
        str(output),
        "--export",
        "csv",
    ]

    # Act
    exit_code = main(arguments, environment={})

    # Assert
    with output.open(newline="") as export_file:
        reader = csv.DictReader(export_file)
        rows = list(reader)
        assert reader.fieldnames == [
            "cve_id",
            "basis_kind",
            "matched_products",
            "nvd_version_note_outcome",
            "applicability",
            "published",
            "evidence_ids",
        ]
    assert exit_code == 0
    assert len(rows) == 3
    assert rows[0]["cve_id"] == "CVE-9999-0001"
    assert rows[0]["nvd_version_note_outcome"] == "hit"
    assert rows[1]["nvd_version_note_outcome"] == "unknown"
    assert rows[2]["nvd_version_note_outcome"] == "no_hit"
    assert json.loads(rows[0]["matched_products"]) == [
        {"vendor": "democorp", "product": "demo_gateway"}
    ]
    assert json.loads(rows[0]["evidence_ids"]) == ["ev:d8097ae9c31b754d26a1ef92"]
    assert all(row["applicability"] == "unknown" for row in rows)
    assert "SYNTHETIC" not in output.read_text()
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert list(tmp_path.iterdir()) == [output]
    assert capsys.readouterr().out == ""


def test_jsonl_exports_one_row_per_cve_and_preserves_descriptions(
    fixture_bundle: FixtureBundle, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    output = tmp_path / "inventory.jsonl"
    service = build_product_query_service(fixture_bundle)
    inventory = service.query(ProductQueryRequest(vendor="democorp", limit=20))

    # Act
    exit_code = main([*ALL_DEMOCORP, "--output", str(output), "--export", "jsonl"], environment={})

    # Assert
    rows = []
    for line in output.read_text().splitlines():
        rows.append(json.loads(line))
    assert exit_code == 0
    assert len(rows) == len(inventory.items) == 3
    for row, vulnerability in zip(rows, inventory.items, strict=True):
        assert row["cve_id"] == vulnerability.record.cve_id
        assert row["descriptions"] == vulnerability.record.model_dump(mode="json")["descriptions"]
        assert "nvd_version_note_outcome" not in row
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert capsys.readouterr().out == ""


def test_export_traverses_every_page_without_requiring_all_flag(tmp_path: Path) -> None:
    # Arrange
    output = tmp_path / "inventory.csv"
    arguments = [
        "product",
        "--vendor",
        "democorp",
        "--limit",
        "1",
        "--output",
        str(output),
        "--export",
        "csv",
    ]

    # Act
    exit_code = main(arguments, environment={})

    # Assert
    assert exit_code == 0
    with output.open(newline="") as export_file:
        assert len(list(csv.DictReader(export_file))) == 3


def test_export_cap_failure_does_not_create_a_partial_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    output = tmp_path / "inventory.csv"
    arguments = [
        "product",
        "--vendor",
        "democorp",
        "--limit",
        "1",
        "--max-pages",
        "1",
        "--output",
        str(output),
        "--export",
        "csv",
    ]

    # Act
    exit_code = main(arguments, environment={})

    # Assert
    assert exit_code == 2
    assert not output.exists()
    assert list(tmp_path.iterdir()) == []
    assert "--max-pages 1 before the end" in capsys.readouterr().err


def test_failed_atomic_publication_removes_the_temporary_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    output = tmp_path / "existing-directory"
    output.mkdir()
    arguments = [*ALL_DEMOCORP, "--output", str(output), "--export", "csv", "--force"]

    # Act
    exit_code = main(arguments, environment={})

    # Assert
    assert exit_code == 2
    assert output.is_dir()
    assert list(tmp_path.iterdir()) == [output]
    assert capsys.readouterr().out == ""


def test_existing_export_is_refused_without_force(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    output = tmp_path / "inventory.csv"
    output.write_text("keep existing bytes")

    # Act
    exit_code = main([*ALL_DEMOCORP, "--output", str(output), "--export", "csv"], environment={})

    # Assert
    assert exit_code == 2
    assert output.read_text() == "keep existing bytes"
    assert "already exists; use --force" in capsys.readouterr().err


def test_force_replaces_export_with_a_complete_private_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    output = tmp_path / "inventory.csv"
    output.write_text("replace these bytes")
    output.chmod(0o644)

    # Act
    exit_code = main(
        [*ALL_DEMOCORP, "--output", str(output), "--export", "csv", "--force"], environment={}
    )

    # Assert
    assert exit_code == 0
    assert "replace these bytes" not in output.read_text()
    with output.open(newline="") as export_file:
        assert len(list(csv.DictReader(export_file))) == 3
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert list(tmp_path.iterdir()) == [output]
    assert capsys.readouterr().out == ""


def test_empty_full_inventory_prints_one_empty_page_and_exits_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    arguments = ["product", "--product", "nonexistent_synthetic_product", "--all"]

    # Act
    exit_code = main(arguments, environment={})

    # Assert
    documents = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert len(documents) == 1
    assert documents[0]["items"] == []
    assert documents[0]["next_cursor"] is None


@pytest.mark.parametrize(
    "options",
    [
        ["--max-pages", "0"],
        ["--all", "--cursor", "invalid"],
        ["--all", "--format", "text"],
        ["--export", "csv"],
        ["--output", "unused.csv"],
        ["--force"],
    ],
)
def test_conflicting_export_or_traversal_options_exit_two_without_stdout(
    options: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    arguments = ["product", "--vendor", "democorp", *options]

    # Act
    exit_code = main(arguments, environment={})

    # Assert
    terminal = capsys.readouterr()
    assert exit_code == 2
    assert terminal.out == ""
    assert "vulnwitness product:" in terminal.err
