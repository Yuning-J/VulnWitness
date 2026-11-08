"""Revision language declarations are optional and never inferred from CNVD's name."""

from pathlib import Path
from textwrap import dedent

import pytest
from pydantic import ValidationError

from vulnwitness.adapters.migration.cnvd_snapshot_catalog import load_cnvd_snapshot_catalog


@pytest.mark.parametrize(
    "declaration,expected",
    [("    language: zh\n", "zh"), ("    language: zh-Hans\n", "zh-Hans"), ("", None)],
    ids=["declared-zh", "preserve-declared-tag", "undeclared"],
)
def test_catalog_loads_optional_language_per_revision(
    tmp_path: Path, declaration: str, expected: str | None
) -> None:
    catalog_file = tmp_path / "snapshots.yaml"
    catalog_file.write_text(
        dedent(f"""\
        snapshots:
          - revision: "{"a" * 40}"
            files:
              - upstream_path: data/test.parquet
                sha256: "{"1" * 64}"
                row_count: 1
          - revision: "{"b" * 40}"
            files:
              - upstream_path: data/test.parquet
                sha256: "{"2" * 64}"
                row_count: 1
        """)
    )

    if declaration:
        catalog_file.write_text(
            catalog_file.read_text().replace("    files:", declaration + "    files:", 1)
        )

    catalog = load_cnvd_snapshot_catalog(catalog_file)

    assert catalog.snapshots[0].language == expected
    assert catalog.snapshots[1].language is None


def test_catalog_rejects_empty_language_declaration(tmp_path: Path) -> None:
    catalog_file = tmp_path / "snapshots.yaml"
    catalog_file.write_text(
        dedent(f"""\
        snapshots:
          - revision: "{"a" * 40}"
            language: ""
            files:
              - upstream_path: data/test.parquet
                sha256: "{"1" * 64}"
                row_count: 1
        """)
    )

    with pytest.raises(ValidationError, match="language"):
        load_cnvd_snapshot_catalog(catalog_file)
