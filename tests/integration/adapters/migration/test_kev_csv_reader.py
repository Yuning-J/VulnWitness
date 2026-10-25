"""``read_kev_catalog`` on KEV CSV files under ``tmp_path`` (ADR 0008 §6): a valid catalog
is read whole, in any column order, with or without the three optional columns, values
kept exactly as parsed; equal repeated rows are counted and unequal ones refused; and
every fault in the header, a row, a value, the encoding, the container or the size makes
the whole input invalid with its fixed reason code, as does a catalog rewritten after it
was inspected."""

import csv
import gzip
import io
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from cve_kgrag.adapters.migration.input_files import inspect_input_file
from cve_kgrag.adapters.migration.kev_csv_reader import KevCatalog, read_kev_catalog
from cve_kgrag.adapters.migration.migration_limits import MigrationLimits
from cve_kgrag.domain.cve import MAX_CVE_ID_CHARS
from cve_kgrag.domain.migration_report import MigrationFailed, MigrationFailureCode
from tests.support.legacy_inputs import (
    KEV_COLUMNS,
    build_cve_id,
    build_kev_row,
    encode_kev_csv,
    write_kev_csv,
)

DEFAULT_LIMITS = MigrationLimits()
REQUIRED_COLUMNS = [
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
]
OPTIONAL_COLUMNS = ["notes", "knownRansomwareCampaignUse", "cwes"]
UTF8_BOM = b"\xef\xbb\xbf"

FileWriter = Callable[[Path], Path]
CatalogChange = Callable[[Path, list[dict[str, str]]], None]


def read_catalog_at(path: Path, limits: MigrationLimits = DEFAULT_LIMITS) -> KevCatalog:
    """The catalog the file at ``path`` holds, inspected as the importer inspects it."""
    input_file = inspect_input_file(path, limits)
    return read_kev_catalog(input_file, limits)


def read_failure_code(path: Path, limits: MigrationLimits = DEFAULT_LIMITS) -> MigrationFailureCode:
    with pytest.raises(MigrationFailed) as failure:
        read_catalog_at(path, limits)
    return failure.value.code


def encode_csv_line(values: list[str]) -> bytes:
    """One CSV line as CISA writes it, for rows the KEV builders cannot express."""
    text_stream = io.StringIO(newline="")
    csv.writer(text_stream, dialect="excel").writerow(values)
    return text_stream.getvalue().encode()


def columns_without(*absent_columns: str) -> list[str]:
    columns: list[str] = []
    for column in KEV_COLUMNS:
        if column not in absent_columns:
            columns.append(column)
    return columns


def write_catalog_bytes(path: Path, catalog_bytes: bytes) -> Path:
    path.write_bytes(catalog_bytes)
    return path


def encode_unquoted_csv_line(row: dict[str, str]) -> bytes:
    """One CSV line of ``row`` in ``KEV_COLUMNS`` order, every value written as it is,
    so a value may hold quotes a CSV writer would have escaped."""
    values: list[str] = []
    for column in KEV_COLUMNS:
        values.append(row[column])
    return (",".join(values) + "\r\n").encode()


def rewrite_catalog_in_place(path: Path, rows: list[dict[str, str]]) -> None:
    write_kev_csv(path, rows)


def replace_catalog_by_rename(path: Path, rows: list[dict[str, str]]) -> None:
    replacement_path = write_kev_csv(path.with_name("replacement.csv"), rows)
    replacement_path.replace(path)


def test_valid_catalog_is_read_with_every_row_by_cve_id(tmp_path: Path) -> None:
    path = write_kev_csv(tmp_path / "kev.csv", [build_kev_row(1), build_kev_row(2)])

    catalog = read_catalog_at(path)

    assert catalog == KevCatalog(
        entries={build_cve_id(1): build_kev_row(1), build_cve_id(2): build_kev_row(2)},
        identical_duplicates=0,
    )


def test_catalog_with_a_header_and_no_rows_is_empty(tmp_path: Path) -> None:
    path = write_kev_csv(tmp_path / "kev.csv", [])

    catalog = read_catalog_at(path)

    assert catalog == KevCatalog(entries={}, identical_duplicates=0)


def test_column_order_does_not_change_the_catalog(tmp_path: Path) -> None:
    rows = [build_kev_row(1, notes="first"), build_kev_row(2, cwes="CWE-20")]
    reversed_columns = list(reversed(KEV_COLUMNS))
    standard_path = write_kev_csv(tmp_path / "standard.csv", rows)
    reordered_path = write_kev_csv(tmp_path / "reordered.csv", rows, reversed_columns)

    standard_catalog = read_catalog_at(standard_path)
    reordered_catalog = read_catalog_at(reordered_path)

    assert reordered_catalog == standard_catalog


@pytest.mark.parametrize(
    "absent_columns",
    [("notes",), ("knownRansomwareCampaignUse",), ("cwes",), tuple(OPTIONAL_COLUMNS)],
    ids=["without_notes", "without_ransomware_use", "without_cwes", "without_all_three"],
)
def test_catalog_without_optional_columns_is_read_without_those_keys(
    tmp_path: Path, absent_columns: tuple[str, ...]
) -> None:
    columns = columns_without(*absent_columns)
    path = write_kev_csv(tmp_path / "kev.csv", [build_kev_row(1)], columns)
    expected_entry = build_kev_row(1)
    for column in absent_columns:
        del expected_entry[column]

    catalog = read_catalog_at(path)

    assert catalog.entries == {build_cve_id(1): expected_entry}


def test_every_column_but_cve_id_and_date_added_may_be_empty(tmp_path: Path) -> None:
    sparse_row = build_kev_row(
        1,
        vendorProject="",
        product="",
        vulnerabilityName="",
        shortDescription="",
        requiredAction="",
        dueDate="",
        knownRansomwareCampaignUse="",
        notes="",
        cwes="",
    )
    path = write_kev_csv(tmp_path / "kev.csv", [sparse_row])

    catalog = read_catalog_at(path)

    assert catalog.entries == {build_cve_id(1): sparse_row}


def test_values_are_kept_exactly_as_parsed_without_trimming(tmp_path: Path) -> None:
    untrimmed_row = build_kev_row(
        1,
        vendorProject="  Democorp  ",
        product="\tGateway",
        shortDescription='SYNTHETIC: a "quoted", comma-bearing\r\nmulti-line value ',
        notes=" ",
    )
    path = write_kev_csv(tmp_path / "kev.csv", [untrimmed_row])

    catalog = read_catalog_at(path)

    assert catalog.entries == {build_cve_id(1): untrimmed_row}


@pytest.mark.parametrize("missing_column", REQUIRED_COLUMNS, ids=REQUIRED_COLUMNS)
def test_header_missing_a_required_column_is_invalid(tmp_path: Path, missing_column: str) -> None:
    path = write_kev_csv(tmp_path / "kev.csv", [build_kev_row(1)], columns_without(missing_column))

    failure_code = read_failure_code(path)

    assert failure_code is MigrationFailureCode.KEV_INVALID_HEADER


@pytest.mark.parametrize(
    "columns",
    [
        [*KEV_COLUMNS, "epss"],
        [*KEV_COLUMNS, "cveID"],
        [*KEV_COLUMNS, "notes"],
        [*KEV_COLUMNS, ""],
        ["CVEID", *KEV_COLUMNS[1:]],
        [" cveID", *KEV_COLUMNS[1:]],
    ],
    ids=[
        "unknown_column",
        "repeated_required_column",
        "repeated_optional_column",
        "empty_column_name",
        "column_name_in_another_case",
        "column_name_with_a_leading_space",
    ],
)
def test_header_with_an_unknown_repeated_or_empty_name_is_invalid(
    tmp_path: Path, columns: list[str]
) -> None:
    path = write_kev_csv(tmp_path / "kev.csv", [build_kev_row(1)], columns)

    failure_code = read_failure_code(path)

    assert failure_code is MigrationFailureCode.KEV_INVALID_HEADER


@pytest.mark.parametrize(
    "catalog_bytes", [b"", UTF8_BOM], ids=["empty_file", "byte_order_mark_only"]
)
def test_file_without_a_header_line_is_invalid(tmp_path: Path, catalog_bytes: bytes) -> None:
    path = write_catalog_bytes(tmp_path / "kev.csv", catalog_bytes)

    failure_code = read_failure_code(path)

    assert failure_code is MigrationFailureCode.KEV_INVALID_HEADER


@pytest.mark.parametrize(
    "extra_line",
    [
        encode_csv_line([build_cve_id(2), "Democorp"]),
        encode_csv_line([*build_kev_row(2).values(), "surplus"]),
        b"\r\n",
        b"   \r\n",
    ],
    ids=["row_too_narrow", "row_too_wide", "blank_line", "line_of_spaces"],
)
def test_row_of_another_width_than_the_header_is_invalid(tmp_path: Path, extra_line: bytes) -> None:
    last_line = encode_csv_line(list(build_kev_row(3).values()))
    catalog_bytes = encode_kev_csv([build_kev_row(1)]) + extra_line + last_line
    path = write_catalog_bytes(tmp_path / "kev.csv", catalog_bytes)

    failure_code = read_failure_code(path)

    assert failure_code is MigrationFailureCode.KEV_INVALID_ROW


def test_blank_line_after_the_last_row_is_invalid(tmp_path: Path) -> None:
    path = write_catalog_bytes(tmp_path / "kev.csv", encode_kev_csv([build_kev_row(1)]) + b"\r\n")

    failure_code = read_failure_code(path)

    assert failure_code is MigrationFailureCode.KEV_INVALID_ROW


@pytest.mark.parametrize(
    "malformed_line",
    [
        b'"CVE-9999-0002,Democorp\r\n',
        b'"CVE-9999-0002"x,Democorp,Gateway,a,2099-01-05,b,c,2099-01-26,Unknown,,\r\n',
    ],
    ids=["unterminated_quote", "character_after_closing_quote"],
)
def test_row_the_strict_csv_dialect_cannot_parse_is_invalid(
    tmp_path: Path, malformed_line: bytes
) -> None:
    path = write_catalog_bytes(
        tmp_path / "kev.csv", encode_kev_csv([build_kev_row(1)]) + malformed_line
    )

    failure_code = read_failure_code(path)

    assert failure_code is MigrationFailureCode.KEV_INVALID_ROW


@pytest.mark.parametrize(
    "column", ["notes", "shortDescription"], ids=["notes", "short_description"]
)
def test_otherwise_valid_row_with_text_after_a_closing_quote_is_invalid(
    tmp_path: Path, column: str
) -> None:
    """``"x"y`` is a quoted ``x`` then a stray ``y``: a lenient reader joins them into
    ``xy`` and keeps the row; the strict dialect refuses it."""
    unquoted_line = encode_unquoted_csv_line(build_kev_row(2, **{column: '"x"y'}))
    path = write_catalog_bytes(
        tmp_path / "kev.csv", encode_kev_csv([build_kev_row(1)]) + unquoted_line
    )

    failure_code = read_failure_code(path)

    assert failure_code is MigrationFailureCode.KEV_INVALID_ROW


@pytest.mark.parametrize(
    "cve_id",
    [
        "",
        "CVE-9999-001",
        "cve-9999-0001",
        "CVE-99-0001",
        " CVE-9999-0001",
        "CVE-9999-0001\n",
        "CVE-9999-" + "1" * (MAX_CVE_ID_CHARS - len("CVE-9999-") + 1),
    ],
    ids=[
        "empty",
        "three_digit_sequence",
        "lower_case_prefix",
        "two_digit_year",
        "leading_space",
        "trailing_newline",
        "longer_than_any_cve_id",
    ],
)
def test_row_without_a_valid_cve_id_is_invalid(tmp_path: Path, cve_id: str) -> None:
    path = write_kev_csv(tmp_path / "kev.csv", [build_kev_row(1, cveID=cve_id)])

    failure_code = read_failure_code(path)

    assert failure_code is MigrationFailureCode.KEV_INVALID_ROW


INVALID_DATES = ["20990105", "2099-W01-1", "2099-02-30", "2099-1-05", "2099-01-05T00:00:00"]
INVALID_DATE_IDS = [
    "basic_format",
    "iso_week_date",
    "not_a_calendar_day",
    "single_digit_month",
    "date_and_time",
]


@pytest.mark.parametrize("date_added", ["", *INVALID_DATES], ids=["empty", *INVALID_DATE_IDS])
def test_row_without_a_valid_date_added_is_invalid(tmp_path: Path, date_added: str) -> None:
    path = write_kev_csv(tmp_path / "kev.csv", [build_kev_row(1, dateAdded=date_added)])

    failure_code = read_failure_code(path)

    assert failure_code is MigrationFailureCode.KEV_INVALID_ROW


def test_row_with_an_empty_due_date_is_read_as_empty(tmp_path: Path) -> None:
    path = write_kev_csv(tmp_path / "kev.csv", [build_kev_row(1, dueDate="")])

    catalog = read_catalog_at(path)

    assert catalog.entries[build_cve_id(1)]["dueDate"] == ""


@pytest.mark.parametrize("due_date", INVALID_DATES, ids=INVALID_DATE_IDS)
def test_row_with_a_malformed_due_date_is_invalid(tmp_path: Path, due_date: str) -> None:
    path = write_kev_csv(tmp_path / "kev.csv", [build_kev_row(1, dueDate=due_date)])

    failure_code = read_failure_code(path)

    assert failure_code is MigrationFailureCode.KEV_INVALID_ROW


@pytest.mark.parametrize(
    "ransomware_use",
    ["Known", "Unknown", "known", "UNKNOWN", "kNoWn", ""],
    ids=["known", "unknown", "lower_case", "upper_case", "mixed_case", "empty"],
)
def test_ransomware_use_in_either_case_or_empty_is_kept_as_written(
    tmp_path: Path, ransomware_use: str
) -> None:
    path = write_kev_csv(
        tmp_path / "kev.csv", [build_kev_row(1, knownRansomwareCampaignUse=ransomware_use)]
    )

    catalog = read_catalog_at(path)

    assert catalog.entries[build_cve_id(1)]["knownRansomwareCampaignUse"] == ransomware_use


@pytest.mark.parametrize(
    "ransomware_use",
    ["Yes", "N/A", " Known", "Unknown ", "Knowns"],
    ids=["yes", "not_applicable", "leading_space", "trailing_space", "longer_word"],
)
def test_ransomware_use_other_than_known_or_unknown_is_invalid(
    tmp_path: Path, ransomware_use: str
) -> None:
    path = write_kev_csv(
        tmp_path / "kev.csv", [build_kev_row(1, knownRansomwareCampaignUse=ransomware_use)]
    )

    failure_code = read_failure_code(path)

    assert failure_code is MigrationFailureCode.KEV_INVALID_ROW


@pytest.mark.parametrize(
    ("repeated_rows", "expected_duplicates"),
    [(2, 1), (3, 2)],
    ids=["one_repeat", "two_repeats"],
)
def test_identical_repeated_rows_are_kept_once_and_counted(
    tmp_path: Path, repeated_rows: int, expected_duplicates: int
) -> None:
    rows = [build_kev_row(2)]
    for _ in range(repeated_rows):
        rows.append(build_kev_row(1))
    path = write_kev_csv(tmp_path / "kev.csv", rows)

    catalog = read_catalog_at(path)

    assert catalog == KevCatalog(
        entries={build_cve_id(2): build_kev_row(2), build_cve_id(1): build_kev_row(1)},
        identical_duplicates=expected_duplicates,
    )


@pytest.mark.parametrize(
    "conflicting_row",
    [
        build_kev_row(1, notes="a later note"),
        build_kev_row(1, dueDate=""),
        build_kev_row(1, knownRansomwareCampaignUse="known"),
        build_kev_row(1, vendorProject="Democorp "),
    ],
    ids=[
        "different_notes",
        "due_date_dropped",
        "ransomware_use_in_another_case",
        "trailing_space_only",
    ],
)
def test_repeated_rows_that_differ_in_any_value_are_conflicting(
    tmp_path: Path, conflicting_row: dict[str, str]
) -> None:
    path = write_kev_csv(tmp_path / "kev.csv", [build_kev_row(1), conflicting_row])

    failure_code = read_failure_code(path)

    assert failure_code is MigrationFailureCode.KEV_CONFLICTING_ROWS


def test_one_leading_byte_order_mark_is_accepted(tmp_path: Path) -> None:
    rows = [build_kev_row(1)]
    path = write_catalog_bytes(tmp_path / "kev.csv", UTF8_BOM + encode_kev_csv(rows))

    catalog = read_catalog_at(path)

    assert catalog.entries == {build_cve_id(1): build_kev_row(1)}


def test_two_leading_byte_order_marks_leave_an_invalid_header(tmp_path: Path) -> None:
    path = write_catalog_bytes(
        tmp_path / "kev.csv", UTF8_BOM + UTF8_BOM + encode_kev_csv([build_kev_row(1)])
    )

    failure_code = read_failure_code(path)

    assert failure_code is MigrationFailureCode.KEV_INVALID_HEADER


@pytest.mark.parametrize(
    "catalog_bytes",
    [
        encode_kev_csv([build_kev_row(1, notes="Café")]).decode().encode("latin-1"),
        encode_kev_csv([build_kev_row(1)]).decode().encode("utf-16"),
        encode_kev_csv([build_kev_row(1)]) + b"\xff",
    ],
    ids=["latin_1_value", "utf_16_file", "stray_invalid_byte"],
)
def test_catalog_that_is_not_utf_8_is_invalid_encoding(
    tmp_path: Path, catalog_bytes: bytes
) -> None:
    path = write_catalog_bytes(tmp_path / "kev.csv", catalog_bytes)

    failure_code = read_failure_code(path)

    assert failure_code is MigrationFailureCode.KEV_INVALID_ENCODING


def write_gzip_catalog(path: Path) -> Path:
    path.write_bytes(gzip.compress(encode_kev_csv([build_kev_row(1)]), mtime=0))
    return path


def write_zip_catalog(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("known_exploited_vulnerabilities.csv", encode_kev_csv([build_kev_row(1)]))
    return path


@pytest.mark.parametrize(
    "write_catalog", [write_gzip_catalog, write_zip_catalog], ids=["gzip", "zip"]
)
def test_compressed_catalog_is_an_unrecognised_format(
    tmp_path: Path, write_catalog: FileWriter
) -> None:
    path = write_catalog(tmp_path / "kev.csv")

    failure_code = read_failure_code(path)

    assert failure_code is MigrationFailureCode.UNRECOGNISED_FORMAT


@pytest.mark.parametrize(
    "change_catalog",
    [rewrite_catalog_in_place, replace_catalog_by_rename],
    ids=["rewritten", "renamed_over"],
)
def test_catalog_changed_after_inspection_fails_as_input_changed(
    tmp_path: Path, change_catalog: CatalogChange
) -> None:
    # The new catalog is valid and the same size; only its bytes tell it apart.
    path = write_kev_csv(tmp_path / "kev.csv", [build_kev_row(1)])
    input_file = inspect_input_file(path, DEFAULT_LIMITS)
    change_catalog(path, [build_kev_row(2)])

    with pytest.raises(MigrationFailed) as failure:
        read_kev_catalog(input_file, DEFAULT_LIMITS)

    assert failure.value.code is MigrationFailureCode.INPUT_CHANGED


def test_catalog_exactly_at_the_byte_cap_is_read(tmp_path: Path) -> None:
    path = write_kev_csv(tmp_path / "kev.csv", [build_kev_row(1)])
    limits = MigrationLimits(max_kev_bytes=path.stat().st_size)

    catalog = read_catalog_at(path, limits)

    assert list(catalog.entries) == [build_cve_id(1)]


def test_catalog_one_byte_over_the_byte_cap_is_too_large(tmp_path: Path) -> None:
    path = write_kev_csv(tmp_path / "kev.csv", [build_kev_row(1)])
    limits = MigrationLimits(max_kev_bytes=path.stat().st_size - 1)

    failure_code = read_failure_code(path, limits)

    assert failure_code is MigrationFailureCode.KEV_TOO_LARGE


def test_catalog_exactly_at_the_row_cap_is_read(tmp_path: Path) -> None:
    path = write_kev_csv(tmp_path / "kev.csv", [build_kev_row(1), build_kev_row(2)])
    limits = MigrationLimits(max_kev_rows=2)

    catalog = read_catalog_at(path, limits)

    assert list(catalog.entries) == [build_cve_id(1), build_cve_id(2)]


@pytest.mark.parametrize(
    "rows",
    [
        [build_kev_row(1), build_kev_row(2), build_kev_row(3)],
        [build_kev_row(1), build_kev_row(1), build_kev_row(1)],
    ],
    ids=["distinct_rows", "identical_rows"],
)
def test_catalog_one_row_over_the_row_cap_is_too_large(
    tmp_path: Path, rows: list[dict[str, str]]
) -> None:
    path = write_kev_csv(tmp_path / "kev.csv", rows)
    limits = MigrationLimits(max_kev_rows=2)

    failure_code = read_failure_code(path, limits)

    assert failure_code is MigrationFailureCode.KEV_TOO_LARGE
