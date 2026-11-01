"""Read the CISA KEV catalog CSV, all or nothing (ADR 0008 §6).

KEV is a small authoritative catalog that states a vulnerability is exploited, so any
fault in it makes the whole input invalid rather than dropping a row: an unknown,
missing, repeated or empty column, a row of another width, a blank line, a required
value missing or malformed, a ``forensicTriage`` other than ``Yes`` or ``No``, or one CVE
in rows that disagree. Values are kept exactly as
the CSV module parses them, every present column included, so a row's anchor hashes
everything the catalog said.
"""

import csv
import io
import re
from dataclasses import dataclass
from datetime import date

from vulnwitness.adapters.migration.input_files import InputFile, open_input_file
from vulnwitness.adapters.migration.migration_limits import MigrationLimits
from vulnwitness.domain.corpus_store_manifest import InputContainer
from vulnwitness.domain.cve import CVE_ID_PATTERN, MAX_CVE_ID_CHARS
from vulnwitness.domain.migration_report import MigrationFailed, MigrationFailureCode

KEV_REQUIRED_COLUMNS = frozenset(
    {
        "cveID",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "dateAdded",
        "shortDescription",
        "requiredAction",
        "dueDate",
    }
)
# Columns CISA added after the catalog began; older snapshots lack them.
KEV_OPTIONAL_COLUMNS = frozenset({"notes", "knownRansomwareCampaignUse", "cwes", "forensicTriage"})
KEV_COLUMNS = KEV_REQUIRED_COLUMNS | KEV_OPTIONAL_COLUMNS
ISO_DATE_PATTERN = r"[0-9]{4}-[0-9]{2}-[0-9]{2}"
RANSOMWARE_VALUES = frozenset({"known", "unknown"})
# CISA's schema gives forensicTriage exactly two meanings, so any other spelling is a
# change upstream to review, not a value to accept.
FORENSIC_TRIAGE_VALUES = frozenset({"Yes", "No"})


@dataclass(frozen=True)
class KevCatalog:
    """The catalog's rows by CVE ID, each with every present column, and how many rows
    repeated an equal earlier row."""

    entries: dict[str, dict[str, str]]
    identical_duplicates: int


def is_calendar_date(text: str) -> bool:
    if re.fullmatch(ISO_DATE_PATTERN, text) is None:
        return False
    try:
        date.fromisoformat(text)
    except ValueError:
        return False
    return True


def check_header(header: list[str]) -> None:
    columns = set(header)
    has_bad_name = "" in columns or len(columns) != len(header)
    if has_bad_name or not columns <= KEV_COLUMNS or not columns >= KEV_REQUIRED_COLUMNS:
        raise MigrationFailed(MigrationFailureCode.KEV_INVALID_HEADER)


def read_kev_row(header: list[str], row: list[str]) -> dict[str, str]:
    """The row as a mapping of column to value; raises ``MigrationFailed`` for a row of
    another width or a required value missing or malformed."""
    if len(row) != len(header):
        raise MigrationFailed(MigrationFailureCode.KEV_INVALID_ROW)
    entry: dict[str, str] = {}
    for column, value in zip(header, row, strict=True):
        entry[column] = value
    is_valid = (
        len(entry["cveID"]) <= MAX_CVE_ID_CHARS
        and re.fullmatch(CVE_ID_PATTERN, entry["cveID"]) is not None
        and is_calendar_date(entry["dateAdded"])
        and (entry["dueDate"] == "" or is_calendar_date(entry["dueDate"]))
        and entry.get("knownRansomwareCampaignUse", "").casefold() in RANSOMWARE_VALUES | {""}
        and ("forensicTriage" not in entry or entry["forensicTriage"] in FORENSIC_TRIAGE_VALUES)
    )
    if not is_valid:
        raise MigrationFailed(MigrationFailureCode.KEV_INVALID_ROW)
    return entry


def check_kev_input(input_file: InputFile, limits: MigrationLimits) -> None:
    """Raise ``MigrationFailed`` unless the inspected KEV input is a plain file within the
    KEV cap; the importer checks it before copying the input for reading, so an oversized
    or compressed catalog costs no copy."""
    if input_file.container is not InputContainer.PLAIN:
        raise MigrationFailed(MigrationFailureCode.UNRECOGNISED_FORMAT)
    if input_file.size_bytes > limits.max_kev_bytes:
        raise MigrationFailed(MigrationFailureCode.KEV_TOO_LARGE)


def read_kev_catalog(input_file: InputFile, limits: MigrationLimits) -> KevCatalog:
    """The catalog the KEV input holds; raises ``MigrationFailed`` for any fault in it.
    The importer passes the input's snapshot (``snapshot_input``), so the rows are the
    inspected bytes, whose hash is the anchors' source version."""
    check_kev_input(input_file, limits)
    with open_input_file(input_file.path) as input_stream:
        try:
            catalog_bytes = input_stream.read(limits.max_kev_bytes + 1)
        except OSError:
            raise MigrationFailed(MigrationFailureCode.INPUT_UNREADABLE) from None
    if len(catalog_bytes) > limits.max_kev_bytes:
        raise MigrationFailed(MigrationFailureCode.KEV_TOO_LARGE)
    try:
        # utf-8-sig drops one leading BOM; a second stays in the first column's name.
        catalog_text = catalog_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise MigrationFailed(MigrationFailureCode.KEV_INVALID_ENCODING) from None
    rows = csv.reader(io.StringIO(catalog_text, newline=""), dialect="excel", strict=True)
    entries: dict[str, dict[str, str]] = {}
    identical_duplicates = 0
    try:
        header = next(rows, None)
        if header is None:
            raise MigrationFailed(MigrationFailureCode.KEV_INVALID_HEADER)
        check_header(header)
        for row_count, row in enumerate(rows, start=1):
            if row_count > limits.max_kev_rows:
                raise MigrationFailed(MigrationFailureCode.KEV_TOO_LARGE)
            entry = read_kev_row(header, row)
            earlier_entry = entries.get(entry["cveID"])
            if earlier_entry is None:
                entries[entry["cveID"]] = entry
            elif earlier_entry == entry:
                identical_duplicates += 1
            else:
                raise MigrationFailed(MigrationFailureCode.KEV_CONFLICTING_ROWS)
    except csv.Error:
        raise MigrationFailed(MigrationFailureCode.KEV_INVALID_ROW) from None
    return KevCatalog(entries=entries, identical_duplicates=identical_duplicates)
