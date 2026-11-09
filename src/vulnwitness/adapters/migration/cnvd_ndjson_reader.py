"""Read operator-supplied raw CNVD records, retaining only ADR 0018's fields."""

import json
import re
from dataclasses import replace
from datetime import date

from vulnwitness.adapters.migration.cnvd_types import CnvdRow
from vulnwitness.adapters.migration.input_files import InputFile, open_input_file
from vulnwitness.adapters.migration.migration_limits import MigrationLimits
from vulnwitness.domain.corpus_store_manifest import InputContainer
from vulnwitness.domain.cve import CNVD_ID_PATTERN
from vulnwitness.domain.migration_report import MigrationFailed, MigrationFailureCode
from vulnwitness.domain.timestamps import CALENDAR_DATE_PATTERN


def check_raw_cnvd_input(input_file: InputFile, limits: MigrationLimits) -> None:
    """Require a plain input within the raw CNVD file cap before copying it."""
    if input_file.container is not InputContainer.PLAIN:
        raise MigrationFailed(MigrationFailureCode.CNVD_INVALID_NDJSON)
    if input_file.size_bytes > limits.max_raw_cnvd_bytes:
        raise MigrationFailed(MigrationFailureCode.CNVD_FILE_TOO_LARGE)


def read_text(record: dict[str, object], field: str) -> str:
    value = record[field]
    if not isinstance(value, str):
        raise ValueError("expected text")
    value.encode("utf-8")
    return value


def read_date(record: dict[str, object], field: str) -> date | None:
    if field not in record:
        return None
    value = read_text(record, field)
    if re.fullmatch(CALENDAR_DATE_PATTERN, value) is None:
        raise ValueError("expected a calendar date")
    return date.fromisoformat(value)


def read_objects(value: object) -> list[dict[str, object]]:
    """The source uses a single object or a list for CVEs and products."""
    if isinstance(value, dict):
        return [value]
    if not isinstance(value, list):
        raise ValueError("expected an object or list")
    objects = []
    for element in value:
        if not isinstance(element, dict):
            raise ValueError("expected an object")
        objects.append(element)
    return objects


def read_cve_ids(record: dict[str, object]) -> tuple[str, ...]:
    cve_ids: list[str] = []
    for citation in read_objects(record.get("cves", [])):
        cve = citation["cve"]
        if not isinstance(cve, dict):
            raise ValueError("expected a CVE object")
        cve_id = read_text(cve, "cveNumber")
        if cve_id not in cve_ids:
            cve_ids.append(cve_id)
    return tuple(cve_ids) or ("",)


def read_products(record: dict[str, object]) -> tuple[str, ...]:
    products: list[str] = []
    for product_group in read_objects(record.get("products", [])):
        product = product_group["product"]
        if isinstance(product, str):
            products.append(read_text(product_group, "product"))
        elif isinstance(product, list):
            for product_text in product:
                if not isinstance(product_text, str):
                    raise ValueError("expected product text")
                product_text.encode("utf-8")
                products.append(product_text)
        else:
            raise ValueError("expected product text or a list")
    return tuple(products)


def parse_raw_cnvd_record(record: object) -> tuple[CnvdRow, ...]:
    """Validate retained fields strictly, ignoring every unrelated source key."""
    if not isinstance(record, dict):
        raise ValueError("expected a record object")
    cnvd_id = read_text(record, "number")
    title = read_text(record, "title")
    description = read_text(record, "description")
    severity = read_text(record, "serverity")
    if re.fullmatch(CNVD_ID_PATTERN, cnvd_id) is None:
        raise ValueError("invalid CNVD ID")
    if not title or not description or severity not in {"高", "中", "低"}:
        raise ValueError("invalid CNVD text or grade")
    row = CnvdRow(
        cnvd_id=cnvd_id,
        title=title,
        description=description,
        severity=severity,
        cve_id="",
        source="cnvd",
        products=read_products(record),
        submit_time=read_date(record, "submitTime"),
        open_time=read_date(record, "openTime"),
        handling_advice=read_text(record, "formalWay") if "formalWay" in record else None,
    )
    rows = []
    for cve_id in read_cve_ids(record):
        rows.append(replace(row, cve_id=cve_id))
    return tuple(rows)


def read_raw_cnvd_rows(
    input_file: InputFile, limits: MigrationLimits, preceding_rows: int
) -> tuple[CnvdRow, ...]:
    """Read a bounded snapshot all or nothing; failures name their one-based line.

    Each record produces one row per distinct cited CVE, or an empty-CVE row.
    The total row cap includes expanded links and records superseded by later files.
    """
    check_raw_cnvd_input(input_file, limits)
    rows: list[CnvdRow] = []
    cnvd_ids: set[str] = set()
    line_number = 0
    with open_input_file(input_file.path) as input_stream:
        while line := input_stream.readline(limits.max_entry_bytes + 1):
            line_number += 1
            if preceding_rows + len(rows) >= limits.max_cnvd_rows:
                raise MigrationFailed(
                    MigrationFailureCode.CNVD_TOO_MANY_ROWS, input_line=line_number
                )
            try:
                if len(line) > limits.max_entry_bytes:
                    raise ValueError("record exceeds byte cap")
                record_rows = parse_raw_cnvd_record(json.loads(line.decode("utf-8")))
            except (ValueError, KeyError, RecursionError):
                raise MigrationFailed(
                    MigrationFailureCode.CNVD_INVALID_RECORD, input_line=line_number
                ) from None
            cnvd_id = record_rows[0].cnvd_id
            if cnvd_id in cnvd_ids:
                raise MigrationFailed(MigrationFailureCode.CNVD_REPEATED_ID, input_line=line_number)
            cnvd_ids.add(cnvd_id)
            rows.extend(record_rows)
            if len(rows) + preceding_rows > limits.max_cnvd_rows:
                raise MigrationFailed(
                    MigrationFailureCode.CNVD_TOO_MANY_ROWS, input_line=line_number
                )
    return tuple(rows)
