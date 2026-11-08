"""Read CNVD Parquet all or nothing, through the migration parsers entry point only."""

import re

import pyarrow
import pyarrow.parquet

from vulnwitness.adapters.migration.cnvd_types import (
    CNVD_COLUMNS,
    CNVD_ID_PATTERN,
    CnvdRow,
    check_cnvd_input,
)
from vulnwitness.adapters.migration.input_files import InputFile, open_input_file
from vulnwitness.adapters.migration.migration_limits import MigrationLimits
from vulnwitness.domain.migration_report import MigrationFailed, MigrationFailureCode

PARQUET_MAGIC = b"PAR1"
CNVD_BATCH_ROWS = 1024


def check_cnvd_schema(schema: pyarrow.Schema) -> None:
    columns = set(schema.names)
    if not columns >= set(CNVD_COLUMNS):
        raise MigrationFailed(MigrationFailureCode.CNVD_MISSING_COLUMN)
    if columns != set(CNVD_COLUMNS) or len(schema) != len(CNVD_COLUMNS):
        raise MigrationFailed(MigrationFailureCode.CNVD_EXTRA_COLUMN)
    for column in schema:
        if not pyarrow.types.is_string(column.type):
            raise MigrationFailed(MigrationFailureCode.CNVD_MISTYPED_COLUMN)


def check_cnvd_row(row: CnvdRow, cnvd_ids: set[str]) -> None:
    if re.fullmatch(CNVD_ID_PATTERN, row.cnvd_id) is None:
        raise MigrationFailed(MigrationFailureCode.CNVD_INVALID_ID)
    if row.cnvd_id in cnvd_ids:
        raise MigrationFailed(MigrationFailureCode.CNVD_REPEATED_ID)
    if row.title == "":
        raise MigrationFailed(MigrationFailureCode.CNVD_EMPTY_TITLE)
    if row.description == "":
        raise MigrationFailed(MigrationFailureCode.CNVD_EMPTY_DESCRIPTION)
    if row.severity not in {"高", "中", "低"}:
        raise MigrationFailed(MigrationFailureCode.CNVD_INVALID_SEVERITY)
    if row.source != "cnvd":
        raise MigrationFailed(MigrationFailureCode.CNVD_INVALID_SOURCE)
    cnvd_ids.add(row.cnvd_id)


def read_cnvd_rows(
    input_file: InputFile, limits: MigrationLimits, cnvd_ids: set[str], preceding_rows: int
) -> tuple[CnvdRow, ...]:
    """Read the inspected snapshot, checking every structural rule and the total row cap.
    ``cnvd_ids`` holds IDs from preceding files and collects this file's IDs to reject
    duplicates across the whole revision. Raises ``MigrationFailed`` on any fault.
    """
    check_cnvd_input(input_file, limits)
    rows: list[CnvdRow] = []
    with open_input_file(input_file.path) as input_stream:
        try:
            if input_stream.read(4) != PARQUET_MAGIC:
                raise MigrationFailed(MigrationFailureCode.CNVD_INVALID_PARQUET)
            input_stream.seek(0)
            parquet_file = pyarrow.parquet.ParquetFile(input_stream)
            check_cnvd_schema(parquet_file.schema_arrow)
            if preceding_rows + parquet_file.metadata.num_rows > limits.max_cnvd_rows:
                raise MigrationFailed(MigrationFailureCode.CNVD_TOO_MANY_ROWS)
            for batch in parquet_file.iter_batches(batch_size=CNVD_BATCH_ROWS):
                for column in batch.columns:
                    if column.null_count:
                        raise MigrationFailed(MigrationFailureCode.CNVD_NULL_VALUE)
                for fields in batch.to_pylist():
                    row = CnvdRow(
                        cnvd_id=fields["id"],
                        title=fields["title"],
                        description=fields["description"],
                        severity=fields["severity"],
                        cve_id=fields["cve_id"],
                        source=fields["source"],
                    )
                    if preceding_rows + len(rows) >= limits.max_cnvd_rows:
                        raise MigrationFailed(MigrationFailureCode.CNVD_TOO_MANY_ROWS)
                    check_cnvd_row(row, cnvd_ids)
                    rows.append(row)
        except (pyarrow.ArrowException, OSError, ValueError):
            raise MigrationFailed(MigrationFailureCode.CNVD_INVALID_PARQUET) from None
    return tuple(rows)
