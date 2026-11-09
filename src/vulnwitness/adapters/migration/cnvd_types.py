"""CNVD rows and byte bounds shared without importing the optional Parquet reader."""

import re
from dataclasses import dataclass
from datetime import date

from vulnwitness.adapters.migration.input_files import InputFile
from vulnwitness.adapters.migration.migration_limits import MigrationLimits
from vulnwitness.domain.corpus_store_manifest import InputContainer
from vulnwitness.domain.cve import CVE_ID_PATTERN, MAX_CVE_ID_CHARS
from vulnwitness.domain.migration_report import MigrationFailed, MigrationFailureCode

CNVD_COLUMNS = ("id", "title", "description", "severity", "cve_id", "source")


@dataclass(frozen=True)
class CnvdRow:
    cnvd_id: str
    title: str
    description: str
    severity: str
    cve_id: str
    source: str
    products: tuple[str, ...] = ()
    submit_time: date | None = None
    open_time: date | None = None
    handling_advice: str | None = None

    def has_cve_id(self) -> bool:
        """Whether the whole, unchanged value is exactly one valid CVE ID."""
        return (
            len(self.cve_id) <= MAX_CVE_ID_CHARS
            and re.fullmatch(CVE_ID_PATTERN, self.cve_id) is not None
        )


def check_cnvd_input(input_file: InputFile, limits: MigrationLimits) -> None:
    """Require a plain file within the CNVD byte cap before copying or reading it."""
    if input_file.container is not InputContainer.PLAIN:
        raise MigrationFailed(MigrationFailureCode.CNVD_INVALID_PARQUET)
    if input_file.size_bytes > limits.max_cnvd_bytes:
        raise MigrationFailed(MigrationFailureCode.CNVD_FILE_TOO_LARGE)
