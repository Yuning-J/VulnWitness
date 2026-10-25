"""Why a source entry could not be normalized: a fixed code per reason.

A normalizer raises with one of these codes, so a batch import can report what it
skipped without its message, which may quote the entry.
"""

from enum import StrEnum


class NormalizationFailureCode(StrEnum):
    WRONG_JSON_TYPE = "wrong_json_type"
    MISSING_FIELD = "missing_field"
    INVALID_TIMESTAMP = "invalid_timestamp"
    INVALID_DATE = "invalid_date"
    INVALID_CONFIGURATION = "invalid_configuration"
    INVALID_CPE = "invalid_cpe"
    INVALID_REFERENCE = "invalid_reference"
    INVALID_CVSS = "invalid_cvss"
    INVALID_KEV_ENTRY = "invalid_kev_entry"
    NO_DESCRIPTION = "no_description"
    CONTRACT_VIOLATION = "contract_violation"
    REJECTED_BY_SOURCE = "rejected_by_source"
