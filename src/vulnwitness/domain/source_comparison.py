"""VulnWitness's CNVD severity comparison, independent of either source's claims."""

from operator import not_
from typing import Final, Literal, Self

from pydantic import ConfigDict, Field, model_validator

from vulnwitness.domain.cnvd import PendingCnvdOutcome
from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.cve import CnvdEntry, CveRecord, Severity

NvdState = Literal[
    "analysed",
    "awaiting_analysis",
    "deferred",
    "status_unknown",
    "not_in_nvd_snapshot",
    "rejected_by_nvd",
    "excluded_by_import",
]
COMPARISON_STATEMENT: Final = (
    "This is VulnWitness's mapping between two grading schemes, not a judgement that "
    "either source is right. CNVD's grading criteria are unverified. "
    "CVSS measures severity, not risk."
)
CNVD_RAW_SEVERITIES: dict[str, Literal["高", "中", "低"]] = {
    "high": "高",
    "medium": "中",
    "low": "低",
}
PENDING_NVD_STATES: dict[PendingCnvdOutcome, NvdState] = {
    "cnvd_without_nvd_record": "not_in_nvd_snapshot",
    "cnvd_for_rejected_nvd_record": "rejected_by_nvd",
    "cnvd_for_excluded_nvd_record": "excluded_by_import",
}
NVD_STATUS_STATES: dict[str, NvdState] = {
    "Analyzed": "analysed",
    "Modified": "analysed",
    "Received": "awaiting_analysis",
    "Awaiting Analysis": "awaiting_analysis",
    "Undergoing Analysis": "awaiting_analysis",
    "Deferred": "deferred",
}


class ComparedNvdSeverity(ContractModel):
    base_severity: Severity | None
    cvss_version: Literal["3.1", "3.0"]
    scorer: str = Field(min_length=1)
    scorer_type: Literal["primary", "secondary"] | None


class SourceComparison(ContractModel):
    model_config = ConfigDict(
        json_schema_extra={
            "if": {"properties": {"grade_relative": {"const": "not_compared"}}},
            "then": {
                "required": ["not_compared_reason"],
                "properties": {"not_compared_reason": {"type": "string"}},
            },
            "else": {"not": {"required": ["not_compared_reason"]}},
        }
    )

    nvd_state: NvdState
    grade_relative: Literal["higher", "same", "lower", "not_compared"]
    not_compared_reason: (
        Literal["no_nvd_record", "no_nvd_cvss3_metric", "no_usable_base_severity"] | None
    ) = Field(default=None, exclude_if=not_)
    rule: Literal["cnvd_grade_vs_nvd_own_cvss3"] = "cnvd_grade_vs_nvd_own_cvss3"
    cnvd_raw_severity: Literal["高", "中", "低"]
    nvd_raw_severity: ComparedNvdSeverity | None
    statement: Literal[
        "This is VulnWitness's mapping between two grading schemes, not a judgement that "
        "either source is right. CNVD's grading criteria are unverified. "
        "CVSS measures severity, not risk."
    ] = COMPARISON_STATEMENT

    @model_validator(mode="after")
    def check_not_compared_reason(self) -> Self:
        if (self.grade_relative == "not_compared") != (self.not_compared_reason is not None):
            raise ValueError("a reason is required exactly when grades are not compared")
        return self


def compare_cnvd_severity(
    entry: CnvdEntry,
    record: CveRecord | None,
    pending_outcome: PendingCnvdOutcome | None = None,
) -> SourceComparison:
    """Compare CNVD's grade with NVD's own v3.1 metric, else its v3.0 metric.

    A missing record requires its stored pending outcome. Only ``nvd@nist.gov`` scores
    participate, regardless of scorer type; an unusable v3.1 never falls back to v3.0.
    """
    if record is None:
        if pending_outcome is None:
            raise ValueError("a pending comparison requires its import outcome")
        return SourceComparison(
            nvd_state=PENDING_NVD_STATES[pending_outcome],
            grade_relative="not_compared",
            not_compared_reason="no_nvd_record",
            cnvd_raw_severity=CNVD_RAW_SEVERITIES[entry.severity],
            nvd_raw_severity=None,
        )
    compared_severity = select_nvd_cvss3(record)
    grade_relative: Literal["higher", "same", "lower", "not_compared"] = "not_compared"
    reason: Literal["no_nvd_cvss3_metric", "no_usable_base_severity"] | None = None
    if compared_severity is None:
        reason = "no_nvd_cvss3_metric"
    elif compared_severity.base_severity in (None, "NONE"):
        reason = "no_usable_base_severity"
    else:
        nvd_grades = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 2}
        cnvd_grades = {"low": 0, "medium": 1, "high": 2}
        nvd_grade = nvd_grades[compared_severity.base_severity]
        cnvd_grade = cnvd_grades[entry.severity]
        if cnvd_grade > nvd_grade:
            grade_relative = "higher"
        elif cnvd_grade < nvd_grade:
            grade_relative = "lower"
        else:
            grade_relative = "same"
    return SourceComparison(
        nvd_state=NVD_STATUS_STATES.get(record.nvd_status or "", "status_unknown"),
        grade_relative=grade_relative,
        not_compared_reason=reason,
        cnvd_raw_severity=CNVD_RAW_SEVERITIES[entry.severity],
        nvd_raw_severity=compared_severity,
    )


def select_nvd_cvss3(record: CveRecord) -> ComparedNvdSeverity | None:
    """NVD's own v3.1 metric, else v3.0; an unusable v3.1 never falls back."""
    for version in ("3.1", "3.0"):
        for metric in record.cvss:
            if metric.version == version and metric.scorer == "nvd@nist.gov":
                return ComparedNvdSeverity(
                    base_severity=metric.base_severity,
                    cvss_version=version,
                    scorer=metric.scorer,
                    scorer_type=metric.scorer_type,
                )
    return None
