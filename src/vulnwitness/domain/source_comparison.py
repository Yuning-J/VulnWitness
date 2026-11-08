"""VulnWitness's CNVD severity comparison, independent of either source's claims."""

from typing import Final, Literal

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
    "This is VulnWitness's comparison, not a statement by NVD or CNVD. "
    "CNVD's grading criteria are unverified; the severity mapping is VulnWitness's choice."
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


class SourceComparison(ContractModel):
    nvd_state: NvdState
    severity: Literal["agree", "disagree", "not_comparable"]
    rule: Literal["cnvd_severity_vs_nvd_primary_cvss3"] = "cnvd_severity_vs_nvd_primary_cvss3"
    cnvd_raw_severity: Literal["高", "中", "低"]
    nvd_raw_severity: ComparedNvdSeverity | None
    statement: Literal[
        "This is VulnWitness's comparison, not a statement by NVD or CNVD. "
        "CNVD's grading criteria are unverified; the severity mapping is VulnWitness's choice."
    ] = COMPARISON_STATEMENT


def compare_cnvd_severity(
    entry: CnvdEntry,
    record: CveRecord | None,
    pending_outcome: PendingCnvdOutcome | None = None,
) -> SourceComparison:
    """Compare a merged entry's primary v3.1 (else v3.0), or classify a pending entry.

    A missing record requires its stored pending outcome. v2, v4 and secondary metrics
    never participate; a selected v3.1 with no usable severity never falls back to v3.0.
    """
    if record is None:
        if pending_outcome is None:
            raise ValueError("a pending comparison requires its import outcome")
        return SourceComparison(
            nvd_state=PENDING_NVD_STATES[pending_outcome],
            severity="not_comparable",
            cnvd_raw_severity=CNVD_RAW_SEVERITIES[entry.severity],
            nvd_raw_severity=None,
        )
    compared_severity = None
    for version in ("3.1", "3.0"):
        for metric in record.cvss:
            if metric.version == version and metric.scorer_type == "primary":
                compared_severity = ComparedNvdSeverity(
                    base_severity=metric.base_severity,
                    cvss_version=version,
                )
                break
        if compared_severity is not None:
            break
    severity: Literal["agree", "disagree", "not_comparable"] = "not_comparable"
    if compared_severity is not None and compared_severity.base_severity not in (None, "NONE"):
        matching_severities = {"high": ("HIGH", "CRITICAL"), "medium": ("MEDIUM",), "low": ("LOW",)}
        severity = (
            "agree"
            if compared_severity.base_severity in matching_severities[entry.severity]
            else "disagree"
        )
    return SourceComparison(
        nvd_state=NVD_STATUS_STATES.get(record.nvd_status or "", "status_unknown"),
        severity=severity,
        cnvd_raw_severity=CNVD_RAW_SEVERITIES[entry.severity],
        nvd_raw_severity=compared_severity,
    )
