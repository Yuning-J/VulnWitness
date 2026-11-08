"""The stated CNVD comparison rule keeps source claims and project choices distinct."""

import pytest

from tests.support.builders import build_cnvd_entry, build_cve_record, build_cvss_metric
from vulnwitness.domain.cnvd import PendingCnvdOutcome
from vulnwitness.domain.cve import CvssMetric
from vulnwitness.domain.source_comparison import COMPARISON_STATEMENT, compare_cnvd_severity


@pytest.mark.parametrize(
    "cnvd,nvd,expected",
    [
        ("high", "HIGH", "agree"),
        ("high", "CRITICAL", "agree"),
        ("medium", "MEDIUM", "agree"),
        ("low", "LOW", "agree"),
        ("high", "MEDIUM", "disagree"),
        ("medium", "HIGH", "disagree"),
        ("low", "MEDIUM", "disagree"),
        ("high", "NONE", "not_comparable"),
        ("medium", None, "not_comparable"),
    ],
    ids=[
        "high-high",
        "high-critical",
        "medium-medium",
        "low-low",
        "high-medium",
        "medium-high",
        "low-medium",
        "none",
        "missing-base-severity",
    ],
)
def test_severity_rule_compares_the_two_source_grades(
    cnvd: str, nvd: str | None, expected: str
) -> None:
    entry = build_cnvd_entry(severity=cnvd)
    record = build_cve_record(cvss=(build_cvss_metric(base_severity=nvd),))

    comparison = compare_cnvd_severity(entry, record)

    assert comparison.severity == expected
    assert comparison.nvd_raw_severity is not None
    assert comparison.nvd_raw_severity.base_severity == nvd
    assert comparison.nvd_raw_severity.cvss_version == "3.1"
    assert comparison.rule == "cnvd_severity_vs_nvd_primary_cvss3"
    assert comparison.statement == COMPARISON_STATEMENT
    assert comparison.cnvd_raw_severity == {"high": "高", "medium": "中", "low": "低"}[cnvd]


@pytest.mark.parametrize(
    "metrics,version,expected",
    [
        ((), None, "not_comparable"),
        ((build_cvss_metric(version="2.0"),), None, "not_comparable"),
        ((build_cvss_metric(version="4.0"),), None, "not_comparable"),
        ((build_cvss_metric(scorer_type="secondary"),), None, "not_comparable"),
        ((build_cvss_metric(scorer_type=None),), None, "not_comparable"),
        ((build_cvss_metric(version="3.0"),), "3.0", "agree"),
        (
            (build_cvss_metric(version="3.0", base_severity="HIGH"), build_cvss_metric()),
            "3.1",
            "agree",
        ),
        (
            (build_cvss_metric(), build_cvss_metric(version="3.0", base_severity="HIGH")),
            "3.1",
            "agree",
        ),
        (
            (build_cvss_metric(scorer_type="secondary", base_severity="HIGH"), build_cvss_metric()),
            "3.1",
            "agree",
        ),
        (
            (build_cvss_metric(base_severity=None), build_cvss_metric(version="3.0")),
            "3.1",
            "not_comparable",
        ),
        (
            (build_cvss_metric(base_severity="NONE"), build_cvss_metric(version="3.0")),
            "3.1",
            "not_comparable",
        ),
    ],
    ids=[
        "no-score",
        "v2-only",
        "v4-only",
        "cna-only",
        "unknown-scorer-type",
        "v30-fallback",
        "v31-over-earlier-v30",
        "v31-over-later-v30",
        "ignore-secondary",
        "v31-null-no-fallback",
        "v31-none-no-fallback",
    ],
)
def test_only_primary_v31_else_v30_participates(
    metrics: tuple[CvssMetric, ...],
    version: str | None,
    expected: str,
) -> None:
    record = build_cve_record(cvss=metrics)

    comparison = compare_cnvd_severity(build_cnvd_entry(), record)

    assert comparison.severity == expected
    assert (
        None if comparison.nvd_raw_severity is None else comparison.nvd_raw_severity.cvss_version
    ) == version


@pytest.mark.parametrize(
    "status,expected",
    [
        ("Analyzed", "analysed"),
        ("Modified", "analysed"),
        ("Received", "awaiting_analysis"),
        ("Awaiting Analysis", "awaiting_analysis"),
        ("Undergoing Analysis", "awaiting_analysis"),
        ("Deferred", "deferred"),
        (None, "status_unknown"),
        ("Future Status", "status_unknown"),
    ],
    ids=[
        "analyzed",
        "modified",
        "received",
        "awaiting",
        "undergoing",
        "deferred",
        "absent",
        "future",
    ],
)
def test_nvd_status_is_classified_without_affecting_severity(
    status: str | None, expected: str
) -> None:
    record = build_cve_record(nvd_status=status, cvss=(build_cvss_metric(),))

    comparison = compare_cnvd_severity(build_cnvd_entry(), record)

    assert comparison.nvd_state == expected
    assert comparison.severity == "agree"
    assert record.nvd_status == status


@pytest.mark.parametrize(
    "outcome,expected",
    [
        ("cnvd_without_nvd_record", "not_in_nvd_snapshot"),
        ("cnvd_for_rejected_nvd_record", "rejected_by_nvd"),
        ("cnvd_for_excluded_nvd_record", "excluded_by_import"),
    ],
    ids=["absent", "rejected", "excluded"],
)
def test_pending_outcomes_are_not_comparable(outcome: PendingCnvdOutcome, expected: str) -> None:
    comparison = compare_cnvd_severity(build_cnvd_entry(), None, outcome)

    assert comparison.nvd_state == expected
    assert comparison.severity == "not_comparable"
    assert comparison.nvd_raw_severity is None
