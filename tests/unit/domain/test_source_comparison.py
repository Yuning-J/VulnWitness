"""The CNVD grade mapping preserves each assessing body's score and provenance."""

import pytest
from pydantic import ValidationError

from tests.support.builders import build_cnvd_entry, build_cve_record, build_cvss_metric
from vulnwitness.domain.cnvd import PendingCnvdOutcome
from vulnwitness.domain.cve import CvssMetric
from vulnwitness.domain.source_comparison import (
    COMPARISON_STATEMENT,
    SourceComparison,
    compare_cnvd_severity,
)


@pytest.mark.parametrize(
    "cnvd,nvd,expected,reason",
    [
        ("high", "HIGH", "same", None),
        ("high", "CRITICAL", "same", None),
        ("medium", "MEDIUM", "same", None),
        ("low", "LOW", "same", None),
        ("high", "MEDIUM", "higher", None),
        ("high", "LOW", "higher", None),
        ("medium", "LOW", "higher", None),
        ("medium", "HIGH", "lower", None),
        ("low", "MEDIUM", "lower", None),
        ("low", "CRITICAL", "lower", None),
        ("high", "NONE", "not_compared", "no_usable_base_severity"),
        ("medium", None, "not_compared", "no_usable_base_severity"),
    ],
    ids=[
        "high-high",
        "high-critical",
        "medium-medium",
        "low-low",
        "high-medium",
        "high-low",
        "medium-low",
        "medium-high",
        "low-medium",
        "low-critical",
        "none",
        "missing-base-severity",
    ],
)
def test_grade_relative_maps_the_two_source_grades(
    cnvd: str, nvd: str | None, expected: str, reason: str | None
) -> None:
    entry = build_cnvd_entry(severity=cnvd)
    record = build_cve_record(cvss=(build_cvss_metric(base_severity=nvd),))

    comparison = compare_cnvd_severity(entry, record)

    assert comparison.grade_relative == expected
    assert comparison.not_compared_reason == reason
    assert ("not_compared_reason" in comparison.model_dump()) == (reason is not None)
    assert comparison.nvd_raw_severity is not None
    assert comparison.nvd_raw_severity.model_dump() == {
        "base_severity": nvd,
        "cvss_version": "3.1",
        "scorer": "nvd@nist.gov",
        "scorer_type": "primary",
    }
    assert comparison.rule == "cnvd_grade_vs_nvd_own_cvss3"
    assert comparison.statement == COMPARISON_STATEMENT
    assert comparison.cnvd_raw_severity == {"high": "高", "medium": "中", "low": "低"}[cnvd]


@pytest.mark.parametrize(
    "metrics,version,expected,reason",
    [
        ((), None, "not_compared", "no_nvd_cvss3_metric"),
        ((build_cvss_metric(version="2.0"),), None, "not_compared", "no_nvd_cvss3_metric"),
        ((build_cvss_metric(version="4.0"),), None, "not_compared", "no_nvd_cvss3_metric"),
        (
            (build_cvss_metric(scorer="cna@example.org"),),
            None,
            "not_compared",
            "no_nvd_cvss3_metric",
        ),
        ((build_cvss_metric(scorer="NVD"),), None, "not_compared", "no_nvd_cvss3_metric"),
        ((build_cvss_metric(scorer_type="secondary"),), "3.1", "same", None),
        ((build_cvss_metric(scorer_type=None),), "3.1", "same", None),
        ((build_cvss_metric(version="3.0"),), "3.0", "same", None),
        (
            (build_cvss_metric(version="3.0", base_severity="HIGH"), build_cvss_metric()),
            "3.1",
            "same",
            None,
        ),
        (
            (build_cvss_metric(), build_cvss_metric(version="3.0", base_severity="HIGH")),
            "3.1",
            "same",
            None,
        ),
        (
            (
                build_cvss_metric(scorer="cna@example.org", base_severity="HIGH"),
                build_cvss_metric(scorer_type="secondary"),
            ),
            "3.1",
            "same",
            None,
        ),
        (
            (build_cvss_metric(scorer="cna@example.org"), build_cvss_metric(version="3.0")),
            "3.0",
            "same",
            None,
        ),
        (
            (build_cvss_metric(base_severity=None), build_cvss_metric(version="3.0")),
            "3.1",
            "not_compared",
            "no_usable_base_severity",
        ),
        (
            (build_cvss_metric(base_severity="NONE"), build_cvss_metric(version="3.0")),
            "3.1",
            "not_compared",
            "no_usable_base_severity",
        ),
    ],
    ids=[
        "no-score",
        "v2-only",
        "v4-only",
        "cna-primary-only",
        "exact-scorer-only",
        "nvd-secondary",
        "nvd-unknown-type",
        "v30-fallback",
        "v31-over-earlier-v30",
        "v31-over-later-v30",
        "cna-primary-nvd-secondary",
        "cna-v31-nvd-v30",
        "v31-null-no-fallback",
        "v31-none-no-fallback",
    ],
)
def test_only_nvd_own_v31_else_v30_participates(
    metrics: tuple[CvssMetric, ...], version: str | None, expected: str, reason: str | None
) -> None:
    record = build_cve_record(cvss=metrics)

    comparison = compare_cnvd_severity(build_cnvd_entry(), record)

    assert comparison.grade_relative == expected
    assert comparison.not_compared_reason == reason
    assert (
        None if comparison.nvd_raw_severity is None else comparison.nvd_raw_severity.cvss_version
    ) == version
    if comparison.nvd_raw_severity is not None:
        selected = next(
            metric
            for metric in metrics
            if metric.scorer == "nvd@nist.gov" and metric.version == version
        )
        assert comparison.nvd_raw_severity.scorer == selected.scorer
        assert comparison.nvd_raw_severity.scorer_type == selected.scorer_type


@pytest.mark.parametrize(
    "grade,reason",
    [("same", "no_nvd_record"), ("not_compared", None)],
    ids=["compared-with-reason", "not-compared-without-reason"],
)
def test_comparison_rejects_inconsistent_reason(grade: str, reason: str | None) -> None:
    comparison = compare_cnvd_severity(build_cnvd_entry(), build_cve_record()).model_dump()
    comparison.update(grade_relative=grade, not_compared_reason=reason)

    with pytest.raises(ValidationError, match="a reason is required exactly"):
        SourceComparison.model_validate(comparison)


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
    assert comparison.grade_relative == "same"
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
def test_pending_outcomes_are_not_compared(outcome: PendingCnvdOutcome, expected: str) -> None:
    comparison = compare_cnvd_severity(build_cnvd_entry(), None, outcome)

    assert comparison.nvd_state == expected
    assert comparison.grade_relative == "not_compared"
    assert comparison.nvd_raw_severity is None
    assert comparison.not_compared_reason == "no_nvd_record"
