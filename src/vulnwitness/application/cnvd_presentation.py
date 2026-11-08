"""Presentation of recorded authority grades, without recomputing their comparison."""

from vulnwitness.domain.source_comparison import SourceComparison


def describe_cnvd_comparison(comparison: SourceComparison) -> str:
    """Name the recorded scorer and rule; only a higher grade merits a visible mark."""
    metric = comparison.nvd_raw_severity
    if comparison.grade_relative == "not_compared":
        return (
            f"CNVD grade relative to NVD's own CVSS v3: not_compared "
            f"({comparison.not_compared_reason}) under {comparison.rule}"
        )
    assert metric is not None
    assessment = f"{metric.scorer}'s CVSS {metric.cvss_version} {metric.base_severity}"
    if comparison.grade_relative == "higher":
        return f"◇ CNVD grades higher than {assessment} under {comparison.rule}"
    return (
        f"CNVD grade relative to {assessment}: {comparison.grade_relative} under {comparison.rule}"
    )
