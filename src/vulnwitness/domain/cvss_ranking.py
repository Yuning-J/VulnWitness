"""Selection policy for a record's supplied CVSS metrics."""

from vulnwitness.domain.cve import CvssMetric

SEVERITY_ORDER = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def rank_cvss_metric(metric: CvssMetric) -> tuple[bool, bool, int, float]:
    """For display, prefer v3.x/v4.0 over v2.0, then primary, severity and base score."""
    severity_rank = -1
    if metric.base_severity is not None:
        severity_rank = SEVERITY_ORDER.index(metric.base_severity)
    return (
        metric.version != "2.0",
        metric.scorer_type == "primary",
        severity_rank,
        metric.base_score,
    )
