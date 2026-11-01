"""Selection policy for a record's supplied CVSS metrics."""

from vulnwitness.domain.cve import CvssMetric

SEVERITY_ORDER = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def rank_cvss_metric(metric: CvssMetric) -> tuple[bool, int, float]:
    """Prefer primary scorers, then the highest supplied severity and base score."""
    severity_rank = -1
    if metric.base_severity is not None:
        severity_rank = SEVERITY_ORDER.index(metric.base_severity)
    return metric.scorer_type == "primary", severity_rank, metric.base_score
