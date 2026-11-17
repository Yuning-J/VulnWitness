"""Recognise NVD-owned metrics across stored NVD feed formats."""

from vulnwitness.domain.cve import CvssMetric


def is_nvd_own_metric(metric: CvssMetric) -> bool:
    """JSON 1.1 uses ``NVD``; API 2.0 uses ``nvd@nist.gov``."""
    return metric.scorer in ("NVD", "nvd@nist.gov")
