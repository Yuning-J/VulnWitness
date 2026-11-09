"""Presentation of recorded authority grades, without recomputing their comparison."""

from vulnwitness.domain.name_check import CnvdNameCheck
from vulnwitness.domain.source_comparison import SourceComparison


def describe_cnvd_name_check(check: CnvdNameCheck) -> str:
    """Describe the served label and names without rerunning the name check."""
    labels = {
        "vendor_product_overlap": "vendor and product names overlap",
        "product_overlap": "only the product name overlaps",
        "vendor_overlap": "only the vendor name overlaps",
        "no_overlap": "no name overlap; review the link",
        "uncheckable": "cannot check",
    }
    reasons = {
        "no_nvd_record": "no servable NVD record",
        "no_affected_products": "no NVD affected products",
        "no_extractable_name": "no extractable CNVD name",
    }
    label = labels[check.result]
    if check.uncheckable_reason is not None:
        label += f" ({reasons[check.uncheckable_reason]})"
    text = f"CNVD name check: {label}. CNVD name: {check.cnvd_name or 'none extracted'}."
    if check.nvd_pair is not None:
        text += f" NVD vendor/product: {check.nvd_pair.vendor}/{check.nvd_pair.product}."
    return text


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
