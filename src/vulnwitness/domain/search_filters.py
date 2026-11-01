"""Structured filter matching shared by retrieval and product investigations."""

from collections.abc import Iterable

from vulnwitness.domain.cve import CveRecord, purl_package_identity
from vulnwitness.domain.search import KEV_MATCH_TERM, SearchFilters


def fold_values(values: Iterable[str]) -> list[str]:
    folded_values: list[str] = []
    for value in values:
        folded_values.append(value.casefold())
    return folded_values


def match_filter_reasons(record: CveRecord, filters: SearchFilters) -> list[tuple[str, str]] | None:
    """One (field, value) reason per active filter, or ``None`` if any filter fails."""
    vendors: set[str] = set()
    products: set[str] = set()
    packages: set[str] = set()
    for affected_product in record.list_implicated_products():
        vendors.add(affected_product.vendor.casefold())
        products.add(affected_product.product.casefold())
        if affected_product.purl is not None:
            packages.add(purl_package_identity(affected_product.purl))
    severities: set[str] = set()
    for metric in record.cvss:
        if metric.base_severity is not None:
            severities.add(metric.base_severity)

    value_filters = (
        ("affected.vendor", vendors, fold_values(filters.vendors)),
        ("affected.product", products, fold_values(filters.products)),
        ("affected.purl", packages, fold_values(filters.purls)),
        ("cwe_ids", set(record.cwe_ids), filters.cwe_ids),
        ("cvss.base_severity", severities, filters.severities),
    )
    reasons: list[tuple[str, str]] = []
    for field_name, record_values, filter_values in value_filters:
        if not filter_values:
            continue
        shared_value = min(
            (value for value in filter_values if value in record_values), default=None
        )
        if shared_value is None:
            return None
        reasons.append((field_name, shared_value))
    if filters.origins:
        if record.vulnerability_origin not in filters.origins:
            return None
        reasons.append(("vulnerability_origin", record.vulnerability_origin.value))
    if filters.published_years:
        if record.published is None or record.published.year not in filters.published_years:
            return None
        reasons.append(("published.year", str(record.published.year)))
    if filters.kev_only:
        if record.kev is None:
            return None
        reasons.append(("kev", KEV_MATCH_TERM))
    return reasons
