"""Deterministic structured filtering over canonical CVE records."""

from collections.abc import Iterable, Set

from cve_kgrag.domain.cve import CveRecord, purl_package_identity
from cve_kgrag.domain.search import KEV_MATCH_TERM, RetrievalMatch, RetrievalOutcome, SearchFilters
from cve_kgrag.domain.taxonomy import BackendStatus


def first_shared_value(record_values: Set[str], filter_values: Iterable[str]) -> str | None:
    """The alphabetically first filter value the record also has, or ``None``."""
    return min((value for value in filter_values if value in record_values), default=None)


def names_package_url(record: CveRecord) -> bool:
    """Whether one of the record's implicated products names a package URL."""
    return any(product.purl is not None for product in record.list_implicated_products())


def fold_values(values: Iterable[str]) -> list[str]:
    folded_values: list[str] = []
    for value in values:
        folded_values.append(value.casefold())
    return folded_values


class InMemoryStructuredIndex:
    """Implements ``StructuredRetriever``. Each match lists, per filter field, one value it met."""

    def __init__(self, records: Iterable[CveRecord]) -> None:
        self._records = tuple(sorted(records, key=lambda record: record.cve_id))
        self._holds_package_urls = any(map(names_package_url, self._records))

    def holds_package_urls(self) -> bool:
        """Decided once, when the index is built: whether any record names a package URL
        among its implicated products, the ones a ``purls`` filter compares."""
        return self._holds_package_urls

    def search(self, filters: SearchFilters) -> RetrievalOutcome:
        matches: list[RetrievalMatch] = []
        for record in self._records:
            reasons = self._match_reasons(record, filters)
            if reasons is None:
                continue
            matched_fields: list[str] = []
            matched_terms: list[str] = []
            for field_name, value in reasons:
                matched_fields.append(field_name)
                matched_terms.append(value)
            matches.append(
                RetrievalMatch(
                    cve_id=record.cve_id,
                    score=float(len(reasons)),
                    matched_fields=tuple(matched_fields),
                    matched_terms=tuple(matched_terms),
                )
            )
        return RetrievalOutcome(status=BackendStatus.OK, matches=tuple(matches))

    def _match_reasons(
        self, record: CveRecord, filters: SearchFilters
    ) -> list[tuple[str, str]] | None:
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
            shared_value = first_shared_value(record_values, filter_values)
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
