"""Deterministic structured filtering over canonical CVE records."""

from collections.abc import Iterable

from vulnwitness.domain.cve import CveRecord
from vulnwitness.domain.search import RetrievalMatch, RetrievalOutcome, SearchFilters
from vulnwitness.domain.search_filters import match_filter_reasons
from vulnwitness.domain.taxonomy import BackendStatus


def names_package_url(record: CveRecord) -> bool:
    """Whether one of the record's implicated products names a package URL."""
    return any(product.purl is not None for product in record.list_implicated_products())


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
            reasons = match_filter_reasons(record, filters)
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
