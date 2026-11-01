"""Retrieval channels the search service fuses.

``allowed_cve_ids`` carries the structured-filter constraint into a channel so the
channel applies ``limit`` to records that satisfy it. ``None`` means unconstrained;
an empty set means no record can match.
"""

from collections.abc import Sequence, Set
from typing import Protocol

from vulnwitness.domain.search import RetrievalOutcome, SearchFilters


class LexicalRetriever(Protocol):
    def search(
        self, query_text: str, limit: int, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        """Up to ``limit`` matches, best first; ties ordered by ascending CVE ID.

        ``limit`` is at least 1: the search request bounds it before any retriever runs.
        """
        ...


class StructuredRetriever(Protocol):
    def search(self, filters: SearchFilters) -> RetrievalOutcome:
        """Every record satisfying the filters, ordered by CVE ID, with per-field reasons."""
        ...

    def holds_package_urls(self) -> bool:
        """Whether any record names a package URL a ``purls`` filter could match."""
        ...


class GraphRetriever(Protocol):
    def expand(
        self, seed_cve_ids: Sequence[str], limit: int, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        """Up to ``limit`` non-seed records sharing an asserted relation with a seed."""
        ...


class SemanticRetriever(Protocol):
    def search(
        self, query_text: str, limit: int, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        """Optional semantic matches without importing its implementation."""
        ...
