"""Semantic retrieval over an injected vector collection and text encoder."""

import logging
from collections.abc import Mapping, Sequence, Set
from typing import Any, Protocol

from cve_kgrag.adapters.semantic.chunk_hits import collapse_chunk_hits, read_chroma_query_hits
from cve_kgrag.domain.search import RetrievalOutcome
from cve_kgrag.domain.taxonomy import BackendFailure, BackendStatus


class TextEncoder(Protocol):
    def encode_query(self, query_text: str) -> list[float]: ...


class VectorCollection(Protocol):
    def query(
        self,
        query_embeddings: list[list[float]],
        n_results: int,
        where: Mapping[str, Any] | None,
        include: Sequence[str],
    ) -> Mapping[str, Any]:
        """A Chroma-shaped single-query answer: ``metadatas`` and ``distances`` rows."""
        ...


class VectorSemanticRetriever:
    """Implements ``SemanticRetriever`` over a chunked CVE collection.

    ``limit`` bounds the chunks fetched, so several chunks of one CVE can leave
    fewer than ``limit`` CVEs. Filters run inside the store as a ``cve_id``
    metadata constraint. An empty answer is an index gap: a nearest-neighbour
    query returns chunks whenever the collection holds any for the allowed CVEs.
    """

    def __init__(self, collection: VectorCollection, encoder: TextEncoder) -> None:
        self._collection = collection
        self._encoder = encoder

    def search(
        self, query_text: str, limit: int, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        if allowed_cve_ids is not None and not allowed_cve_ids:
            return RetrievalOutcome(status=BackendStatus.OK)
        where = None if allowed_cve_ids is None else {"cve_id": {"$in": sorted(allowed_cve_ids)}}
        try:
            query_hits = self._collection.query(
                query_embeddings=[self._encoder.encode_query(query_text)],
                n_results=limit,
                where=where,
                include=["metadatas", "distances"],
            )
            chunk_hits = read_chroma_query_hits(query_hits)
        except Exception as error:  # the vector store and model raise arbitrary errors
            # By type only: a store's error can name its database path.
            logging.getLogger(__name__).warning("semantic search raised %s", type(error).__name__)
            return RetrievalOutcome(
                status=BackendStatus.ERROR, failure=BackendFailure.SEARCH_FAILED
            )
        if not chunk_hits:
            return RetrievalOutcome(
                status=BackendStatus.INCOMPLETE_INDEX, failure=BackendFailure.INDEX_INCOMPLETE
            )
        return RetrievalOutcome(
            status=BackendStatus.OK,
            matches=collapse_chunk_hits(chunk_hits, limit, allowed_cve_ids),
        )
