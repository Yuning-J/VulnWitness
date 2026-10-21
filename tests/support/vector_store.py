"""A fixed query encoder and an in-memory vector collection standing in for Chroma, for the
semantic adapter (``VectorSemanticRetriever``)."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any


class FixedEncoder:
    def encode_query(self, query_text: str) -> list[float]:
        return [1.0, 0.0]


@dataclass
class FakeCollection:
    """Answers every query with the canned rows, or raises the canned error."""

    metadatas: list[dict[str, Any]] = field(default_factory=list)
    distances: list[float] = field(default_factory=list)
    query_error: Exception | None = None
    where_clauses: list[Mapping[str, Any] | None] = field(default_factory=list)

    def query(
        self,
        query_embeddings: list[list[float]],
        n_results: int,
        where: Mapping[str, Any] | None,
        include: Sequence[str],
    ) -> Mapping[str, Any]:
        self.where_clauses.append(where)
        if self.query_error is not None:
            raise self.query_error
        return {"metadatas": [self.metadatas], "distances": [self.distances]}
