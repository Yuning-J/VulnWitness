"""Chroma + sentence-transformers wiring for the semantic retriever.

This module is loaded only through the ``vulnwitness.adapters`` entry-point group.
Its heavy dependencies stay outside the core import graph.
"""

from pathlib import Path

import chromadb  # type: ignore[import-not-found]
from chromadb.config import Settings  # type: ignore[import-not-found]
from sentence_transformers import SentenceTransformer  # type: ignore[import-not-found]

from vulnwitness.adapters.semantic.vector_retriever import VectorSemanticRetriever


class SentenceTransformerEncoder:
    """Implements ``TextEncoder`` with unit-length embeddings, from a model already on
    disk: ``local_files_only`` keeps the model hub out of every load, so loading neither
    reaches the network nor writes the model cache."""

    def __init__(self, model_name: str) -> None:
        self._model = SentenceTransformer(model_name, local_files_only=True)

    def encode_query(self, query_text: str) -> list[float]:
        embeddings = self._model.encode([query_text], normalize_embeddings=True)
        query_embedding: list[float] = embeddings[0].tolist()
        return query_embedding


# The file a Chroma persist directory holds; opening a directory without it would create it.
CHROMA_DATABASE_FILE = "chroma.sqlite3"


def build_semantic_retriever(
    *, collection_name: str, persist_directory: str, model_name: str
) -> VectorSemanticRetriever:
    """The retriever over an existing collection. Raises ``FileNotFoundError``, naming no
    path, for a directory that holds no Chroma database, before Chroma could create one,
    so a mistyped setting never writes to disk. Chroma has no read-only client: opening an
    existing database may still write to it (its SQLite journal, migrations), so only the
    commands an operator runs with ``--semantic`` load this adapter (ADR 0004 §1)."""
    if not (Path(persist_directory) / CHROMA_DATABASE_FILE).is_file():
        raise FileNotFoundError("the persist directory holds no Chroma database")
    client = chromadb.PersistentClient(
        path=persist_directory, settings=Settings(anonymized_telemetry=False)
    )
    return VectorSemanticRetriever(
        client.get_collection(collection_name), SentenceTransformerEncoder(model_name)
    )
