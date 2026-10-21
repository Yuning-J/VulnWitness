"""Semantic retrieval over an injected vector collection: filters, gaps and failures."""

import logging

import pytest

from cve_kgrag.adapters.semantic.vector_retriever import VectorSemanticRetriever
from cve_kgrag.domain.taxonomy import BackendFailure, BackendStatus
from tests.support.collect import list_cve_ids
from tests.support.vector_store import FakeCollection, FixedEncoder

# A store's own error text names its database; no log line may carry it.
STORE_PATH = "/home/operator/private/chroma.sqlite3"


def test_filters_reach_the_store_as_a_cve_id_constraint() -> None:
    collection = FakeCollection(metadatas=[{"cve_id": "CVE-9999-0002"}], distances=[0.2])

    outcome = VectorSemanticRetriever(collection, FixedEncoder()).search(
        "query", 5, frozenset({"CVE-9999-0002", "CVE-9999-0001"})
    )

    assert outcome.status is BackendStatus.OK
    assert list_cve_ids(outcome.matches) == ["CVE-9999-0002"]
    assert collection.where_clauses == [{"cve_id": {"$in": ["CVE-9999-0001", "CVE-9999-0002"]}}]


def test_empty_answer_is_an_index_gap_with_or_without_filters() -> None:
    retriever = VectorSemanticRetriever(FakeCollection(), FixedEncoder())

    unfiltered = retriever.search("query", 5, None)
    filtered = retriever.search("query", 5, frozenset({"CVE-9999-0001"}))

    assert unfiltered.status is BackendStatus.INCOMPLETE_INDEX
    assert filtered.status is BackendStatus.INCOMPLETE_INDEX


def test_empty_allowed_set_answers_without_querying_the_store() -> None:
    collection = FakeCollection()

    outcome = VectorSemanticRetriever(collection, FixedEncoder()).search("query", 5, frozenset())

    assert outcome.status is BackendStatus.OK
    assert outcome.matches == ()
    assert collection.where_clauses == []


def test_store_failure_is_a_typed_error_logged_by_type_without_its_message(
    caplog: pytest.LogCaptureFixture,
) -> None:
    collection = FakeCollection(query_error=OSError(f"{STORE_PATH} is locked"))

    with caplog.at_level(logging.DEBUG):
        outcome = VectorSemanticRetriever(collection, FixedEncoder()).search("query", 5, None)

    formatter = logging.Formatter("%(levelname)s %(message)s")
    logged_lines: list[str] = []
    for log_record in caplog.records:
        logged_lines.append(formatter.format(log_record))
    assert outcome.status is BackendStatus.ERROR
    assert outcome.failure is BackendFailure.SEARCH_FAILED
    assert logged_lines == ["WARNING semantic search raised OSError"]
