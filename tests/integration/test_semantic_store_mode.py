"""Proves the semantic channel's state by served dataset (ADR 0004 §1, ADR 0009 §14): with
a corpus store served, a requested channel is unavailable as ``COLLECTION_NOT_BOUND`` and
no adapter is looked up, so a collection whose CVE IDs overlap the store never supplies a
hit; a run that does not request it reports ``not_configured``, as with the fixture."""

from typing import Any

import pytest

from tests.support.collect import find_capability
from tests.support.corpus_stores import COMPATIBILITY_STORE
from tests.support.entry_points import FakeAdapterRegistry, FakeEntryPoint
from tests.support.vector_store import FakeCollection, FixedEncoder
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.adapters.semantic.vector_retriever import VectorSemanticRetriever
from vulnwitness.adapters.store.corpus_store import CorpusStore, load_corpus_store
from vulnwitness.composition import (
    build_investigation_service,
    build_search_service,
    build_serving_data_plane,
    describe_semantic_capability,
)
from vulnwitness.domain.investigation import (
    InvestigationRequest,
    SourceCapability,
    SourceCapabilityState,
)
from vulnwitness.domain.search import SearchRequest, SemanticUnavailableDetail
from vulnwitness.domain.taxonomy import BackendFailureDetail, BackendStatus, RetrievalChannel
from vulnwitness.ports.served_corpus import ServedCorpus
from vulnwitness.settings import SemanticSettings

# A record both the fixture and the compatibility store hold.
OVERLAPPING_CVE_ID = "CVE-9999-0004"
# A query no lexical channel answers, so any candidate is the semantic channel's.
SEMANTIC_ONLY_QUERY = "zzqx"
SEMANTIC_SETTINGS = SemanticSettings(persist_directory="unused-vectors")


def build_overlapping_retriever(**settings: Any) -> VectorSemanticRetriever:
    """A working semantic adapter whose collection answers with a record the store holds."""
    collection = FakeCollection(metadatas=[{"cve_id": OVERLAPPING_CVE_ID}], distances=[0.1])
    return VectorSemanticRetriever(collection, FixedEncoder())


def load_overlapping_factory() -> object:
    return build_overlapping_retriever


@pytest.fixture
def corpus_store() -> CorpusStore:
    return load_corpus_store(COMPATIBILITY_STORE)


@pytest.fixture
def overlapping_registry() -> FakeAdapterRegistry:
    return FakeAdapterRegistry([FakeEntryPoint("semantic", load_overlapping_factory)])


def describe_capability(
    served_corpus: ServedCorpus,
    semantic_settings: SemanticSettings | None,
    registry: FakeAdapterRegistry,
) -> SourceCapability:
    search_service = build_search_service(served_corpus, semantic_settings, registry.list_adapters)
    return describe_semantic_capability(search_service)


def test_fixture_with_the_channel_requested_uses_the_overlapping_adapter(
    fixture_bundle: FixtureBundle, overlapping_registry: FakeAdapterRegistry
) -> None:
    search_service = build_search_service(
        fixture_bundle, SEMANTIC_SETTINGS, overlapping_registry.list_adapters
    )

    response = search_service.search(SearchRequest(query=SEMANTIC_ONLY_QUERY, semantic=True))

    found_ids: list[str] = []
    for candidate in response.candidates:
        found_ids.append(candidate.record.cve_id)
    assert found_ids == [OVERLAPPING_CVE_ID]


def test_store_with_the_channel_requested_never_looks_up_the_adapter_or_uses_its_hits(
    corpus_store: CorpusStore, overlapping_registry: FakeAdapterRegistry
) -> None:
    search_service = build_search_service(
        corpus_store, SEMANTIC_SETTINGS, overlapping_registry.list_adapters
    )

    response = search_service.search(SearchRequest(query=SEMANTIC_ONLY_QUERY, semantic=True))

    semantic_outcome = response.channel_outcomes[-1]
    assert overlapping_registry.is_listed is False
    assert response.candidates == ()
    assert (semantic_outcome.channel, semantic_outcome.status, semantic_outcome.detail) == (
        RetrievalChannel.SEMANTIC,
        BackendStatus.UNAVAILABLE,
        BackendFailureDetail.COLLECTION_NOT_BOUND,
    )


@pytest.mark.parametrize(
    ("served", "is_requested", "registry_entries", "expected_capability"),
    [
        (
            "fixture",
            False,
            "overlapping",
            SourceCapability(source="semantic_channel", state=SourceCapabilityState.NOT_CONFIGURED),
        ),
        (
            "fixture",
            True,
            "overlapping",
            SourceCapability(source="semantic_channel", state=SourceCapabilityState.AVAILABLE),
        ),
        (
            "fixture",
            True,
            "none",
            SourceCapability(
                source="semantic_channel",
                state=SourceCapabilityState.UNAVAILABLE,
                detail=SemanticUnavailableDetail.ADAPTER_UNUSABLE,
            ),
        ),
        (
            "store",
            False,
            "overlapping",
            SourceCapability(source="semantic_channel", state=SourceCapabilityState.NOT_CONFIGURED),
        ),
        (
            "store",
            True,
            "overlapping",
            SourceCapability(
                source="semantic_channel",
                state=SourceCapabilityState.UNAVAILABLE,
                detail=SemanticUnavailableDetail.COLLECTION_NOT_BOUND,
            ),
        ),
        (
            "store",
            True,
            "none",
            SourceCapability(
                source="semantic_channel",
                state=SourceCapabilityState.UNAVAILABLE,
                detail=SemanticUnavailableDetail.COLLECTION_NOT_BOUND,
            ),
        ),
    ],
    ids=[
        "fixture_not_requested",
        "fixture_requested",
        "fixture_requested_without_an_adapter",
        "store_not_requested",
        "store_requested",
        "store_requested_without_an_adapter",
    ],
)
def test_semantic_capability_follows_the_served_dataset_and_the_request(
    fixture_bundle: FixtureBundle,
    corpus_store: CorpusStore,
    served: str,
    is_requested: bool,
    registry_entries: str,
    expected_capability: SourceCapability,
) -> None:
    served_corpus: ServedCorpus = fixture_bundle if served == "fixture" else corpus_store
    registry = FakeAdapterRegistry()
    if registry_entries == "overlapping":
        registry = FakeAdapterRegistry([FakeEntryPoint("semantic", load_overlapping_factory)])
    semantic_settings = SEMANTIC_SETTINGS if is_requested else None

    capability = describe_capability(served_corpus, semantic_settings, registry)

    assert capability == expected_capability


def test_store_investigation_requesting_the_channel_seals_a_set_naming_why_it_is_unbound(
    corpus_store: CorpusStore, overlapping_registry: FakeAdapterRegistry
) -> None:
    investigation_service = build_investigation_service(
        build_serving_data_plane(
            corpus_store,
            search_service=build_search_service(
                corpus_store, SEMANTIC_SETTINGS, overlapping_registry.list_adapters
            ),
        )
    )

    evidence_set = investigation_service.investigate(
        InvestigationRequest(query="democorp gateway", scope="implementation_only", semantic=True)
    )

    semantic_details: set[BackendFailureDetail] = set()
    for source_outcome in evidence_set.coverage.source_outcomes:
        for channel_failure in source_outcome.channel_failures:
            if channel_failure.channel is RetrievalChannel.SEMANTIC:
                semantic_details.add(channel_failure.detail)
    semantic_capability = find_capability(evidence_set.source_capabilities, "semantic_channel")
    assert semantic_capability.detail is SemanticUnavailableDetail.COLLECTION_NOT_BOUND
    assert semantic_details == {BackendFailureDetail.COLLECTION_NOT_BOUND}
    assert overlapping_registry.is_listed is False
