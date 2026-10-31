"""Search service over the synthetic fixture: every channel, filters and failures end to end."""

from collections.abc import Callable, Sequence, Set
from dataclasses import dataclass, field
from typing import Any

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.adapters.lexical.bm25_index import Bm25LexicalIndex
from cve_kgrag.adapters.memory.in_memory_repository import InMemoryKnowledgeRepository
from cve_kgrag.adapters.semantic.vector_retriever import VectorSemanticRetriever
from cve_kgrag.adapters.store.corpus_store import load_corpus_store
from cve_kgrag.application.search import SearchService
from cve_kgrag.composition import build_search_service
from cve_kgrag.domain.cve import CveRecord
from cve_kgrag.domain.evidence import EvidenceAnchor
from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.search import (
    ChannelHit,
    GraphPath,
    RetrievalMatch,
    RetrievalOutcome,
    SearchFilters,
    SearchRequest,
    SearchResponse,
    SearchWarning,
    SearchWarningCode,
    UnsupportedFilter,
)
from cve_kgrag.domain.taxonomy import (
    BackendFailureDetail,
    BackendStatus,
    KnowledgeScope,
    ResultStatus,
    RetrievalChannel,
)
from cve_kgrag.domain.validation import EvidenceValidationError, validate_search_response
from tests.support.collect import list_candidate_cve_ids, list_codes
from tests.support.corpus_stores import COMPATIBILITY_STORE
from tests.support.fakes import (
    CannedRetriever,
    RecordedChannels,
    build_failure,
    build_lexical_match,
    build_recorded_channels,
)
from tests.support.investigation import DISGUISED_LOW_SIGNAL_WORDS
from tests.support.services import build_fixture_service
from tests.support.vector_store import FakeCollection, FixedEncoder


@dataclass
class CannedStructuredIndex:
    outcome: RetrievalOutcome

    def search(self, filters: SearchFilters) -> RetrievalOutcome:
        return self.outcome

    def holds_package_urls(self) -> bool:
        return True


def test_exact_id_ranks_first_even_when_lexical_terms_favor_another_record(
    search_service: SearchService,
) -> None:
    response = search_service.search(SearchRequest(query="CVE-9999-0002 sql injection login"))

    assert response.status is ResultStatus.OK
    assert list_candidate_cve_ids(response.candidates)[:2] == ["CVE-9999-0002", "CVE-9999-0001"]
    assert response.channels_executed == (RetrievalChannel.EXACT_ID, RetrievalChannel.LEXICAL)


def test_query_of_only_a_cve_id_runs_exact_channel_alone(search_service: SearchService) -> None:
    response = search_service.search(SearchRequest(query="cve-9999-0003"))

    assert response.channels_executed == (RetrievalChannel.EXACT_ID,)
    assert list_candidate_cve_ids(response.candidates) == ["CVE-9999-0003"]


def test_unknown_cve_id_returns_no_match_with_warning_and_no_fabricated_record(
    search_service: SearchService,
) -> None:
    response = search_service.search(SearchRequest(query="CVE-9999-4242"))

    assert response.status is ResultStatus.NO_MATCH
    assert response.candidates == ()
    assert response.evidence == ()
    assert response.warnings[0].code is SearchWarningCode.UNKNOWN_CVE_ID
    assert response.warnings[0].subject == "CVE-9999-4242"


def test_unknown_terms_return_no_match_and_no_evidence(search_service: SearchService) -> None:
    response = search_service.search(SearchRequest(query="zzqx bluetooth pairing"))

    assert response.status is ResultStatus.NO_MATCH
    assert response.candidates == ()
    assert response.evidence == ()


def test_search_term_no_record_holds_is_named_in_a_warning(search_service: SearchService) -> None:
    response = search_service.search(SearchRequest(query="ausf zzqx"))

    assert response.status is ResultStatus.OK
    assert response.warnings == (
        SearchWarning(code=SearchWarningCode.TERM_NOT_INDEXED, subject="zzqx"),
    )


def test_stopword_only_query_warns_no_searchable_terms(search_service: SearchService) -> None:
    response = search_service.search(SearchRequest(query="the of and"))

    assert response.status is ResultStatus.NO_MATCH
    assert response.channels_executed == ()
    assert response.warnings[0].code is SearchWarningCode.NO_SEARCHABLE_TERMS


@pytest.mark.parametrize(
    "query",
    [
        "CVE.9999.0003",
        "CVE/9999/0003",
        "CVE 9999 0003",
        "CVE-\u0669\u0669\u0669\u0669-\u0660\u0660\u0660\u0663",
        "CVE ID 9999-0003",
        "CVE-9999-003",
        "\u1d04\u1d20\u1d07-9999-0003",
    ],
    ids=[
        "full_stops",
        "slashes",
        "spaces",
        "arabic_indic_digits",
        "id_word",
        "short_number",
        "latin_small_capitals",
    ],
)
def test_text_read_as_an_id_but_not_written_as_one_is_neither_looked_up_nor_searched(
    search_service: SearchService, query: str
) -> None:
    response = search_service.search(SearchRequest(query=query))

    assert response.status is ResultStatus.NO_MATCH
    assert response.candidates == ()
    assert response.channels_executed == ()
    assert response.warnings[0].code is SearchWarningCode.NO_SEARCHABLE_TERMS


def test_lexical_candidates_expose_channel_scores_and_match_reasons(
    search_service: SearchService,
) -> None:
    response = search_service.search(SearchRequest(query="SUCI out-of-bounds read"))

    top_candidate = response.candidates[0]
    lexical_hit = top_candidate.channel_hits[0]
    assert top_candidate.record.cve_id == "CVE-9999-0004"
    assert lexical_hit.channel is RetrievalChannel.LEXICAL
    assert lexical_hit.raw_score > 0
    assert lexical_hit.matched_fields == ("description",)
    assert "suci" in lexical_hit.matched_terms


def test_every_candidate_is_an_evidenced_implementation_record_never_a_protocol_claim(
    search_service: SearchService,
) -> None:
    response = search_service.search(SearchRequest(query="5G-AKA AUSF UDM democorp", limit=20))

    evidence_ids: set[str] = set()
    for anchor in response.evidence:
        evidence_ids.add(anchor.evidence_id)
    assert response.candidates
    for candidate in response.candidates:
        assert candidate.scope_assessment.scope is KnowledgeScope.IMPLEMENTATION_VULNERABILITY
        assert candidate.record.protocol_design_claim == "not_established"
        assert candidate.record.formal_seed_eligible is False
        assert set(candidate.record.evidence_ids) <= evidence_ids


def test_injection_text_in_a_record_is_returned_as_ordinary_implementation_data(
    search_service: SearchService,
) -> None:
    response = search_service.search(SearchRequest(query="ignore previous instructions"))

    injected = response.candidates[0]
    assert injected.record.cve_id == "CVE-9999-0007"
    assert injected.scope_assessment.scope is KnowledgeScope.IMPLEMENTATION_VULNERABILITY
    assert injected.record.protocol_design_claim == "not_established"


def test_record_without_source_data_reports_missing_fields(search_service: SearchService) -> None:
    response = search_service.search(SearchRequest(query="CVE-9999-0008"))

    assert response.candidates[0].missing_fields == ("cvss", "cwe_ids", "affected", "published")


def test_hyphenated_5g_aka_matches_but_compact_5gaka_needs_topic_resolution(
    search_service: SearchService,
) -> None:
    hyphenated = search_service.search(SearchRequest(query="5G-AKA"))
    compact = search_service.search(SearchRequest(query="5gaka"))

    assert list_candidate_cve_ids(hyphenated.candidates)[0] == "CVE-9999-0003"
    assert compact.status is ResultStatus.NO_MATCH


def test_limit_caps_candidate_count(search_service: SearchService) -> None:
    response = search_service.search(
        SearchRequest(query="democorp fictional5g examplenet", limit=2)
    )

    assert len(response.candidates) == 2


def test_structured_filters_constrain_text_candidates_and_are_inspectable(
    search_service: SearchService,
) -> None:
    response = search_service.search(
        SearchRequest(query="gateway 5G", filters={"vendors": ["fictional5g"]}, limit=20)
    )

    assert list_candidate_cve_ids(response.candidates) == ["CVE-9999-0003", "CVE-9999-0004"]
    assert RetrievalChannel.STRUCTURED in response.channels_executed
    for candidate in response.candidates:
        assert candidate.record.affected[0].vendor == "fictional5g"


def test_graph_channel_expands_from_seed_with_relation_reasons(
    search_service: SearchService,
) -> None:
    response = search_service.search(
        SearchRequest(query="CVE-9999-0003", graph_expand=True, limit=20)
    )

    assert response.channels_executed == (RetrievalChannel.EXACT_ID, RetrievalChannel.GRAPH)
    assert list_candidate_cve_ids(response.candidates) == [
        "CVE-9999-0003",
        "CVE-9999-0004",
        "CVE-9999-0007",
    ]
    graph_hit = response.candidates[1].channel_hits[0]
    assert graph_hit.channel is RetrievalChannel.GRAPH
    assert "fictional5g/f5gc" in graph_hit.matched_terms


def test_requested_unconfigured_semantic_backend_makes_success_partial(
    search_service: SearchService,
) -> None:
    response = search_service.search(SearchRequest(query="gateway", semantic=True))

    assert response.status is ResultStatus.PARTIAL
    semantic = response.channel_outcomes[-1]
    assert semantic.channel is RetrievalChannel.SEMANTIC
    assert semantic.status is BackendStatus.UNAVAILABLE
    assert response.warnings[-1].code is SearchWarningCode.BACKEND_UNAVAILABLE


@pytest.mark.parametrize(
    ("backend_status", "expected_status"),
    [
        (BackendStatus.UNAVAILABLE, ResultStatus.SOURCE_UNAVAILABLE),
        (BackendStatus.INCOMPLETE_INDEX, ResultStatus.INCOMPLETE_INDEX),
        (BackendStatus.ERROR, ResultStatus.BACKEND_ERROR),
    ],
    ids=["unavailable", "incomplete_index", "error"],
)
def test_sole_failed_backend_reports_its_own_status_not_no_match(
    fixture_bundle: FixtureBundle, backend_status: BackendStatus, expected_status: ResultStatus
) -> None:
    service = build_fixture_service(
        fixture_bundle, lexical_retriever=CannedRetriever(build_failure(backend_status))
    )

    response = service.search(SearchRequest(query="anything"))

    assert response.status is expected_status
    assert response.candidates == ()


def test_failed_backend_beside_a_successful_one_makes_the_response_partial(
    fixture_bundle: FixtureBundle,
) -> None:
    service = build_fixture_service(
        fixture_bundle, lexical_retriever=CannedRetriever(build_failure(BackendStatus.ERROR))
    )

    response = service.search(SearchRequest(query="CVE-9999-0001 gateway"))

    assert response.status is ResultStatus.PARTIAL
    assert list_candidate_cve_ids(response.candidates) == ["CVE-9999-0001"]


@pytest.mark.parametrize(
    "request_fields",
    [
        {"query": "CVE-9999-0001 gateway 5G-AKA", "limit": 20},
        {
            "query": "CVE-9999-0003 democorp gateway",
            "filters": {"vendors": ["democorp", "fictional5g"], "severities": ["HIGH", "CRITICAL"]},
            "graph_expand": True,
            "semantic": True,
            "limit": 20,
        },
    ],
    ids=["exact_and_lexical", "every_channel"],
)
def test_identical_requests_over_independently_built_services_hash_identically(
    fixture_bundle: FixtureBundle, request_fields: dict[str, object]
) -> None:
    request = SearchRequest.model_validate(request_fields)

    first = build_search_service(fixture_bundle).search(request)
    second = build_search_service(fixture_bundle).search(request)

    assert first.result_sha256 == second.result_sha256
    assert first.model_dump_json() == second.model_dump_json()


def test_retriever_returning_unknown_record_is_rejected_not_returned(
    fixture_bundle: FixtureBundle,
) -> None:
    inventing_retriever = CannedRetriever(
        RetrievalOutcome(status=BackendStatus.OK, matches=(build_lexical_match("CVE-9999-7777"),))
    )
    service = build_fixture_service(fixture_bundle, lexical_retriever=inventing_retriever)

    with pytest.raises(EvidenceValidationError, match="CVE-9999-7777"):
        service.search(SearchRequest(query="anything"))


def test_repository_rejects_record_citing_missing_evidence(fixture_bundle: FixtureBundle) -> None:
    with pytest.raises(EvidenceValidationError, match="cites unknown evidence"):
        InMemoryKnowledgeRepository(fixture_bundle.records, fixture_bundle.evidence[1:])


def test_lexical_index_over_fixture_needs_no_external_service(
    fixture_bundle: FixtureBundle,
) -> None:
    index = Bm25LexicalIndex(fixture_bundle.records)

    assert index.search("gateway", limit=5, allowed_cve_ids=None).matches


def test_unknown_exact_id_with_filters_returns_no_unrelated_filter_matches(
    search_service: SearchService,
) -> None:
    response = search_service.search(
        SearchRequest(query="CVE-9999-4242", filters={"vendors": ["fictional5g"]})
    )

    assert response.status is ResultStatus.NO_MATCH
    assert response.candidates == ()
    assert response.warnings[0].code is SearchWarningCode.UNKNOWN_CVE_ID


@pytest.mark.parametrize(
    ("backend_status", "expected_status"),
    [
        (BackendStatus.UNAVAILABLE, ResultStatus.SOURCE_UNAVAILABLE),
        (BackendStatus.INCOMPLETE_INDEX, ResultStatus.INCOMPLETE_INDEX),
        (BackendStatus.ERROR, ResultStatus.BACKEND_ERROR),
    ],
    ids=["unavailable", "incomplete_index", "error"],
)
def test_failed_filter_backend_returns_no_unfiltered_candidates(
    fixture_bundle: FixtureBundle, backend_status: BackendStatus, expected_status: ResultStatus
) -> None:
    service = build_fixture_service(
        fixture_bundle, structured_retriever=CannedStructuredIndex(build_failure(backend_status))
    )

    response = service.search(
        SearchRequest(query="CVE-9999-0001 democorp gateway", filters={"vendors": ["nobody"]})
    )

    assert response.status is expected_status
    assert response.candidates == ()
    assert response.channels_executed == (RetrievalChannel.STRUCTURED,)


def test_filters_keep_the_text_ranking_of_the_records_they_admit(
    search_service: SearchService,
) -> None:
    query = "dashboard democorp"
    unfiltered_search = search_service.search(SearchRequest(query=query, limit=20))
    filtered_search = search_service.search(
        SearchRequest(query=query, filters={"cwe_ids": ["CWE-89", "CWE-79"]}, limit=20)
    )

    assert list_candidate_cve_ids(unfiltered_search.candidates)[:2] == [
        "CVE-9999-0002",
        "CVE-9999-0001",
    ]
    assert list_candidate_cve_ids(filtered_search.candidates) == ["CVE-9999-0002", "CVE-9999-0001"]


def test_filters_apply_before_the_limit(search_service: SearchService) -> None:
    query = "democorp demo_gateway examplenet"
    unfiltered_search = search_service.search(SearchRequest(query=query, limit=1))
    filtered_search = search_service.search(
        SearchRequest(query=query, filters={"vendors": ["examplenet"]}, limit=1)
    )

    assert list_candidate_cve_ids(unfiltered_search.candidates) != ["CVE-9999-0005"]
    assert list_candidate_cve_ids(filtered_search.candidates) == ["CVE-9999-0005"]


def test_requested_id_excluded_by_filters_is_reported_not_returned(
    search_service: SearchService,
) -> None:
    response = search_service.search(
        SearchRequest(query="CVE-9999-0001", filters={"vendors": ["examplenet"]})
    )

    assert response.status is ResultStatus.NO_MATCH
    assert response.warnings[0].code is SearchWarningCode.EXCLUDED_BY_FILTERS
    assert response.warnings[0].subject == "CVE-9999-0001"


def test_graph_expansion_contributes_under_filters_and_records_its_path(
    search_service: SearchService,
) -> None:
    response = search_service.search(
        SearchRequest(
            query="CVE-9999-0003",
            graph_expand=True,
            filters={"vendors": ["fictional5g"]},
            limit=20,
        )
    )

    graph_hit = response.candidates[1].channel_hits[0]
    assert list_candidate_cve_ids(response.candidates) == ["CVE-9999-0003", "CVE-9999-0004"]
    assert graph_hit.channel is RetrievalChannel.GRAPH
    assert (
        GraphPath(seed_cve_id="CVE-9999-0003", relation="product", value="fictional5g/f5gc")
        in graph_hit.graph_paths
    )


def test_graph_neighbours_never_displace_direct_matches(search_service: SearchService) -> None:
    roomy_search = search_service.search(SearchRequest(query="gateway", graph_expand=True, limit=3))
    tight_search = search_service.search(SearchRequest(query="gateway", graph_expand=True, limit=2))

    assert list_candidate_cve_ids(roomy_search.candidates) == [
        "CVE-9999-0001",
        "CVE-9999-0002",
        "CVE-9999-0007",
    ]
    assert list_candidate_cve_ids(tight_search.candidates) == ["CVE-9999-0001", "CVE-9999-0002"]


def test_retriever_ignoring_the_filter_constraint_is_rejected(
    fixture_bundle: FixtureBundle,
) -> None:
    unconstrained_retriever = CannedRetriever(
        RetrievalOutcome(status=BackendStatus.OK, matches=(build_lexical_match("CVE-9999-0001"),))
    )
    service = build_fixture_service(fixture_bundle, lexical_retriever=unconstrained_retriever)

    with pytest.raises(EvidenceValidationError, match="the active filters exclude"):
        service.search(SearchRequest(query="gateway", filters={"vendors": ["examplenet"]}))


def test_semantic_channel_contributes_records_by_their_chunks(
    fixture_bundle: FixtureBundle,
) -> None:
    """Two chunks of one record count as one semantic candidate."""
    collection = FakeCollection(
        metadatas=[{"cve_id": "CVE-9999-0004"}, {"cve_id": "CVE-9999-0004"}],
        distances=[0.1, 0.2],
    )
    service = build_fixture_service(
        fixture_bundle, semantic_retriever=VectorSemanticRetriever(collection, FixedEncoder())
    )

    response = service.search(SearchRequest(query="zzqx", semantic=True))

    assert response.status is ResultStatus.OK
    assert list_candidate_cve_ids(response.candidates) == ["CVE-9999-0004"]
    assert response.candidates[0].channel_hits[0].channel is RetrievalChannel.SEMANTIC


def test_backend_failure_detail_is_machine_independent(fixture_bundle: FixtureBundle) -> None:
    request = SearchRequest(query="gateway", semantic=True)
    first_collection = FakeCollection(query_error=OSError("/home/alice/vector_db: locked"))
    second_collection = FakeCollection(query_error=OSError("/srv/bob/vector_db: locked"))

    first = build_fixture_service(
        fixture_bundle,
        semantic_retriever=VectorSemanticRetriever(first_collection, FixedEncoder()),
    ).search(request)
    second = build_fixture_service(
        fixture_bundle,
        semantic_retriever=VectorSemanticRetriever(second_collection, FixedEncoder()),
    ).search(request)

    assert first.status is ResultStatus.PARTIAL
    assert first.channel_outcomes[-1].detail is BackendFailureDetail.SEARCH_FAILED
    assert first.result_sha256 == second.result_sha256


def test_filters_matching_no_record_return_no_match_without_text_candidates(
    search_service: SearchService,
) -> None:
    response = search_service.search(
        SearchRequest(query="CVE-9999-0001 gateway", filters={"vendors": ["nobody"]})
    )

    assert response.status is ResultStatus.NO_MATCH
    assert response.candidates == ()
    assert response.warnings[0].code is SearchWarningCode.EXCLUDED_BY_FILTERS


def test_filtered_search_whose_only_text_channel_fails_reports_the_failure(
    fixture_bundle: FixtureBundle,
) -> None:
    service = build_fixture_service(
        fixture_bundle, lexical_retriever=CannedRetriever(build_failure(BackendStatus.ERROR))
    )

    response = service.search(SearchRequest(query="gateway", filters={"vendors": ["democorp"]}))

    assert response.status is ResultStatus.BACKEND_ERROR
    assert response.candidates == ()


@dataclass
class RecordingSemanticRetriever:
    """Returns one canned outcome and records the filter set each call received."""

    outcome: RetrievalOutcome
    allowed_id_sets: list[Set[str] | None] = field(default_factory=list)

    def search(
        self, query_text: str, limit: int, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        self.allowed_id_sets.append(allowed_cve_ids)
        return self.outcome


def test_semantic_channel_receives_the_filter_set(fixture_bundle: FixtureBundle) -> None:
    semantic_retriever = RecordingSemanticRetriever(
        RetrievalOutcome(status=BackendStatus.OK, matches=(build_lexical_match("CVE-9999-0005"),))
    )
    service = build_fixture_service(fixture_bundle, semantic_retriever=semantic_retriever)

    response = service.search(
        SearchRequest(query="router", semantic=True, filters={"kev_only": True})
    )

    assert semantic_retriever.allowed_id_sets == [frozenset({"CVE-9999-0005"})]
    assert list_candidate_cve_ids(response.candidates) == ["CVE-9999-0005"]


@dataclass
class CannedGraph:
    outcome: RetrievalOutcome

    def expand(
        self, seed_cve_ids: Sequence[str], limit: int, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        return self.outcome


@pytest.mark.parametrize("channel", ["semantic", "graph"])
def test_semantic_or_graph_match_outside_the_filters_is_rejected(
    fixture_bundle: FixtureBundle, channel: str
) -> None:
    excluded_outcome = RetrievalOutcome(
        status=BackendStatus.OK, matches=(build_lexical_match("CVE-9999-0001"),)
    )
    retrievers: dict[str, object] = {
        "semantic": {"semantic_retriever": RecordingSemanticRetriever(excluded_outcome)},
        "graph": {"graph_retriever": CannedGraph(excluded_outcome)},
    }[channel]
    service = build_fixture_service(fixture_bundle, **retrievers)

    with pytest.raises(EvidenceValidationError, match="the active filters exclude"):
        service.search(
            SearchRequest(
                query="router",
                semantic=True,
                graph_expand=True,
                filters={"vendors": ["examplenet"]},
            )
        )


def test_unstored_record_is_rejected_even_when_ranked_past_the_limit(
    fixture_bundle: FixtureBundle,
) -> None:
    inventing_retriever = CannedRetriever(
        RetrievalOutcome(
            status=BackendStatus.OK,
            matches=(
                build_lexical_match("CVE-9999-0001"),
                build_lexical_match("CVE-9999-0002"),
                build_lexical_match("CVE-9999-7777"),
            ),
        )
    )
    service = build_fixture_service(fixture_bundle, lexical_retriever=inventing_retriever)

    with pytest.raises(EvidenceValidationError, match="CVE-9999-7777"):
        service.search(SearchRequest(query="anything", limit=1))


def test_repository_rejects_a_cve_anchor_scoped_as_protocol_context(
    fixture_bundle: FixtureBundle,
) -> None:
    relabeled_anchor = fixture_bundle.evidence[0].model_copy(
        update={"scope": KnowledgeScope.PROTOCOL_THREAT_CONTEXT}
    )

    with pytest.raises(EvidenceValidationError, match="CVE evidence must be"):
        InMemoryKnowledgeRepository(
            fixture_bundle.records, (relabeled_anchor, *fixture_bundle.evidence[1:])
        )


def test_semantic_hit_with_over_long_cve_id_is_a_typed_channel_error(
    fixture_bundle: FixtureBundle,
) -> None:
    collection = FakeCollection(metadatas=[{"cve_id": "CVE-2024-" + "1" * 40}], distances=[0.1])
    service = build_fixture_service(
        fixture_bundle, semantic_retriever=VectorSemanticRetriever(collection, FixedEncoder())
    )

    response = service.search(SearchRequest(query="gateway", semantic=True))

    assert response.status is ResultStatus.PARTIAL
    assert response.channel_outcomes[-1].status is BackendStatus.ERROR


def test_whitespace_only_query_is_answered_no_match_with_a_warning(
    search_service: SearchService,
) -> None:
    response = search_service.search(SearchRequest(query="   "))

    assert response.status is ResultStatus.NO_MATCH
    assert response.warnings[0].code is SearchWarningCode.NO_SEARCHABLE_TERMS


@pytest.mark.parametrize(
    "query", ["   ", "the of", "CVE-9999-0003"], ids=["blank", "stopwords", "id_only"]
)
def test_semantic_channel_is_not_called_without_searchable_terms(
    fixture_bundle: FixtureBundle, query: str
) -> None:
    semantic_retriever = RecordingSemanticRetriever(
        RetrievalOutcome(status=BackendStatus.OK, matches=(build_lexical_match("CVE-9999-0001"),))
    )
    service = build_fixture_service(fixture_bundle, semantic_retriever=semantic_retriever)

    response = service.search(SearchRequest(query=query, semantic=True))

    assert semantic_retriever.allowed_id_sets == []
    assert "CVE-9999-0001" not in list_candidate_cve_ids(response.candidates)
    assert RetrievalChannel.SEMANTIC not in response.channels_executed


def test_blank_query_with_semantic_requested_is_no_match(fixture_bundle: FixtureBundle) -> None:
    semantic_retriever = RecordingSemanticRetriever(
        RetrievalOutcome(status=BackendStatus.OK, matches=(build_lexical_match("CVE-9999-0001"),))
    )
    service = build_fixture_service(fixture_bundle, semantic_retriever=semantic_retriever)

    response = service.search(SearchRequest(query="   ", semantic=True))

    assert response.status is ResultStatus.NO_MATCH
    assert response.warnings[0].code is SearchWarningCode.NO_SEARCHABLE_TERMS


def build_service_over(
    fixture_bundle: FixtureBundle, recorded_channels: RecordedChannels
) -> SearchService:
    return build_fixture_service(
        fixture_bundle,
        lexical_retriever=recorded_channels.lexical,
        semantic_retriever=recorded_channels.semantic,
        graph_retriever=recorded_channels.graph,
    )


@pytest.mark.parametrize("query", ["cve", "CVEs", "CVE, cves"], ids=["word", "plural", "both"])
@pytest.mark.parametrize(
    "filters", [{}, {"vendors": ["fictional5g"]}], ids=["no_filters", "vendor_filter"]
)
def test_query_of_only_low_signal_words_calls_no_text_or_graph_channel(
    fixture_bundle: FixtureBundle, query: str, filters: dict[str, Any]
) -> None:
    recorded_channels = build_recorded_channels()
    service = build_service_over(fixture_bundle, recorded_channels)

    search_answer = service.search(
        SearchRequest(query=query, filters=filters, semantic=True, graph_expand=True)
    )

    assert recorded_channels.lexical.query_texts == []
    assert recorded_channels.semantic.query_texts == []
    assert recorded_channels.graph.seed_id_lists == []
    assert search_answer.status is ResultStatus.NO_MATCH
    assert search_answer.candidates == ()
    assert search_answer.warnings[-1].code is SearchWarningCode.NO_SEARCHABLE_TERMS


@pytest.mark.parametrize(
    "query",
    ["CVE of 2021-44228", "nvdcve in 2021 and 2022", "nvdcve cves 2021 44228"],
    ids=[
        "stopword_after_the_word_cve",
        "stopwords_after_a_word_ending_in_cve",
        "low_signal_word_after_a_word_ending_in_cve",
    ],
)
def test_query_whose_words_form_an_id_likeness_calls_no_text_channel(
    fixture_bundle: FixtureBundle, query: str
) -> None:
    recorded_channels = build_recorded_channels()
    service = build_service_over(fixture_bundle, recorded_channels)

    search_answer = service.search(SearchRequest(query=query, semantic=True))

    assert recorded_channels.lexical.query_texts == []
    assert recorded_channels.semantic.query_texts == []
    assert search_answer.status is ResultStatus.NO_MATCH
    assert search_answer.warnings[-1].code is SearchWarningCode.NO_SEARCHABLE_TERMS


@pytest.mark.parametrize(
    ("query", "expected_search_text"),
    [
        ("cve ausf crash", "ausf crash"),
        ("CVE 2022 log4j", "2022 log4j"),
        ("cves of ausf", "of ausf"),
        ("nvdcve ausf", "nvdcve ausf"),
    ],
    ids=["before_terms", "before_a_year", "plural_before_a_stopword", "word_containing_cve"],
)
def test_text_channels_receive_the_query_without_its_low_signal_words(
    fixture_bundle: FixtureBundle, query: str, expected_search_text: str
) -> None:
    recorded_channels = build_recorded_channels()
    service = build_service_over(fixture_bundle, recorded_channels)

    service.search(SearchRequest(query=query, semantic=True))

    assert recorded_channels.lexical.query_texts == [expected_search_text]
    assert recorded_channels.semantic.query_texts == [expected_search_text]


def test_low_signal_word_beside_an_id_leaves_the_exact_lookup_alone(
    search_service: SearchService,
) -> None:
    search_answer = search_service.search(SearchRequest(query="CVE-9999-0003 cve"))

    assert search_answer.channels_executed == (RetrievalChannel.EXACT_ID,)
    assert list_candidate_cve_ids(search_answer.candidates) == ["CVE-9999-0003"]


def test_low_signal_word_beside_an_id_expands_the_lookup_without_text_channels(
    fixture_bundle: FixtureBundle,
) -> None:
    recorded_channels = build_recorded_channels()
    service = build_service_over(fixture_bundle, recorded_channels)

    service.search(SearchRequest(query="CVE-9999-0003 cve", semantic=True, graph_expand=True))

    assert recorded_channels.lexical.query_texts == []
    assert recorded_channels.semantic.query_texts == []
    assert recorded_channels.graph.seed_id_lists == [("CVE-9999-0003",)]


@pytest.mark.parametrize("query", ["cve", "the of"], ids=["low_signal_word", "stopwords"])
@pytest.mark.parametrize(
    "filters", [{"kev_only": True}, {"vendors": ["fictional5g"]}], ids=["kev", "vendor"]
)
def test_filters_never_supply_candidates_to_a_query_without_search_terms(
    search_service: SearchService, query: str, filters: dict[str, Any]
) -> None:
    search_answer = search_service.search(
        SearchRequest(query=query, filters=filters, semantic=True, graph_expand=True)
    )

    assert search_answer.channels_executed == (RetrievalChannel.STRUCTURED,)
    assert search_answer.candidates == ()
    assert search_answer.status is ResultStatus.NO_MATCH


def reseal_search_response(response: SearchResponse, **changes: Any) -> SearchResponse:
    """``response`` with ``changes`` applied unvalidated and its hash recomputed, as a holder
    of the response could do."""
    changed_response = response.model_copy(update=changes)
    return changed_response.model_copy(
        update={"result_sha256": changed_response.compute_result_sha256()}
    )


def replace_first_record(
    response: SearchResponse, forged_record: CveRecord, **changes: Any
) -> SearchResponse:
    first_candidate = response.candidates[0].model_copy(update={"record": forged_record})
    return reseal_search_response(
        response, candidates=(first_candidate, *response.candidates[1:]), **changes
    )


def forge_the_description_and_weakness(
    response: SearchResponse, fixture_bundle: FixtureBundle
) -> SearchResponse:
    """The reviewer's forgery: the record says what its source never did, behind its genuine
    anchors."""
    record = response.candidates[0].record
    forged_description = record.descriptions[0].model_copy(
        update={"value": "FORGED: remote code execution in every AUSF"}
    )
    forged_record = record.model_copy(
        update={"descriptions": (forged_description,), "cwe_ids": ("CWE-787",)}
    )
    return replace_first_record(response, forged_record)


def cite_another_records_genuine_anchor(
    response: SearchResponse, fixture_bundle: FixtureBundle
) -> SearchResponse:
    """The reviewer's forgery: the record also cites another CVE's genuine anchor."""
    record = response.candidates[0].record
    other_anchor: EvidenceAnchor | None = None
    for anchor in fixture_bundle.evidence:
        if other_anchor is None and anchor.authoritative_record_id != record.cve_id:
            other_anchor = anchor
    assert other_anchor is not None
    forged_record = record.model_copy(
        update={"evidence_ids": (*record.evidence_ids, other_anchor.evidence_id)}
    )
    evidence = sorted({*response.evidence, other_anchor}, key=lambda anchor: anchor.evidence_id)
    return replace_first_record(response, forged_record, evidence=tuple(evidence))


SearchForgery = Callable[[SearchResponse, FixtureBundle], SearchResponse]


@pytest.mark.parametrize(
    "forgery",
    [forge_the_description_and_weakness, cite_another_records_genuine_anchor],
    ids=["forged_description_and_weakness", "record_citing_another_records_anchor"],
)
def test_resealed_response_serving_a_forged_record_is_rejected(
    search_service: SearchService,
    fixture_bundle: FixtureBundle,
    packaged_evidence_catalog: EvidenceCatalog,
    forgery: SearchForgery,
) -> None:
    response = search_service.search(SearchRequest(query="5G AKA"))
    validate_search_response(response, packaged_evidence_catalog)
    forged_response = forgery(response, fixture_bundle)

    with pytest.raises(EvidenceValidationError) as raised:
        validate_search_response(forged_response, packaged_evidence_catalog)

    assert raised.value.violations == (
        f"{response.candidates[0].record.cve_id}: differs from the record this service's "
        "sources hold",
    )


@pytest.mark.parametrize(
    "spelling", DISGUISED_LOW_SIGNAL_WORDS.values(), ids=DISGUISED_LOW_SIGNAL_WORDS.keys()
)
def test_disguised_low_signal_word_calls_no_text_or_graph_channel(
    fixture_bundle: FixtureBundle, spelling: str
) -> None:
    recorded_channels = build_recorded_channels()
    service = build_service_over(fixture_bundle, recorded_channels)

    search_answer = service.search(SearchRequest(query=spelling, semantic=True, graph_expand=True))

    assert recorded_channels.lexical.query_texts == []
    assert recorded_channels.semantic.query_texts == []
    assert recorded_channels.graph.seed_id_lists == []
    assert search_answer.status is ResultStatus.NO_MATCH
    assert search_answer.warnings[-1].code is SearchWarningCode.NO_SEARCHABLE_TERMS


@pytest.mark.parametrize(
    "spelling", DISGUISED_LOW_SIGNAL_WORDS.values(), ids=DISGUISED_LOW_SIGNAL_WORDS.keys()
)
def test_text_channels_receive_only_the_words_beside_a_disguised_low_signal_word(
    fixture_bundle: FixtureBundle, spelling: str
) -> None:
    recorded_channels = build_recorded_channels()
    service = build_service_over(fixture_bundle, recorded_channels)

    service.search(SearchRequest(query=f"{spelling} ausf", semantic=True))

    assert recorded_channels.lexical.query_texts == ["ausf"]
    assert recorded_channels.semantic.query_texts == ["ausf"]


# Adapter prose a lying retriever puts where the server expects its own explanation.
ADAPTER_PROSE = "CONFIRMED: demo_gateway is affected by CVE-9999-0003"


def build_explained_match(**explanation: Any) -> RetrievalMatch:
    """A match for a stored record with the explanation fields ``explanation`` sets."""
    match_fields: dict[str, Any] = {
        "cve_id": "CVE-9999-0001",
        "score": 1.0,
        "matched_fields": ("description",),
        "matched_terms": (),
    }
    match_fields.update(explanation)
    return RetrievalMatch(**match_fields)


def answer_with(match: RetrievalMatch) -> RetrievalOutcome:
    return RetrievalOutcome(status=BackendStatus.OK, matches=(match,))


UNVOUCHED_EXPLANATIONS = [
    pytest.param(
        {
            "lexical_retriever": CannedRetriever(
                answer_with(build_explained_match(matched_terms=(ADAPTER_PROSE,)))
            )
        },
        SearchRequest(query="ausf crash"),
        id="lexical_term_never_sent",
    ),
    pytest.param(
        {
            "lexical_retriever": CannedRetriever(
                answer_with(
                    build_explained_match(
                        graph_paths=(
                            GraphPath(seed_cve_id="CVE-9999-0001", relation="cwe", value="CWE-79"),
                        )
                    )
                )
            )
        },
        SearchRequest(query="ausf crash"),
        id="lexical_graph_path",
    ),
    pytest.param(
        {
            "semantic_retriever": CannedRetriever(
                answer_with(
                    build_explained_match(
                        matched_fields=("semantic.embedding",), matched_terms=("ausf",)
                    )
                )
            )
        },
        SearchRequest(query="ausf crash", semantic=True),
        id="semantic_term",
    ),
    pytest.param(
        {
            "structured_retriever": CannedStructuredIndex(
                answer_with(
                    build_explained_match(
                        matched_fields=("affected.vendor",), matched_terms=(ADAPTER_PROSE,)
                    )
                )
            )
        },
        SearchRequest(query="ausf crash", filters=SearchFilters(vendors=("open5gs",))),
        id="structured_term_never_sent",
    ),
    pytest.param(
        {
            "graph_retriever": CannedGraph(
                answer_with(
                    build_explained_match(
                        cve_id="CVE-9999-0002",
                        matched_fields=("relation.vendor",),
                        matched_terms=(ADAPTER_PROSE,),
                        graph_paths=(
                            GraphPath(
                                seed_cve_id="CVE-9999-0003", relation="vendor", value=ADAPTER_PROSE
                            ),
                        ),
                    )
                )
            )
        },
        SearchRequest(query="CVE-9999-0003", graph_expand=True),
        id="graph_relation_neither_record_asserts",
    ),
    pytest.param(
        {
            "lexical_retriever": CannedRetriever(
                answer_with(
                    RetrievalMatch.model_construct(
                        cve_id="CVE-9999-0001",
                        score=1.0,
                        matched_fields=(ADAPTER_PROSE,),
                        matched_terms=(),
                        graph_paths=(),
                    )
                )
            )
        },
        SearchRequest(query="ausf crash"),
        id="unvalidated_unknown_field",
    ),
    pytest.param(
        {
            "lexical_retriever": CannedRetriever(
                RetrievalOutcome(status=BackendStatus.OK, unindexed_terms=(ADAPTER_PROSE,))
            )
        },
        SearchRequest(query="ausf crash"),
        id="lexical_unindexed_term_never_sent",
    ),
]


@pytest.mark.parametrize(("retrievers", "request_"), UNVOUCHED_EXPLANATIONS)
def test_match_explanation_the_search_cannot_vouch_for_is_rejected_without_its_text(
    fixture_bundle: FixtureBundle, retrievers: dict[str, Any], request_: SearchRequest
) -> None:
    service = build_fixture_service(fixture_bundle, **retrievers)

    with pytest.raises(EvidenceValidationError) as raised:
        service.search(request_)

    assert ADAPTER_PROSE not in str(raised.value)


def test_graph_relation_both_records_assert_is_served(fixture_bundle: FixtureBundle) -> None:
    response = build_fixture_service(fixture_bundle).search(
        SearchRequest(query="CVE-9999-0003", graph_expand=True)
    )

    graph_hits: list[ChannelHit] = []
    for candidate in response.candidates:
        for channel_hit in candidate.channel_hits:
            if channel_hit.channel is RetrievalChannel.GRAPH:
                graph_hits.append(channel_hit)
    assert graph_hits


def test_graph_expansion_is_off_unless_a_request_asks_for_it() -> None:
    """ADR 0009 §12 pins this until the graph_expand follow-up settles expansion at scale."""
    request_schema = SearchRequest.model_json_schema()

    assert SearchRequest(query="gateway").graph_expand is False
    assert request_schema["properties"]["graph_expand"]["default"] is False


# --- Filters the dataset cannot execute, and the result limit ---------------------------


def test_purl_filter_over_records_naming_no_package_url_is_refused_naming_the_filter() -> None:
    store_service = build_search_service(load_corpus_store(COMPATIBILITY_STORE))
    request = SearchRequest(query="gateway", filters=SearchFilters(purls=("pkg:pypi/example",)))

    with pytest.raises(UnsupportedFilter) as raised:
        store_service.search(request)

    assert store_service.serves_purl_filter() is False
    assert raised.value.filter_name == "purls"
    assert "pkg:pypi/example" not in str(raised.value)


def test_purl_filter_over_records_naming_package_urls_is_executed(
    search_service: SearchService,
) -> None:
    request = SearchRequest(
        query="parser", filters=SearchFilters(purls=("pkg:pypi/example-parser",))
    )

    response = search_service.search(request)

    assert search_service.serves_purl_filter() is True
    assert list_candidate_cve_ids(response.candidates) == ["CVE-9999-0006"]


def test_other_filters_over_records_naming_no_package_url_are_executed() -> None:
    store_service = build_search_service(load_corpus_store(COMPATIBILITY_STORE))

    response = store_service.search(
        SearchRequest(query="gateway", filters=SearchFilters(vendors=("democorp",)))
    )

    assert RetrievalChannel.STRUCTURED in response.channels_executed


def test_search_listing_as_many_candidates_as_its_limit_warns_the_limit_was_reached(
    search_service: SearchService,
) -> None:
    response = search_service.search(
        SearchRequest(query="democorp fictional5g examplenet", limit=2)
    )

    assert len(response.candidates) == 2
    assert response.warnings[-1] == SearchWarning(
        code=SearchWarningCode.RESULT_LIMIT_REACHED, subject="2"
    )


def test_search_listing_fewer_candidates_than_its_limit_gives_no_limit_warning(
    search_service: SearchService,
) -> None:
    response = search_service.search(SearchRequest(query="ausf crash", limit=20))

    assert 0 < len(response.candidates) < 20
    assert SearchWarningCode.RESULT_LIMIT_REACHED not in list_codes(response.warnings)


def test_search_whose_channels_returned_fewer_than_their_top_k_gives_no_limit_warning(
    search_service: SearchService,
) -> None:
    """An exact hit and two lexical matches fill a limit of three, yet the lexical channel
    returned fewer than its top-k, so nothing lies beyond the three listed."""
    response = search_service.search(SearchRequest(query="CVE-9999-0003 gateway", limit=3))

    assert list_candidate_cve_ids(response.candidates) == [
        "CVE-9999-0003",
        "CVE-9999-0001",
        "CVE-9999-0002",
    ]
    assert SearchWarningCode.RESULT_LIMIT_REACHED not in list_codes(response.warnings)


def test_exact_lookup_filling_its_limit_gives_no_limit_warning(
    search_service: SearchService,
) -> None:
    """The exact-ID channel answers only the IDs named, so nothing lies beyond them."""
    response = search_service.lookup("CVE-9999-0003")

    assert len(response.candidates) == 1
    assert SearchWarningCode.RESULT_LIMIT_REACHED not in list_codes(response.warnings)


def test_limit_warning_naming_another_limit_than_the_candidates_listed_is_rejected(
    search_service: SearchService, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = search_service.search(SearchRequest(query="ausf crash", limit=20))
    forged_warnings = (
        *response.warnings,
        SearchWarning(code=SearchWarningCode.RESULT_LIMIT_REACHED, subject="20"),
    )
    forged_draft = response.model_copy(update={"warnings": forged_warnings})
    forged_response = forged_draft.model_copy(
        update={"result_sha256": forged_draft.compute_result_sha256()}
    )

    with pytest.raises(EvidenceValidationError) as raised:
        validate_search_response(forged_response, packaged_evidence_catalog)

    assert raised.value.violations == (
        "the result_limit_reached warning names another limit than the candidates listed",
    )
