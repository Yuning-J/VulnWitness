"""Topic context keeps threat context and CVEs apart, and reports sources honestly."""

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from cve_kgrag.adapters.fight.pinned_yaml import UnavailableFightSource
from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.adapters.lexical.bm25_index import Bm25LexicalIndex
from cve_kgrag.adapters.topics.yaml_cards import default_topic_dir, load_topic_cards
from cve_kgrag.application.topic_context import TopicContextService
from cve_kgrag.composition import build_evidence_catalog, build_topic_context_service
from cve_kgrag.domain.evidence import EvidenceAnchor
from cve_kgrag.domain.search import ChannelOutcome, RetrievalMatch, RetrievalOutcome
from cve_kgrag.domain.taxonomy import (
    BackendFailure,
    BackendFailureDetail,
    BackendStatus,
    KnowledgeScope,
    ResultStatus,
    RetrievalChannel,
)
from cve_kgrag.domain.threat_context import (
    FightSnapshotInfo,
    KnownFightSnapshot,
    SnapshotCoverage,
    ThreatContextItem,
    ThreatContextOutcome,
)
from cve_kgrag.domain.topic import RelevanceTier
from cve_kgrag.domain.topic_context import (
    KnowledgeSource,
    QueryScope,
    TopicContextRequest,
    TopicContextResponse,
    TopicContextWarningCode,
)
from cve_kgrag.domain.validation import EvidenceValidationError
from cve_kgrag.ports.sources import FightSource
from cve_kgrag.topics.registry import TopicRegistry
from tests.support.builders import build_anchor, build_bundle_with
from tests.support.fakes import CannedRetriever, LexicalRequestRecorder
from tests.support.services import build_fixture_service

FULL_SNAPSHOT = FightSnapshotInfo(
    repository_url="https://github.com/mitre/FiGHT",
    commit="0" * 40,
    data_version="0.0.0",
    snapshot_sha256="1" * 64,
    coverage=SnapshotCoverage.FULL,
    technique_count=1,
    tactic_count=1,
    retrieved_at=datetime(2026, 10, 14, tzinfo=UTC),
    ingested_at=datetime(2026, 10, 15, tzinfo=UTC),
    terms_ref="https://fight.mitre.org/resources/terms/",
)


# The catalog entry a deployment would pin for the fake full snapshot.
PINNED_FAKE_SNAPSHOT = KnownFightSnapshot(
    snapshot_sha256=FULL_SNAPSHOT.snapshot_sha256,
    repository_url=FULL_SNAPSHOT.repository_url,
    commit=FULL_SNAPSHOT.commit,
    data_version=FULL_SNAPSHOT.data_version,
    upstream_path="fight.yaml",
    coverage=SnapshotCoverage.FULL,
    technique_count=1,
    tactic_count=1,
    retrieved_at=FULL_SNAPSHOT.retrieved_at,
    terms_ref=FULL_SNAPSHOT.terms_ref,
)


@dataclass
class RecordingFightSource:
    """Returns one canned outcome for a canned snapshot and records every search."""

    outcome: ThreatContextOutcome
    snapshot_info: FightSnapshotInfo | None = FULL_SNAPSHOT
    searches: list[tuple[str, ...]] = field(default_factory=list)
    limits: list[int] = field(default_factory=list)

    def describe(self) -> FightSnapshotInfo | None:
        return self.snapshot_info

    def search(self, terms: Sequence[str], limit: int) -> ThreatContextOutcome:
        self.searches.append(tuple(terms))
        self.limits.append(limit)
        return self.outcome

    def list_evidence(self) -> Sequence[EvidenceAnchor]:
        return self.outcome.evidence

    def list_techniques(self) -> Sequence[ThreatContextItem]:
        indexed_items: list[ThreatContextItem] = []
        for item in self.outcome.items:
            indexed_items.append(
                item.model_copy(update={"matched_fields": (), "matched_terms": ()})
            )
        return tuple(indexed_items)


def build_service(
    bundle: FixtureBundle, fight_source: FightSource, **retrievers: object
) -> TopicContextService:
    return TopicContextService(
        TopicRegistry(load_topic_cards(default_topic_dir())),
        build_fixture_service(bundle, **retrievers),
        fight_source,
        PINNED_FAKE_SNAPSHOT,
        build_evidence_catalog(bundle, fight_source),
    )


def list_implementation_ids(response: TopicContextResponse) -> list[str]:
    cve_ids: list[str] = []
    for topic_candidate in response.implementation_candidates:
        cve_ids.append(topic_candidate.candidate.record.cve_id)
    return cve_ids


def build_request(scope: QueryScope, query: str = "5gaka") -> TopicContextRequest:
    return TopicContextRequest(query=query, scope=scope, limit=20)


def test_implementation_only_never_consults_threat_context(fixture_bundle: FixtureBundle) -> None:
    fight_source = RecordingFightSource(ThreatContextOutcome(status="ok", snapshot=FULL_SNAPSHOT))
    service = build_topic_context_service(fixture_bundle, fight_source, PINNED_FAKE_SNAPSHOT)

    response = service.explore(build_request(QueryScope.IMPLEMENTATION_ONLY))

    assert fight_source.searches == []
    assert response.protocol_context == ()


def test_unresolved_query_consults_no_source(fixture_bundle: FixtureBundle) -> None:
    fight_source = RecordingFightSource(ThreatContextOutcome(status="ok", snapshot=FULL_SNAPSHOT))
    service = build_topic_context_service(fixture_bundle, fight_source, PINNED_FAKE_SNAPSHOT)

    response = service.explore(build_request(QueryScope.MIXED, query="aka"))

    assert fight_source.searches == []
    assert response.source_outcomes == ()
    assert response.status is ResultStatus.NO_MATCH


@pytest.mark.parametrize(
    ("scope", "expected_status"),
    [
        (QueryScope.PROTOCOL_CONTEXT_ONLY, ResultStatus.SOURCE_UNAVAILABLE),
        (QueryScope.MIXED, ResultStatus.PARTIAL),
        (QueryScope.IMPLEMENTATION_ONLY, ResultStatus.OK),
    ],
)
def test_unavailable_threat_context_is_reported_for_the_scopes_that_need_it(
    fixture_bundle: FixtureBundle, scope: QueryScope, expected_status: ResultStatus
) -> None:
    service = build_topic_context_service(fixture_bundle, UnavailableFightSource())

    response = service.explore(build_request(scope))

    assert response.status is expected_status
    assert response.protocol_context == ()


def test_protocol_answer_never_contains_a_cve(fixture_bundle: FixtureBundle) -> None:
    service = build_topic_context_service(fixture_bundle)

    response = service.explore(build_request(QueryScope.PROTOCOL_CONTEXT_ONLY))

    assert response.implementation_candidates == ()
    for item in response.protocol_context:
        assert item.scope is KnowledgeScope.PROTOCOL_THREAT_CONTEXT
    for excluded in response.excluded_implementation_candidates:
        record = excluded.candidate.candidate.record
        assert record.protocol_design_claim == "not_established"
        assert record.formal_seed_eligible is False
        assert "protocol_context_only" in excluded.reason


def test_every_evidence_anchor_is_cited_and_none_is_a_formal_finding(
    fixture_bundle: FixtureBundle,
) -> None:
    service = build_topic_context_service(fixture_bundle)

    response = service.explore(build_request(QueryScope.MIXED))

    cited_ids: set[str] = set()
    for item in response.protocol_context:
        cited_ids.update(item.evidence_ids)
    for topic_candidate in response.implementation_candidates:
        cited_ids.update(topic_candidate.candidate.record.evidence_ids)
    evidence_ids: set[str] = set()
    for anchor in response.evidence:
        evidence_ids.add(anchor.evidence_id)
        assert anchor.scope is not KnowledgeScope.FORMAL_PROTOCOL_FINDING
    assert cited_ids == evidence_ids


def take_first_fight_item(fixture_bundle: FixtureBundle) -> ThreatContextItem:
    protocol_answer = build_topic_context_service(fixture_bundle).explore(
        build_request(QueryScope.PROTOCOL_CONTEXT_ONLY)
    )
    return protocol_answer.protocol_context[0]


@pytest.mark.parametrize(
    ("anchor_fields", "violation"),
    [
        ({"scope": KnowledgeScope.IMPLEMENTATION_VULNERABILITY}, "FiGHT evidence must be"),
        ({"scope": KnowledgeScope.PROTOCOL_THREAT_CONTEXT}, "cites non-FiGHT evidence"),
    ],
    ids=["relabeled_as_implementation", "synthetic_source"],
)
def test_threat_context_item_backed_by_forged_evidence_is_rejected(
    fixture_bundle: FixtureBundle, anchor_fields: dict[str, object], violation: str
) -> None:
    item = take_first_fight_item(fixture_bundle)
    forged_anchor = build_anchor(
        authoritative_record_id=item.technique_id,
        source_version=FULL_SNAPSHOT.source_version,
        source_uri=PINNED_FAKE_SNAPSHOT.source_uri,
        retrieved_at=PINNED_FAKE_SNAPSHOT.retrieved_at,
        license_or_terms_ref=PINNED_FAKE_SNAPSHOT.terms_ref,
        **anchor_fields,
    )
    forged_item = item.model_copy(update={"evidence_ids": (forged_anchor.evidence_id,)})
    forging_source = RecordingFightSource(
        ThreatContextOutcome(
            status="ok", items=(forged_item,), evidence=(forged_anchor,), snapshot=FULL_SNAPSHOT
        )
    )
    service = build_topic_context_service(fixture_bundle, forging_source, PINNED_FAKE_SNAPSHOT)

    with pytest.raises(EvidenceValidationError, match=violation):
        service.explore(build_request(QueryScope.PROTOCOL_CONTEXT_ONLY))


def test_packaged_excerpt_is_reported_as_an_excerpt(fixture_bundle: FixtureBundle) -> None:
    response = build_topic_context_service(fixture_bundle).explore(
        build_request(QueryScope.PROTOCOL_CONTEXT_ONLY)
    )

    fight_outcome = response.source_outcomes[0]
    assert fight_outcome.coverage is SnapshotCoverage.EXCERPT
    assert fight_outcome.source_version is not None
    assert "+sha256:" in fight_outcome.source_version
    assert response.warnings[-1].code is TopicContextWarningCode.SOURCE_SNAPSHOT_IS_EXCERPT


def test_cve_naming_one_ambiguous_acronym_is_dropped_with_a_warning(
    fixture_bundle: FixtureBundle,
) -> None:
    bundle = build_bundle_with(
        fixture_bundle, "CVE-9999-0501", "[SYNTHETIC] UniFi Dream Machine (UDM) admin bypass."
    )
    service = build_service(bundle, UnavailableFightSource())

    response = service.explore(build_request(QueryScope.IMPLEMENTATION_ONLY))

    assert "CVE-9999-0501" not in list_implementation_ids(response)
    assert response.warnings[-1].code is TopicContextWarningCode.UNRELATED_CANDIDATES_DROPPED
    assert response.warnings[-1].subject == "1"


def test_limit_applies_after_relevance_ordering(fixture_bundle: FixtureBundle) -> None:
    service = build_topic_context_service(fixture_bundle)

    response = service.explore(
        TopicContextRequest(query="5gaka", scope=QueryScope.IMPLEMENTATION_ONLY, limit=1)
    )

    assert list_implementation_ids(response) == ["CVE-9999-0003"]
    assert response.implementation_candidates[0].topic_rank == 1


def test_semantic_match_naming_nothing_is_kept_as_semantic_only(
    fixture_bundle: FixtureBundle,
) -> None:
    semantic_match = RetrievalMatch(
        cve_id="CVE-9999-0006", score=0.5, matched_fields=("semantic.embedding",), matched_terms=()
    )
    semantic_retriever = CannedRetriever(
        RetrievalOutcome(status=BackendStatus.OK, matches=(semantic_match,))
    )
    service = build_service(
        fixture_bundle, UnavailableFightSource(), semantic_retriever=semantic_retriever
    )

    response = service.explore(
        TopicContextRequest(
            query="5gaka", scope=QueryScope.IMPLEMENTATION_ONLY, limit=20, semantic=True
        )
    )

    tiers: dict[str, RelevanceTier] = {}
    for topic_candidate in response.implementation_candidates:
        tiers[topic_candidate.candidate.record.cve_id] = topic_candidate.relevance.tier
    assert tiers["CVE-9999-0006"] is RelevanceTier.SEMANTIC_ONLY
    assert list_implementation_ids(response)[-1] == "CVE-9999-0006"


def test_failed_cve_search_names_its_failing_channel_with_the_server_sentence(
    fixture_bundle: FixtureBundle,
) -> None:
    failing_lexical = CannedRetriever(
        RetrievalOutcome(status=BackendStatus.ERROR, failure=BackendFailure.SEARCH_FAILED)
    )
    service = build_service(
        fixture_bundle,
        RecordingFightSource(ThreatContextOutcome(status="ok", snapshot=FULL_SNAPSHOT)),
        lexical_retriever=failing_lexical,
    )

    response = service.explore(build_request(QueryScope.IMPLEMENTATION_ONLY))

    cve_outcome = response.source_outcomes[-1]
    assert cve_outcome.status is ResultStatus.BACKEND_ERROR
    assert cve_outcome.detail is None
    assert cve_outcome.channel_failures == (
        ChannelOutcome(
            channel=RetrievalChannel.LEXICAL,
            status=BackendStatus.ERROR,
            detail=BackendFailureDetail.SEARCH_FAILED,
        ),
    )
    assert response.status is ResultStatus.BACKEND_ERROR


def test_unresolved_query_explains_the_excluded_term(fixture_bundle: FixtureBundle) -> None:
    response = build_topic_context_service(fixture_bundle).explore(
        build_request(QueryScope.MIXED, query="aka")
    )

    codes: list[TopicContextWarningCode] = []
    for warning in response.warnings:
        codes.append(warning.code)
    assert codes == [
        TopicContextWarningCode.EXCLUDED_TERM,
        TopicContextWarningCode.TOPIC_NOT_RESOLVED,
    ]


def test_identical_requests_hash_identically(fixture_bundle: FixtureBundle) -> None:
    first = build_topic_context_service(fixture_bundle).explore(build_request(QueryScope.MIXED))
    second = build_topic_context_service(fixture_bundle).explore(build_request(QueryScope.MIXED))

    assert first.result_sha256 == second.result_sha256
    assert first.model_dump_json() == second.model_dump_json()


def test_source_outcomes_name_each_consulted_source(fixture_bundle: FixtureBundle) -> None:
    response = build_topic_context_service(fixture_bundle).explore(build_request(QueryScope.MIXED))

    sources: list[KnowledgeSource] = []
    for outcome in response.source_outcomes:
        sources.append(outcome.source)
    assert sources == [KnowledgeSource.MITRE_FIGHT, KnowledgeSource.CVE_SEARCH]


def test_fight_source_receives_the_topic_terms_and_the_requested_limit(
    fixture_bundle: FixtureBundle,
) -> None:
    fight_source = RecordingFightSource(ThreatContextOutcome(status="ok", snapshot=FULL_SNAPSHOT))
    service = build_topic_context_service(fixture_bundle, fight_source, PINNED_FAKE_SNAPSHOT)

    service.explore(TopicContextRequest(query="5gaka", scope=QueryScope.MIXED, limit=3))

    assert fight_source.limits == [3]
    assert fight_source.searches[0][:2] == ("5G Authentication and Key Agreement", "5G-AKA")


@pytest.mark.parametrize(
    ("limit", "max_results_per_search", "expected_fight_limit"),
    [(10, 2, 2), (3, 20, 3)],
    ids=["search_cap_below_limit", "limit_below_search_cap"],
)
def test_every_backend_search_stays_within_max_results_per_search(
    fixture_bundle: FixtureBundle,
    limit: int,
    max_results_per_search: int,
    expected_fight_limit: int,
) -> None:
    lexical_recorder = LexicalRequestRecorder(Bm25LexicalIndex(fixture_bundle.records))
    fight_source = RecordingFightSource(ThreatContextOutcome(status="ok", snapshot=FULL_SNAPSHOT))
    service = build_service(fixture_bundle, fight_source, lexical_retriever=lexical_recorder)

    service.explore(
        TopicContextRequest(
            query="5gaka",
            scope=QueryScope.MIXED,
            limit=limit,
            max_results_per_search=max_results_per_search,
        )
    )

    template_limits: list[int] = []
    for _, template_limit in lexical_recorder.requests:
        template_limits.append(template_limit)
    assert template_limits == [max_results_per_search] * 4
    assert fight_source.limits == [expected_fight_limit]


def test_cve_naming_the_compact_alias_is_retrieved(fixture_bundle: FixtureBundle) -> None:
    bundle = build_bundle_with(
        fixture_bundle, "CVE-9999-0601", "[SYNTHETIC] A crash in the 5GAKA handler of a core."
    )
    service = build_service(bundle, UnavailableFightSource())

    response = service.explore(build_request(QueryScope.IMPLEMENTATION_ONLY))

    assert "CVE-9999-0601" in list_implementation_ids(response)


def test_relevant_cve_outranked_by_keyword_decoys_survives_a_small_limit(
    fixture_bundle: FixtureBundle,
) -> None:
    bundle = fixture_bundle
    for index in range(3):
        bundle = build_bundle_with(
            bundle, f"CVE-9999-070{index}", "[SYNTHETIC] Router 5G, aka 5G, aka 5G. Also aka 5G."
        )
    bundle = build_bundle_with(
        bundle,
        "CVE-9999-0710",
        "[SYNTHETIC] Heap overflow while parsing 5G-AKA authentication vectors in a long "
        "and verbose description of an otherwise unremarkable network function component.",
    )
    service = build_service(bundle, UnavailableFightSource())

    response = service.explore(
        TopicContextRequest(query="5gaka", scope=QueryScope.IMPLEMENTATION_ONLY, limit=2)
    )

    assert list_implementation_ids(response) == ["CVE-9999-0003", "CVE-9999-0710"]


def test_cve_search_whose_hits_are_all_dropped_reports_no_match(
    fixture_bundle: FixtureBundle,
) -> None:
    empty_bundle = FixtureBundle(manifest=fixture_bundle.manifest, records=(), evidence=())
    bundle = build_bundle_with(empty_bundle, "CVE-9999-0801", "[SYNTHETIC] UniFi UDM web UI XSS.")
    service = build_service(bundle, UnavailableFightSource())

    response = service.explore(build_request(QueryScope.IMPLEMENTATION_ONLY))

    assert response.source_outcomes[-1].status is ResultStatus.NO_MATCH
    assert response.status is ResultStatus.NO_MATCH


def test_candidate_found_by_two_channels_lists_both_and_keeps_its_best_rank(
    fixture_bundle: FixtureBundle,
) -> None:
    semantic_match = RetrievalMatch(
        cve_id="CVE-9999-0004", score=0.9, matched_fields=("semantic.embedding",), matched_terms=()
    )
    semantic_retriever = CannedRetriever(
        RetrievalOutcome(status=BackendStatus.OK, matches=(semantic_match,))
    )
    service = build_service(
        fixture_bundle, UnavailableFightSource(), semantic_retriever=semantic_retriever
    )

    response = service.explore(
        TopicContextRequest(
            query="5gaka", scope=QueryScope.IMPLEMENTATION_ONLY, limit=20, semantic=True
        )
    )

    for topic_candidate in response.implementation_candidates:
        if topic_candidate.candidate.record.cve_id == "CVE-9999-0004":
            assert topic_candidate.retrieval_channels == (
                RetrievalChannel.LEXICAL,
                RetrievalChannel.SEMANTIC,
            )
            assert topic_candidate.candidate.rank == 1


def test_second_resolved_topic_is_named_as_not_explored(fixture_bundle: FixtureBundle) -> None:
    broader_card = load_topic_cards(default_topic_dir())[0].model_copy(
        update={
            "topic_id": "3gpp:5g",
            "canonical_name": "5G System",
            "exact_aliases": ("5GS",),
            "exclusions": (),
        }
    )
    fight_source = UnavailableFightSource()
    service = TopicContextService(
        TopicRegistry([*load_topic_cards(default_topic_dir()), broader_card]),
        build_fixture_service(fixture_bundle),
        fight_source,
        PINNED_FAKE_SNAPSHOT,
        build_evidence_catalog(fixture_bundle, fight_source),
    )

    response = service.explore(build_request(QueryScope.IMPLEMENTATION_ONLY, query="5gaka in 5GS"))

    assert response.resolution.matches[0].topic_id == "3gpp:5g-aka"
    assert response.warnings[0].code is TopicContextWarningCode.ADDITIONAL_TOPIC_NOT_EXPLORED
    assert response.warnings[0].subject == "3gpp:5g"


@pytest.mark.parametrize(
    ("products", "expected_status", "expected_cve_ids"),
    [
        (["f5gc"], ResultStatus.OK, ["CVE-9999-0003", "CVE-9999-0004"]),
        (["open5gs"], ResultStatus.NO_MATCH, []),
    ],
    ids=["named_product", "product_without_records"],
)
def test_filters_constrain_every_template_search(
    fixture_bundle: FixtureBundle,
    products: list[str],
    expected_status: ResultStatus,
    expected_cve_ids: list[str],
) -> None:
    service = build_topic_context_service(fixture_bundle)

    response = service.explore(
        TopicContextRequest(
            query="5gaka",
            scope=QueryScope.IMPLEMENTATION_ONLY,
            limit=20,
            filters={"products": products},
        )
    )

    assert response.status is expected_status
    assert list_implementation_ids(response) == expected_cve_ids
