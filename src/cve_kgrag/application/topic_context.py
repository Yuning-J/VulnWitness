"""Topic context: resolve a sparse term to a reviewed topic, then gather scoped knowledge.

FiGHT threat context is consulted unless the caller asked for implementation
only. CVE candidates are retrieved with each of the topic's query templates, under
the request's filters and up to ``max_results_per_search`` each, then assessed for
relevance from the record's own text and only then cut to the requested limit. A
candidate is kept when the record names the topic, or enough of its entities and
ecosystem terms, or when the semantic channel matched it (``semantic_only``). Under
``protocol_context_only`` kept candidates are listed as excluded, never as the answer.

An investigation can also search FiGHT directly with the question's own words when no
topic resolved (``search_fight_directly``): one FiGHT search under
``protocol_context_only``, which names each word no technique holds
(``term_not_indexed``). ``explore`` consults no source for a query no topic resolves.

A cut is never silent (ADR 0009 §11a): ``protocol_context_truncated`` counts the
techniques the snapshot matched that the protocol section does not list, and
``candidates_truncated`` the relevant CVEs the candidate section does not list because
of its limit. A card's CVE search that warned it reached ``max_results_per_search`` may
have cut further matches it cannot count: ``result_limit_reached`` says so, without a
count. None of them changes the status.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from cve_kgrag.application.search import SearchService
from cve_kgrag.domain.evidence import EvidenceAnchor
from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.hashing import UNSEALED_SHA256
from cve_kgrag.domain.search import (
    Candidate,
    ChannelOutcome,
    SearchRequest,
    SearchResponse,
    SearchWarningCode,
)
from cve_kgrag.domain.taxonomy import (
    BackendStatus,
    ResultStatus,
    RetrievalChannel,
    describe_backend_failure,
)
from cve_kgrag.domain.text import normalize_query
from cve_kgrag.domain.threat_context import (
    KnownFightSnapshot,
    SnapshotCoverage,
    TechniqueField,
    ThreatContextItem,
    ThreatContextOutcome,
)
from cve_kgrag.domain.topic import ProtocolTopic, RelevanceTier, TopicResolution
from cve_kgrag.domain.topic_context import (
    ExcludedCandidate,
    KnowledgeSource,
    QueryScope,
    SourceOutcome,
    TopicCandidate,
    TopicContextRequest,
    TopicContextResponse,
    TopicContextWarning,
    TopicContextWarningCode,
    decide_topic_status,
    format_excerpt_warning_subject,
    list_consulted_sources,
    summarize_statuses,
)
from cve_kgrag.domain.validation import EvidenceValidationError, validate_topic_context_response
from cve_kgrag.ports.sources import FightSource
from cve_kgrag.topics.registry import TopicRegistry
from cve_kgrag.topics.relevance import assess_relevance

PROTOCOL_EXCLUSION_REASON = (
    "An implementation vulnerability; a CVE never establishes a protocol-design flaw, "
    "so it stays out of a protocol_context_only answer."
)
TIER_ORDER = (
    RelevanceTier.EXPLICIT_PROTOCOL_MENTION,
    RelevanceTier.PROTOCOL_COMPONENT_IMPLEMENTATION,
    RelevanceTier.TELECOM_ECOSYSTEM_ADJACENT,
    RelevanceTier.SEMANTIC_ONLY,
)
RESULT_STATUS_BY_SOURCE_FAILURE = {
    BackendStatus.UNAVAILABLE: ResultStatus.SOURCE_UNAVAILABLE,
    BackendStatus.INCOMPLETE_INDEX: ResultStatus.INCOMPLETE_INDEX,
    BackendStatus.ERROR: ResultStatus.BACKEND_ERROR,
}


def list_topic_terms(topic: ProtocolTopic) -> list[str]:
    """The names a source text may use for the topic: its name, aliases and entities."""
    topic_terms = [topic.canonical_name, *topic.exact_aliases]
    for entity in topic.entities:
        topic_terms.append(entity.name)
    return topic_terms


def consults_fight(scope: QueryScope) -> bool:
    return KnowledgeSource.MITRE_FIGHT in list_consulted_sources(scope)


def decide_fight_search_limit(request: TopicContextRequest) -> int:
    """FiGHT's items are the protocol section itself, so its one search asks for no more
    than the section keeps and no more than any one search may return."""
    return min(request.limit, request.max_results_per_search)


def build_template_searches(
    topic: ProtocolTopic, request: TopicContextRequest
) -> list[SearchRequest]:
    """One CVE search per query template, under the request's filters and per-search cap."""
    template_searches: list[SearchRequest] = []
    for query_template in topic.query_templates:
        template_searches.append(
            SearchRequest(
                query=query_template,
                limit=request.max_results_per_search,
                filters=request.filters,
                semantic=request.semantic,
            )
        )
    return template_searches


def tier_sort_key(topic_candidate: TopicCandidate) -> tuple[int, int, str]:
    return (
        TIER_ORDER.index(topic_candidate.relevance.tier),
        topic_candidate.candidate.rank,
        topic_candidate.candidate.record.cve_id,
    )


def require_sent_terms(
    fight_outcome: ThreatContextOutcome, sent_terms: Sequence[str]
) -> ThreatContextOutcome:
    """Pass the FiGHT outcome through, or raise ``EvidenceValidationError`` if an item
    names a field outside ``TechniqueField`` or a matched term the search did not send, or
    the outcome names an unindexed term the search did not send. Fields are checked here
    too: a source can copy an item without validation (``model_copy``). The violation
    names the technique only, never the source's text."""
    for item in fight_outcome.items:
        for matched_field in item.matched_fields:
            if not isinstance(matched_field, TechniqueField):
                raise EvidenceValidationError(
                    [f"the FiGHT source matched {item.technique_id} in an unknown field"]
                )
        for matched_term in item.matched_terms:
            if matched_term not in sent_terms:
                raise EvidenceValidationError(
                    [f"the FiGHT source explained {item.technique_id} with a term never sent"]
                )
    for unindexed_term in fight_outcome.unindexed_terms:
        if unindexed_term not in sent_terms:
            raise EvidenceValidationError(["the FiGHT source named an unindexed term never sent"])
    return fight_outcome


def require_matched_count(fight_outcome: ThreatContextOutcome) -> ThreatContextOutcome:
    """Pass the FiGHT outcome through, or raise ``EvidenceValidationError`` if its matched
    count is below the items it lists, or is 0 beside items or above 0 beside none; a
    source can copy an outcome without validation (``model_copy``)."""
    listed_count = len(fight_outcome.items)
    matched_count = fight_outcome.matched_count
    if matched_count < listed_count or (matched_count == 0) != (listed_count == 0):
        raise EvidenceValidationError(
            ["the FiGHT source's matched count disagrees with the techniques it listed"]
        )
    return fight_outcome


def reaches_result_limit(cve_search: SearchResponse) -> bool:
    """Whether the search warned that it reached its limit."""
    return any(
        warning.code is SearchWarningCode.RESULT_LIMIT_REACHED for warning in cve_search.warnings
    )


def list_channel_failures(cve_searches: list[SearchResponse]) -> tuple[ChannelOutcome, ...]:
    """Each failing channel outcome of ``cve_searches``, once, in the order first seen."""
    channel_failures: list[ChannelOutcome] = []
    for cve_search in cve_searches:
        for channel_outcome in cve_search.channel_outcomes:
            if channel_outcome.status is BackendStatus.OK:
                continue
            if channel_outcome not in channel_failures:
                channel_failures.append(channel_outcome)
    return tuple(channel_failures)


@dataclass(frozen=True)
class FightSearch:
    """One FiGHT search's contribution to a response: the source's outcome, the techniques
    it lists and their anchors. A failed search lists none."""

    source_outcome: SourceOutcome
    protocol_context: tuple[ThreatContextItem, ...]
    evidence: tuple[EvidenceAnchor, ...]


@dataclass(frozen=True)
class TopicExploration:
    """A sealed topic response, and the CVE IDs of the relevant candidates it does not list
    because of its limit, in topic rank order: an investigation counts them toward
    ``answer_truncated`` without the response carrying them."""

    response: TopicContextResponse
    omitted_cve_ids: tuple[str, ...]


class TopicContextService:
    """Raises ``EvidenceValidationError`` rather than return a response that mixes scopes."""

    def __init__(
        self,
        topic_registry: TopicRegistry,
        search_service: SearchService,
        fight_source: FightSource,
        pinned_fight_snapshot: KnownFightSnapshot | None,
        evidence_catalog: EvidenceCatalog,
    ) -> None:
        """``pinned_fight_snapshot`` is the catalog entry the deployment pinned for
        ``fight_source``, or ``None`` when no FiGHT snapshot is configured.
        ``evidence_catalog`` holds every anchor the CVE and FiGHT sources serve."""
        self._topic_registry = topic_registry
        self._search_service = search_service
        self._fight_source = fight_source
        self._pinned_fight_snapshot = pinned_fight_snapshot
        self._evidence_catalog = evidence_catalog

    def explore(self, request: TopicContextRequest) -> TopicContextResponse:
        return self.explore_with_omissions(request).response

    def explore_with_omissions(self, request: TopicContextRequest) -> TopicExploration:
        resolution = self._topic_registry.resolve(request.query)
        warnings: list[TopicContextWarning] = []
        for excluded_term in resolution.excluded_terms:
            warnings.append(
                TopicContextWarning(
                    code=TopicContextWarningCode.EXCLUDED_TERM, subject=excluded_term.term
                )
            )
        if not resolution.matches:
            warnings.append(
                TopicContextWarning(
                    code=TopicContextWarningCode.TOPIC_NOT_RESOLVED,
                    subject=resolution.normalized_query,
                )
            )
            return TopicExploration(self._seal(request, resolution, (), (), [], [], warnings), ())
        for other_match in resolution.matches[1:]:
            warnings.append(
                TopicContextWarning(
                    code=TopicContextWarningCode.ADDITIONAL_TOPIC_NOT_EXPLORED,
                    subject=other_match.topic_id,
                )
            )
        registered_topic = self._topic_registry.get_topic(resolution.matches[0].topic_id)
        if registered_topic is None:
            raise EvidenceValidationError(["a resolved topic is missing from the registry"])
        topic = registered_topic.topic

        source_outcomes: list[SourceOutcome] = []
        protocol_context: tuple[ThreatContextItem, ...] = ()
        fight_evidence: tuple[EvidenceAnchor, ...] = ()
        if consults_fight(request.scope):
            fight_search = self._search_fight(
                list_topic_terms(topic),
                decide_fight_search_limit(request),
                warnings,
                reports_unindexed_terms=False,
            )
            source_outcomes.append(fight_search.source_outcome)
            protocol_context = fight_search.protocol_context
            fight_evidence = fight_search.evidence

        cve_searches: list[SearchResponse] = []
        for template_search in build_template_searches(topic, request):
            cve_searches.append(self._search_service.search(template_search))
        topic_candidates, dropped_count = self._assess_candidates(topic, cve_searches)
        source_outcomes.append(
            SourceOutcome(
                source=KnowledgeSource.CVE_SEARCH,
                # Results count only once relevance kept them: an all-dropped search found
                # nothing about the topic.
                status=summarize_statuses(
                    (cve_search.status for cve_search in cve_searches), bool(topic_candidates)
                ),
                channel_failures=list_channel_failures(cve_searches),
            )
        )
        if dropped_count:
            warnings.append(
                TopicContextWarning(
                    code=TopicContextWarningCode.UNRELATED_CANDIDATES_DROPPED,
                    subject=str(dropped_count),
                )
            )
        kept_candidates = topic_candidates[: request.limit]
        omitted_cve_ids: list[str] = []
        for omitted_candidate in topic_candidates[request.limit :]:
            omitted_cve_ids.append(omitted_candidate.candidate.record.cve_id)
        if omitted_cve_ids:
            warnings.append(
                TopicContextWarning(
                    code=TopicContextWarningCode.CANDIDATES_TRUNCATED,
                    subject=str(len(omitted_cve_ids)),
                )
            )
        if any(map(reaches_result_limit, cve_searches)):
            warnings.append(
                TopicContextWarning(
                    code=TopicContextWarningCode.RESULT_LIMIT_REACHED,
                    subject=str(request.max_results_per_search),
                )
            )
        evidence = self._collect_evidence(fight_evidence, cve_searches, kept_candidates)
        response = self._seal(
            request,
            resolution,
            protocol_context,
            evidence,
            kept_candidates,
            source_outcomes,
            warnings,
        )
        return TopicExploration(response, tuple(omitted_cve_ids))

    def search_fight_directly(
        self, request: TopicContextRequest, fight_terms: Sequence[str]
    ) -> TopicContextResponse:
        """One FiGHT search of ``fight_terms``, the question's own words, for a query no
        topic resolved: the response keeps the unresolved resolution and its
        ``topic_not_resolved`` warning, consults FiGHT alone under
        ``protocol_context_only`` and names each sent word no technique holds
        (``term_not_indexed``). The caller decides the words may be sent
        (``list_fight_terms``); the plan gate admits this search only for a query that
        resolved no topic and named no excluded term."""
        resolution = self._topic_registry.resolve(request.query)
        warnings = [
            TopicContextWarning(
                code=TopicContextWarningCode.TOPIC_NOT_RESOLVED,
                subject=resolution.normalized_query,
            )
        ]
        fight_search = self._search_fight(
            fight_terms, decide_fight_search_limit(request), warnings, reports_unindexed_terms=True
        )
        return self._seal(
            request,
            resolution,
            fight_search.protocol_context,
            fight_search.evidence,
            [],
            [fight_search.source_outcome],
            warnings,
            sent_fight_terms=fight_terms,
        )

    def _search_fight(
        self,
        fight_terms: Sequence[str],
        limit: int,
        warnings: list[TopicContextWarning],
        reports_unindexed_terms: bool,
    ) -> FightSearch:
        """One FiGHT search, checked against the terms it sent. It appends, in order, the
        excerpt warning, one ``term_not_indexed`` per sent term no technique holds (only
        when ``reports_unindexed_terms``, which only the direct search sets), then
        ``protocol_context_truncated``."""
        fight_outcome = require_matched_count(
            require_sent_terms(self._fight_source.search(fight_terms, limit), fight_terms)
        )
        source_outcome = self._summarize_fight(fight_outcome, warnings)
        if reports_unindexed_terms:
            for unindexed_term in fight_outcome.unindexed_terms:
                warnings.append(
                    TopicContextWarning(
                        code=TopicContextWarningCode.TERM_NOT_INDEXED, subject=unindexed_term
                    )
                )
        unlisted_technique_count = fight_outcome.matched_count - len(fight_outcome.items)
        if unlisted_technique_count:
            warnings.append(
                TopicContextWarning(
                    code=TopicContextWarningCode.PROTOCOL_CONTEXT_TRUNCATED,
                    subject=str(unlisted_technique_count),
                )
            )
        # A failed outcome carries no items or evidence (ThreatContextOutcome).
        return FightSearch(source_outcome, fight_outcome.items, fight_outcome.evidence)

    def _summarize_fight(
        self, fight_outcome: ThreatContextOutcome, warnings: list[TopicContextWarning]
    ) -> SourceOutcome:
        """Summarize from the outcome alone: its results and its snapshot travel together."""
        snapshot_info = fight_outcome.snapshot
        if snapshot_info is None:  # only a failed outcome names no snapshot
            return SourceOutcome(
                source=KnowledgeSource.MITRE_FIGHT,
                status=RESULT_STATUS_BY_SOURCE_FAILURE[fight_outcome.status],
                detail=describe_backend_failure(fight_outcome.failure),
            )
        if snapshot_info.coverage is SnapshotCoverage.EXCERPT:
            warnings.append(
                TopicContextWarning(
                    code=TopicContextWarningCode.SOURCE_SNAPSHOT_IS_EXCERPT,
                    subject=format_excerpt_warning_subject(snapshot_info.technique_count),
                )
            )
        return SourceOutcome(
            source=KnowledgeSource.MITRE_FIGHT,
            status=ResultStatus.OK if fight_outcome.items else ResultStatus.NO_MATCH,
            source_version=snapshot_info.source_version,
            coverage=snapshot_info.coverage,
        )

    def _assess_candidates(
        self, topic: ProtocolTopic, cve_searches: list[SearchResponse]
    ) -> tuple[list[TopicCandidate], int]:
        """Each CVE once, at its best search rank, tiered; unrelated ones are counted."""
        best_candidates: dict[str, Candidate] = {}
        channels_by_cve: dict[str, set[RetrievalChannel]] = {}
        for cve_search in cve_searches:
            for candidate in cve_search.candidates:
                cve_id = candidate.record.cve_id
                best_candidate = best_candidates.get(cve_id)
                if best_candidate is None or candidate.rank < best_candidate.rank:
                    best_candidates[cve_id] = candidate
                cve_channels = channels_by_cve.setdefault(cve_id, set())
                for channel_hit in candidate.channel_hits:
                    cve_channels.add(channel_hit.channel)
        assessed_candidates: list[TopicCandidate] = []
        dropped_count = 0
        for cve_id, candidate in best_candidates.items():
            relevance = assess_relevance(candidate.record, topic, channels_by_cve[cve_id])
            if relevance is None:
                dropped_count += 1
                continue
            ordered_channels: list[RetrievalChannel] = []
            for channel in RetrievalChannel:
                if channel in channels_by_cve[cve_id]:
                    ordered_channels.append(channel)
            assessed_candidates.append(
                TopicCandidate(
                    topic_rank=1,
                    candidate=candidate,
                    retrieval_channels=tuple(ordered_channels),
                    relevance=relevance,
                )
            )
        assessed_candidates.sort(key=tier_sort_key)
        ranked_candidates: list[TopicCandidate] = []
        for topic_rank, assessed_candidate in enumerate(assessed_candidates, start=1):
            ranked_candidates.append(
                assessed_candidate.model_copy(update={"topic_rank": topic_rank})
            )
        return ranked_candidates, dropped_count

    def _collect_evidence(
        self,
        fight_evidence: tuple[EvidenceAnchor, ...],
        cve_searches: list[SearchResponse],
        topic_candidates: list[TopicCandidate],
    ) -> tuple[EvidenceAnchor, ...]:
        cited_ids: set[str] = set()
        for topic_candidate in topic_candidates:
            cited_ids.update(topic_candidate.candidate.record.evidence_ids)
        anchors_by_id: dict[str, EvidenceAnchor] = {}
        for anchor in fight_evidence:
            anchors_by_id[anchor.evidence_id] = anchor
        for cve_search in cve_searches:
            for anchor in cve_search.evidence:
                if anchor.evidence_id in cited_ids:
                    anchors_by_id[anchor.evidence_id] = anchor
        ordered_anchors: list[EvidenceAnchor] = []
        for evidence_id in sorted(anchors_by_id):
            ordered_anchors.append(anchors_by_id[evidence_id])
        return tuple(ordered_anchors)

    def _seal(
        self,
        request: TopicContextRequest,
        resolution: TopicResolution,
        protocol_context: tuple[ThreatContextItem, ...],
        evidence: tuple[EvidenceAnchor, ...],
        topic_candidates: list[TopicCandidate],
        source_outcomes: list[SourceOutcome],
        warnings: list[TopicContextWarning],
        sent_fight_terms: Sequence[str] = (),
    ) -> TopicContextResponse:
        """The sealed, validated response; ``sent_fight_terms`` are the words a direct
        FiGHT search sent, none for a topic's exploration."""
        implementation_candidates: tuple[TopicCandidate, ...] = ()
        excluded_candidates: list[ExcludedCandidate] = []
        if request.scope is QueryScope.PROTOCOL_CONTEXT_ONLY:
            for topic_candidate in topic_candidates:
                excluded_candidates.append(
                    ExcludedCandidate(candidate=topic_candidate, reason=PROTOCOL_EXCLUSION_REASON)
                )
        else:
            implementation_candidates = tuple(topic_candidates)
        has_answer = bool(protocol_context or implementation_candidates)
        response_draft = TopicContextResponse(
            query=request.query,
            normalized_query=normalize_query(request.query),
            requested_scope=request.scope,
            status=decide_topic_status(request.scope, has_answer, source_outcomes),
            resolution=resolution,
            protocol_context=protocol_context,
            implementation_candidates=implementation_candidates,
            excluded_implementation_candidates=tuple(excluded_candidates),
            source_outcomes=tuple(source_outcomes),
            evidence=evidence,
            warnings=tuple(warnings),
            result_sha256=UNSEALED_SHA256,
        )
        response = response_draft.model_copy(
            update={"result_sha256": response_draft.compute_result_sha256()}
        )
        validate_topic_context_response(
            response,
            self._pinned_fight_snapshot,
            self._evidence_catalog,
            sent_fight_terms=sent_fight_terms,
        )
        return response
