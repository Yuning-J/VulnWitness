"""Vulnerability search over injected repositories and retrieval channels."""

from collections.abc import Set

from vulnwitness.application.channel_log import ChannelLog
from vulnwitness.application.cve_lookup import build_cve_lookup
from vulnwitness.application.fusion import FusedCandidate, fuse_channel_results
from vulnwitness.domain.cnvd import CnvdCapability, CnvdIndex
from vulnwitness.domain.cve import CveRecord
from vulnwitness.domain.cve_lookup import CveLookupResponse
from vulnwitness.domain.evidence import EvidenceAnchor
from vulnwitness.domain.evidence_catalog import EvidenceCatalog
from vulnwitness.domain.hashing import UNSEALED_SHA256
from vulnwitness.domain.kev import KevCapability
from vulnwitness.domain.relations import record_relations
from vulnwitness.domain.search import (
    SEMANTIC_UNAVAILABLE_FAILURES,
    Candidate,
    ChannelOutcome,
    MatchedField,
    RetrievalMatch,
    RetrievalOutcome,
    ScopeAssessment,
    SearchFilters,
    SearchRequest,
    SearchResponse,
    SearchWarningCode,
    SemanticUnavailableDetail,
    UnsupportedFilter,
)
from vulnwitness.domain.taxonomy import (
    BackendFailure,
    BackendStatus,
    KnowledgeScope,
    ResultStatus,
    RetrievalChannel,
)
from vulnwitness.domain.text import (
    extract_search_text,
    find_cve_ids,
    normalize_query,
    tokenize,
)
from vulnwitness.domain.validation import EvidenceValidationError, validate_search_response
from vulnwitness.domain.weakness_associations import WeaknessSnapshotCapability
from vulnwitness.domain.weakness_mapping import WeaknessMapping
from vulnwitness.ports.repositories import CveRepository
from vulnwitness.ports.retrieval import (
    GraphRetriever,
    LexicalRetriever,
    SemanticRetriever,
    StructuredRetriever,
)

CVE_SCOPE_ASSESSMENT = ScopeAssessment(
    scope=KnowledgeScope.IMPLEMENTATION_VULNERABILITY,
    basis="A CVE describes an implementation vulnerability, never a protocol-design flaw.",
)
UNCONFIGURED_SEMANTIC = RetrievalOutcome(
    status=BackendStatus.UNAVAILABLE, failure=BackendFailure.NOT_CONFIGURED
)


class SearchService:
    """Answers a search with ranked, evidence-anchored CVE candidates.

    The CVE IDs a query names are looked up exactly; the lexical and semantic channels
    read its search text (``extract_search_text``), without those IDs or the low-signal
    words ``cve`` and ``cves``, and run only when that text holds a search term. Active
    filters constrain every channel and never supply a candidate themselves. If the
    structured backend fails, the search returns no candidates rather than unfiltered
    ones. A response whose channels matched more candidates than the request's limit, or
    one of whose ranked channels (lexical, semantic or graph) returned that many, its own
    top-k, warns ``result_limit_reached``. Raises
    ``UnsupportedFilter`` for a ``purls`` filter when no record names a package URL
    (``require_executable_filters``), and ``EvidenceValidationError`` instead of returning
    a response that cites a record the repository does not hold, or serves a record or
    anchor that differs from the evidence catalog's.
    """

    def __init__(
        self,
        cve_repository: CveRepository,
        evidence_catalog: EvidenceCatalog,
        lexical_retriever: LexicalRetriever,
        structured_retriever: StructuredRetriever,
        graph_retriever: GraphRetriever,
        semantic_retriever: SemanticRetriever | SemanticUnavailableDetail | None = None,
        weakness_mapping: WeaknessMapping | None = None,
        cnvd_index: CnvdIndex | None = None,
        cnvd_attribution: str | None = None,
        cnvd_language: str | None = None,
        kev_capability: KevCapability | None = None,
    ) -> None:
        self._kev_capability = kev_capability or KevCapability(imported=False)
        self._cnvd_index = cnvd_index or CnvdIndex()
        self._cnvd_attribution = cnvd_attribution
        self._cnvd_language = cnvd_language
        self._weakness_mapping = weakness_mapping
        self._cve_repository = cve_repository
        self._evidence_catalog = evidence_catalog
        self._lexical_retriever = lexical_retriever
        self._structured_retriever = structured_retriever
        self._graph_retriever = graph_retriever
        self._semantic_retriever = semantic_retriever

    def describe_weakness_snapshot(self) -> WeaknessSnapshotCapability | None:
        """The mapping served by lookup, separately from retrieval capabilities."""
        return None if self._weakness_mapping is None else self._weakness_mapping.describe()

    def describe_kev(self) -> KevCapability:
        return self._kev_capability

    def describe_cnvd(self) -> CnvdCapability:
        """Whether the store imported CNVD, including imports with no retained entries."""
        revision = self._cnvd_index.imported_revision
        return CnvdCapability(imported=revision is not None, revision=revision)

    def describe_cnvd_attribution(self) -> str | None:
        """Registry credit for instructions exactly when the corpus holds CNVD entries."""
        if self._cnvd_index.cve_id_by_cnvd_id:
            return self._cnvd_attribution
        return None

    def lookup(self, cve_id: str) -> CveLookupResponse:
        """Look up a boundary-validated CVE or CNVD ID with source comparisons and paths."""
        identifier = cve_id
        if identifier.startswith("CNVD-"):
            cve_id = self._cnvd_index.cve_id_by_cnvd_id.get(identifier, "")
        if cve_id:
            search_response = self.search(SearchRequest(query=cve_id, limit=1))
        else:
            channel_log = ChannelLog()
            channel_log.record(RetrievalChannel.EXACT_ID, RetrievalOutcome(status=BackendStatus.OK))
            search_response = self._seal(
                SearchRequest(query=identifier, limit=1),
                normalize_query(identifier),
                channel_log,
                (),
            )
        candidates: list[Candidate] = []
        for candidate in search_response.candidates:
            candidates.append(
                candidate.model_copy(
                    update={
                        "weakness_associations": self._evidence_catalog.get_weakness_associations(
                            candidate.record.cve_id
                        )
                    }
                )
            )
        draft = search_response.model_copy(update={"candidates": tuple(candidates)})
        response = draft.model_copy(update={"result_sha256": draft.compute_result_sha256()})
        validate_search_response(response, self._evidence_catalog)
        return build_cve_lookup(
            response,
            identifier,
            cve_id,
            self._cnvd_index,
            self._evidence_catalog,
            self._cnvd_attribution,
            self._cnvd_language,
        )

    def has_semantic_channel(self) -> bool:
        """Whether a semantic retriever is wired; it may still report a search failed."""
        return self._semantic_retriever is not None and not isinstance(
            self._semantic_retriever, SemanticUnavailableDetail
        )

    def find_semantic_unavailable_detail(self) -> SemanticUnavailableDetail | None:
        """Why an enabled semantic channel cannot search; ``None`` when it can, or when no
        semantic channel is configured."""
        if isinstance(self._semantic_retriever, SemanticUnavailableDetail):
            return self._semantic_retriever
        return None

    def serves_purl_filter(self) -> bool:
        """Whether a ``purls`` filter can be executed: some record names a package URL."""
        return self._structured_retriever.holds_package_urls()

    def require_executable_filters(self, filters: SearchFilters) -> None:
        """Raise ``UnsupportedFilter`` for a ``purls`` filter over records that name no
        package URL: it could match nothing, and an answer of no match would read as no
        vulnerability for that package."""
        if filters.purls and not self.serves_purl_filter():
            raise UnsupportedFilter("purls")

    def search(self, request: SearchRequest) -> SearchResponse:
        self.require_executable_filters(request.filters)
        normalized_query = normalize_query(request.query)
        requested_cve_ids = find_cve_ids(request.query)
        search_text = extract_search_text(request.query)
        channel_log = ChannelLog()

        allowed_cve_ids: frozenset[str] | None = None
        if request.filters.is_active():
            structured_outcome = self._require_admissible(
                self._structured_retriever.search(request.filters),
                None,
                request.filters.list_match_terms(),
            )
            channel_log.record(RetrievalChannel.STRUCTURED, structured_outcome)
            if structured_outcome.status is not BackendStatus.OK:
                return self._seal(request, normalized_query, channel_log, ())
            allowed_cve_ids = collect_match_ids(structured_outcome.matches)

        if requested_cve_ids:
            self._lookup_exact(requested_cve_ids, allowed_cve_ids, channel_log)
        # The text channels need searchable terms beyond the CVE IDs: a text of nothing
        # but IDs, ID likenesses, stopwords and low-signal words carries no meaning to
        # match or embed.
        search_terms = frozenset(tokenize(search_text))
        has_search_terms = bool(search_terms)
        if has_search_terms:
            lexical_outcome = self._lexical_retriever.search(
                search_text, request.limit, allowed_cve_ids
            )
            channel_log.record(
                RetrievalChannel.LEXICAL,
                self._require_admissible(lexical_outcome, allowed_cve_ids, search_terms),
            )
            # A search term no record holds matches nothing and lets no generic term
            # answer in its place, so the response names it.
            for unindexed_term in lexical_outcome.unindexed_terms:
                channel_log.warn(SearchWarningCode.TERM_NOT_INDEXED, unindexed_term)
        elif not requested_cve_ids:
            channel_log.warn(SearchWarningCode.NO_SEARCHABLE_TERMS, normalized_query)
        if request.semantic and has_search_terms:
            semantic_outcome = self._search_semantic(search_text, request, allowed_cve_ids)
            channel_log.record(
                RetrievalChannel.SEMANTIC,
                self._require_admissible(semantic_outcome, allowed_cve_ids, frozenset()),
            )
        seed_ids = channel_log.list_seed_ids()
        if request.graph_expand and seed_ids:
            graph_outcome = self._graph_retriever.expand(seed_ids, request.limit, allowed_cve_ids)
            channel_log.record(
                RetrievalChannel.GRAPH,
                self._require_admissible_graph(graph_outcome, allowed_cve_ids, seed_ids),
            )

        all_fused = fuse_channel_results(channel_log.channel_results)
        # Matches beyond the limit are cut here, and a channel that returned its whole
        # top-k may have cut further ones it never counts, so the warning says only that
        # the limit was reached. A channel that returned fewer than its top-k, like an
        # exact lookup, has nothing beyond what it returned.
        if len(all_fused) > request.limit or channel_log.fills_top_k(request.limit):
            channel_log.warn(SearchWarningCode.RESULT_LIMIT_REACHED, str(request.limit))
        fused = all_fused[: request.limit]
        return self._seal(request, normalized_query, channel_log, self._build_candidates(fused))

    def _require_admissible(
        self,
        outcome: RetrievalOutcome,
        allowed_cve_ids: Set[str] | None,
        vouched_terms: frozenset[str],
    ) -> RetrievalOutcome:
        """Pass the outcome of a channel other than the graph through, or raise if a match
        is unstored, outside the filters, names a term outside ``vouched_terms`` (what the
        search sent the channel) or carries graph paths, or if the outcome names an
        unindexed term outside ``vouched_terms``.

        Every match is checked, not only those that survive the limit, so an integrity
        violation never depends on rank. A violation names the record only, never the
        retriever's text.
        """
        for match in outcome.matches:
            if match.graph_paths:
                raise EvidenceValidationError(
                    [f"a retriever other than the graph gave {match.cve_id} graph paths"]
                )
            self._require_match_admissible(match, allowed_cve_ids, vouched_terms)
        for unindexed_term in outcome.unindexed_terms:
            if unindexed_term not in vouched_terms:
                raise EvidenceValidationError(
                    ["a retriever named an unindexed term the search did not send"]
                )
        return outcome

    def _require_admissible_graph(
        self, outcome: RetrievalOutcome, allowed_cve_ids: Set[str] | None, seed_ids: tuple[str, ...]
    ) -> RetrievalOutcome:
        """Pass the graph outcome through, or raise unless every path starts at a seed and
        names a relation both the seed and the hit record assert (``record_relations``),
        and every matched term is one of those relation values."""
        for match in outcome.matches:
            hit_record = self._cve_repository.get_cve(match.cve_id)
            hit_relations = record_relations(hit_record) if hit_record is not None else frozenset()
            path_values: set[str] = set()
            for graph_path in match.graph_paths:
                seed_record = (
                    self._cve_repository.get_cve(graph_path.seed_cve_id)
                    if graph_path.seed_cve_id in seed_ids
                    else None
                )
                relation = (graph_path.relation, graph_path.value)
                if (
                    seed_record is None
                    or relation not in record_relations(seed_record)
                    or relation not in hit_relations
                ):
                    raise EvidenceValidationError(
                        [f"the graph reached {match.cve_id} by a relation the records lack"]
                    )
                path_values.add(graph_path.value)
            self._require_match_admissible(match, allowed_cve_ids, frozenset(path_values))
        return outcome

    def _require_match_admissible(
        self,
        match: RetrievalMatch,
        allowed_cve_ids: Set[str] | None,
        vouched_terms: frozenset[str],
    ) -> None:
        if self._cve_repository.get_cve(match.cve_id) is None:
            raise EvidenceValidationError(
                [f"a retriever returned {match.cve_id}, which no repository holds"]
            )
        if allowed_cve_ids is not None and match.cve_id not in allowed_cve_ids:
            raise EvidenceValidationError(
                [f"a retriever returned {match.cve_id}, which the active filters exclude"]
            )
        for matched_field in match.matched_fields:
            # Checked as well as typed: an adapter can build a match without validation.
            if not isinstance(matched_field, MatchedField):
                raise EvidenceValidationError(
                    [f"a retriever matched {match.cve_id} in an unknown field"]
                )
        for matched_term in match.matched_terms:
            if matched_term not in vouched_terms:
                raise EvidenceValidationError(
                    [f"a retriever explained {match.cve_id} with a term the search did not send"]
                )

    def _search_semantic(
        self, query_text: str, request: SearchRequest, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        if self._semantic_retriever is None:
            return UNCONFIGURED_SEMANTIC
        if isinstance(self._semantic_retriever, SemanticUnavailableDetail):
            return RetrievalOutcome(
                status=BackendStatus.UNAVAILABLE,
                failure=SEMANTIC_UNAVAILABLE_FAILURES[self._semantic_retriever],
            )
        return self._semantic_retriever.search(query_text, request.limit, allowed_cve_ids)

    def _seal(
        self,
        request: SearchRequest,
        normalized_query: str,
        channel_log: ChannelLog,
        candidates: tuple[Candidate, ...],
    ) -> SearchResponse:
        response_draft = SearchResponse(
            query=request.query,
            normalized_query=normalized_query,
            status=self._response_status(bool(candidates), channel_log.channel_outcomes),
            channels_executed=tuple(channel_log.channels_executed),
            channel_outcomes=tuple(channel_log.channel_outcomes),
            candidates=candidates,
            evidence=self._collect_evidence(candidates),
            warnings=tuple(channel_log.warnings),
            result_sha256=UNSEALED_SHA256,
        )
        response = response_draft.model_copy(
            update={"result_sha256": response_draft.compute_result_sha256()}
        )
        validate_search_response(response, self._evidence_catalog)
        return response

    def _response_status(
        self, has_candidates: bool, outcomes: list[ChannelOutcome]
    ) -> ResultStatus:
        """Typed status. The structured channel only constrains, so its success alone
        never turns a failed retrieval into ``partial``."""
        failed_statuses: list[BackendStatus] = []
        for outcome in outcomes:
            if outcome.status is not BackendStatus.OK:
                failed_statuses.append(outcome.status)
        has_successful_retrieval = any(
            outcome.status is BackendStatus.OK
            and outcome.channel is not RetrievalChannel.STRUCTURED
            for outcome in outcomes
        )
        if not failed_statuses:
            return ResultStatus.OK if has_candidates else ResultStatus.NO_MATCH
        if has_candidates or has_successful_retrieval:
            return ResultStatus.PARTIAL
        if BackendStatus.ERROR in failed_statuses:
            return ResultStatus.BACKEND_ERROR
        if BackendStatus.INCOMPLETE_INDEX in failed_statuses:
            return ResultStatus.INCOMPLETE_INDEX
        return ResultStatus.SOURCE_UNAVAILABLE

    def _lookup_exact(
        self, cve_ids: list[str], allowed_cve_ids: Set[str] | None, channel_log: ChannelLog
    ) -> None:
        matches: list[RetrievalMatch] = []
        for cve_id in cve_ids:
            if self._cve_repository.get_cve(cve_id) is None:
                channel_log.warn(SearchWarningCode.UNKNOWN_CVE_ID, cve_id)
            elif allowed_cve_ids is not None and cve_id not in allowed_cve_ids:
                channel_log.warn(SearchWarningCode.EXCLUDED_BY_FILTERS, cve_id)
            else:
                matches.append(
                    RetrievalMatch(
                        cve_id=cve_id,
                        score=1.0,
                        matched_fields=("cve_id",),
                        matched_terms=(cve_id,),
                    )
                )
        channel_log.record(
            RetrievalChannel.EXACT_ID,
            RetrievalOutcome(status=BackendStatus.OK, matches=tuple(matches)),
        )

    def _build_candidates(self, fused: list[FusedCandidate]) -> tuple[Candidate, ...]:
        candidates: list[Candidate] = []
        for rank, fused_candidate in enumerate(fused, start=1):
            record = self._require_record(fused_candidate.cve_id)
            candidates.append(
                Candidate(
                    rank=rank,
                    record=record,
                    relevance_score=fused_candidate.relevance_score,
                    channel_hits=tuple(fused_candidate.channel_hits),
                    scope_assessment=CVE_SCOPE_ASSESSMENT,
                    missing_fields=record.find_missing_fields(),
                )
            )
        return tuple(candidates)

    def _require_record(self, cve_id: str) -> CveRecord:
        record = self._cve_repository.get_cve(cve_id)
        if record is None:
            raise EvidenceValidationError([f"{cve_id} is not held by the repository"])
        return record

    def _collect_evidence(self, candidates: tuple[Candidate, ...]) -> tuple[EvidenceAnchor, ...]:
        anchors_by_id: dict[str, EvidenceAnchor] = {}
        for candidate in candidates:
            for evidence_id in candidate.record.evidence_ids:
                anchor = self._evidence_catalog.get_evidence(evidence_id)
                if anchor is None:
                    cve_id = candidate.record.cve_id
                    raise EvidenceValidationError(
                        [f"{cve_id} cites unstored evidence {evidence_id}"]
                    )
                anchors_by_id[evidence_id] = anchor
        ordered_anchors: list[EvidenceAnchor] = []
        for evidence_id in sorted(anchors_by_id):
            ordered_anchors.append(anchors_by_id[evidence_id])
        return tuple(ordered_anchors)


def collect_match_ids(matches: tuple[RetrievalMatch, ...]) -> frozenset[str]:
    cve_ids: set[str] = set()
    for match in matches:
        cve_ids.add(match.cve_id)
    return frozenset(cve_ids)
