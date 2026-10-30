"""Topic context: what is known about a protocol topic, kept apart by knowledge scope.

The caller states the scope it consumes. Protocol threat context (FiGHT) and
implementation vulnerabilities (CVEs) never share a section. Under
``protocol_context_only``, CVEs appear only as excluded candidates with the
reason, never as part of the protocol answer.
"""

from collections.abc import Iterable
from enum import StrEnum
from typing import Self

from pydantic import ConfigDict, Field, JsonValue, StrictBool, model_validator
from pydantic.config import JsonDict

from cve_kgrag.domain.affectedness import AffectednessDetail
from cve_kgrag.domain.contract_model import ContractModel
from cve_kgrag.domain.evidence import SHA256_PATTERN, EvidenceAnchor
from cve_kgrag.domain.hashing import canonical_sha256
from cve_kgrag.domain.search import (
    MAX_RESULTS_PER_CALL,
    SCHEMA_VERSION,
    Candidate,
    ChannelOutcome,
    JsonInteger,
    QueryText,
    SchemaVersion,
    SearchFilters,
)
from cve_kgrag.domain.taxonomy import (
    BackendFailureDetail,
    BackendStatus,
    ResultStatus,
    RetrievalChannel,
)
from cve_kgrag.domain.threat_context import SnapshotCoverage, ThreatContextItem
from cve_kgrag.domain.topic import RelevanceAssessment, TopicResolution


class QueryScope(StrEnum):
    PROTOCOL_CONTEXT_ONLY = "protocol_context_only"
    IMPLEMENTATION_ONLY = "implementation_only"
    MIXED = "mixed"


class TopicContextRequest(ContractModel):
    """A topic question. The scope has no default: the caller must choose it."""

    query: QueryText
    scope: QueryScope
    limit: JsonInteger = Field(
        default=10,
        ge=1,
        le=MAX_RESULTS_PER_CALL,
        description=(
            "Items each answer section keeps, after the relevance cut. Relevant CVEs the "
            "searches returned beyond it are counted by a candidates_truncated warning, "
            "and FiGHT techniques the snapshot matched beyond what the section lists by a "
            "protocol_context_truncated warning."
        ),
    )
    max_results_per_search: JsonInteger = Field(
        default=MAX_RESULTS_PER_CALL,
        ge=1,
        le=MAX_RESULTS_PER_CALL,
        description=(
            "Results any one backend search may return: each template CVE search, and the "
            "FiGHT search, which also asks for no more than limit. Each CVE search's own "
            "top-k is uncounted, so more matches may exist unseen, which a "
            "result_limit_reached warning says when a CVE search reached this limit; the "
            "FiGHT search counts every technique it matched (protocol_context_truncated)."
        ),
    )
    semantic: StrictBool = Field(
        default=False, description="Also run the optional semantic channel for CVE candidates."
    )
    filters: SearchFilters = Field(
        default_factory=SearchFilters,
        description="Constrains every template CVE search; FiGHT is never filtered.",
    )


class TopicCandidate(ContractModel):
    topic_rank: int = Field(
        ge=1, description="Order by relevance tier, then search rank, then CVE ID."
    )
    candidate: Candidate = Field(description="The candidate from its best-ranked search.")
    retrieval_channels: tuple[RetrievalChannel, ...] = Field(
        min_length=1, description="Every channel that retrieved the record, in any template."
    )
    relevance: RelevanceAssessment


class ExcludedCandidate(ContractModel):
    candidate: TopicCandidate
    reason: str = Field(min_length=1)


class KnowledgeSource(StrEnum):
    CVE_SEARCH = "cve_search"
    MITRE_FIGHT = "mitre_fight"
    # Whether a named product is affected. No adapter serves it, so an
    # investigation that needs it reports it unavailable.
    AFFECTEDNESS = "affectedness"


# Sources whose results form the answer for a scope; the status is decided over these alone.
ANSWER_SOURCES_BY_SCOPE = {
    QueryScope.PROTOCOL_CONTEXT_ONLY: frozenset({KnowledgeSource.MITRE_FIGHT}),
    QueryScope.IMPLEMENTATION_ONLY: frozenset({KnowledgeSource.CVE_SEARCH}),
    QueryScope.MIXED: frozenset({KnowledgeSource.MITRE_FIGHT, KnowledgeSource.CVE_SEARCH}),
}


# The statuses of a source that answered, with results or without.
SERVED_STATUSES = frozenset({ResultStatus.OK, ResultStatus.NO_MATCH})


def list_enum_values(*enums: type[StrEnum]) -> list[JsonValue]:
    """The values of ``enums`` in order, then ``None``: a nullable closed set of sentences."""
    enum_values: list[JsonValue] = []
    for sentence_enum in enums:
        for member in sentence_enum:
            enum_values.append(member.value)
    enum_values.append(None)
    return enum_values


def describe_detail_when_failed(served_statuses: list[JsonValue]) -> JsonDict:
    """JSON Schema: no ``detail`` when the source answered, and one when it did not."""
    return {
        "if": {"properties": {"status": {"enum": served_statuses}}},
        "then": {"properties": {"detail": {"type": "null"}}},
        "else": {"required": ["detail"], "properties": {"detail": {"not": {"type": "null"}}}},
    }


def describe_source_outcome_shape() -> JsonDict:
    """``SourceOutcome``'s validators as JSON Schema: ``check_snapshot_only_when_served``
    and ``check_failure_fits_source``."""
    served_statuses: list[JsonValue] = []
    for status in ResultStatus:
        if status in SERVED_STATUSES:
            served_statuses.append(status.value)
    return {
        "allOf": [
            {
                "if": {"properties": {"status": {"enum": served_statuses}}},
                "else": {
                    "properties": {"source_version": {"type": "null"}, "coverage": {"type": "null"}}
                },
            },
            {
                "if": {"properties": {"source": {"const": KnowledgeSource.AFFECTEDNESS.value}}},
                "then": {
                    "properties": {
                        "detail": {"enum": list_enum_values(AffectednessDetail)},
                        "channel_failures": {"maxItems": 0},
                    },
                    **describe_detail_when_failed(served_statuses),
                },
            },
            {
                "if": {"properties": {"source": {"const": KnowledgeSource.MITRE_FIGHT.value}}},
                "then": {
                    "properties": {
                        "detail": {"enum": list_enum_values(BackendFailureDetail)},
                        "channel_failures": {"maxItems": 0},
                    },
                    **describe_detail_when_failed(served_statuses),
                },
            },
            {
                "if": {"properties": {"source": {"const": KnowledgeSource.CVE_SEARCH.value}}},
                "then": {
                    "properties": {
                        "detail": {"type": "null"},
                        "channel_failures": {
                            "items": {
                                "properties": {"status": {"not": {"const": BackendStatus.OK.value}}}
                            }
                        },
                    }
                },
            },
        ]
    }


class SourceOutcome(ContractModel):
    """What one knowledge source answered. Every word of it is the server's: a failed
    FiGHT source and the affectedness source carry one of the server's sentences in
    ``detail``, and a CVE search lists its channels' failures in ``channel_failures``."""

    model_config = ConfigDict(json_schema_extra=describe_source_outcome_shape())

    source: KnowledgeSource
    status: ResultStatus
    detail: AffectednessDetail | BackendFailureDetail | None = Field(
        default=None,
        description=(
            "The server's sentence for why the source gave no answer: an AffectednessDetail "
            "for affectedness, a BackendFailureDetail for mitre_fight, and null for "
            "cve_search, whose failures are its channel_failures."
        ),
    )
    channel_failures: tuple[ChannelOutcome, ...] = Field(
        default=(),
        json_schema_extra={"uniqueItems": True},
        description=(
            "Each distinct failure of a cve_search's channels, once; a channel that failed "
            "in different ways appears once per way. Empty for other sources."
        ),
    )
    source_version: str | None = Field(
        default=None, description="Snapshot identity of the source consulted, when it has one."
    )
    coverage: SnapshotCoverage | None = Field(
        default=None,
        description=(
            "The coverage type of the snapshot consulted: full for the whole catalogued "
            "upstream file, excerpt for a reviewed cut of one. It never says the response "
            "lists every match; truncation warnings say what a limit left out."
        ),
    )

    @model_validator(mode="after")
    def check_snapshot_only_when_served(self) -> Self:
        is_served = self.status in SERVED_STATUSES
        names_snapshot = self.source_version is not None or self.coverage is not None
        if names_snapshot and not is_served:
            raise ValueError("a failed source outcome cannot name a snapshot or coverage")
        return self

    @model_validator(mode="after")
    def check_failure_fits_source(self) -> Self:
        """``detail`` is a sentence of the source's own kind, set for FiGHT and affectedness
        exactly when the source did not answer, and only a CVE search lists channel
        failures, each distinct failure once and each a failed channel."""
        if self.source is KnowledgeSource.AFFECTEDNESS:
            detail_type: type[StrEnum] | None = AffectednessDetail
        elif self.source is KnowledgeSource.MITRE_FIGHT:
            detail_type = BackendFailureDetail
        else:
            detail_type = None
        if self.detail is not None and (
            detail_type is None or not isinstance(self.detail, detail_type)
        ):
            raise ValueError(f"a {self.source} outcome cannot carry that detail")
        is_served = self.status in SERVED_STATUSES
        if detail_type is not None and (self.detail is None) != is_served:
            raise ValueError(
                f"a {self.source} outcome carries a detail exactly when the source did not answer"
            )
        if self.channel_failures and self.source is not KnowledgeSource.CVE_SEARCH:
            raise ValueError("only a cve_search outcome names failing channels")
        if len(set(self.channel_failures)) != len(self.channel_failures):
            raise ValueError("a source outcome names each channel failure once")
        for channel_failure in self.channel_failures:
            if channel_failure.status is BackendStatus.OK:
                raise ValueError("channel_failures holds only channels that failed")
        return self


def format_excerpt_warning_subject(technique_count: int) -> str:
    return f"{KnowledgeSource.MITRE_FIGHT.value}: excerpt of {technique_count} techniques"


FAILURE_PRECEDENCE = (
    ResultStatus.BACKEND_ERROR,
    ResultStatus.INCOMPLETE_INDEX,
    ResultStatus.SOURCE_UNAVAILABLE,
    ResultStatus.POLICY_BLOCKED,
)


def summarize_statuses(statuses: Iterable[ResultStatus], has_results: bool) -> ResultStatus:
    """One status for several calls: ``partial`` when anything succeeded beside a failure."""
    status_list = list(statuses)
    failed_statuses: list[ResultStatus] = []
    for status in status_list:
        if status not in {ResultStatus.OK, ResultStatus.NO_MATCH}:
            failed_statuses.append(status)
    if not failed_statuses:
        return ResultStatus.OK if has_results else ResultStatus.NO_MATCH
    has_success = any(status not in FAILURE_PRECEDENCE for status in status_list)
    if has_results or has_success:
        return ResultStatus.PARTIAL
    for status in FAILURE_PRECEDENCE:
        if status in failed_statuses:
            return status
    return ResultStatus.PARTIAL


def decide_topic_status(
    scope: QueryScope, has_answer: bool, source_outcomes: Iterable[SourceOutcome]
) -> ResultStatus:
    """The response status, decided over the sources that form the answer for the scope."""
    answer_statuses: list[ResultStatus] = []
    for outcome in source_outcomes:
        if outcome.source in ANSWER_SOURCES_BY_SCOPE[scope]:
            answer_statuses.append(outcome.status)
    return summarize_statuses(answer_statuses, has_answer)


def list_consulted_sources(scope: QueryScope) -> tuple[KnowledgeSource, ...]:
    """Sources a resolved topic consults, in order: CVEs are always retrieved."""
    if scope is QueryScope.IMPLEMENTATION_ONLY:
        return (KnowledgeSource.CVE_SEARCH,)
    return (KnowledgeSource.MITRE_FIGHT, KnowledgeSource.CVE_SEARCH)


class TopicContextWarningCode(StrEnum):
    TOPIC_NOT_RESOLVED = "topic_not_resolved"
    EXCLUDED_TERM = "excluded_term"
    ADDITIONAL_TOPIC_NOT_EXPLORED = "additional_topic_not_explored"
    UNRELATED_CANDIDATES_DROPPED = "unrelated_candidates_dropped"
    SOURCE_SNAPSHOT_IS_EXCERPT = "source_snapshot_is_excerpt"
    TERM_NOT_INDEXED = "term_not_indexed"
    PROTOCOL_CONTEXT_TRUNCATED = "protocol_context_truncated"
    CANDIDATES_TRUNCATED = "candidates_truncated"
    RESULT_LIMIT_REACHED = "result_limit_reached"


# The order warnings appear in; codes of one position may interleave among themselves.
TOPIC_WARNING_ORDER = {
    TopicContextWarningCode.EXCLUDED_TERM: 0,
    TopicContextWarningCode.TOPIC_NOT_RESOLVED: 1,
    TopicContextWarningCode.ADDITIONAL_TOPIC_NOT_EXPLORED: 1,
    TopicContextWarningCode.SOURCE_SNAPSHOT_IS_EXCERPT: 2,
    TopicContextWarningCode.TERM_NOT_INDEXED: 3,
    TopicContextWarningCode.PROTOCOL_CONTEXT_TRUNCATED: 4,
    TopicContextWarningCode.UNRELATED_CANDIDATES_DROPPED: 5,
    TopicContextWarningCode.CANDIDATES_TRUNCATED: 6,
    TopicContextWarningCode.RESULT_LIMIT_REACHED: 7,
}
# The codes whose subject is a positive decimal number, each given at most once: a count,
# or for result_limit_reached the per-search limit.
TOPIC_COUNT_WARNING_CODES = (
    TopicContextWarningCode.PROTOCOL_CONTEXT_TRUNCATED,
    TopicContextWarningCode.UNRELATED_CANDIDATES_DROPPED,
    TopicContextWarningCode.CANDIDATES_TRUNCATED,
    TopicContextWarningCode.RESULT_LIMIT_REACHED,
)


class TopicContextWarning(ContractModel):
    """What a response leaves out or could not do. ``protocol_context_truncated`` counts
    the techniques the snapshot matched that the protocol section does not list because
    of the response's bounds; ``candidates_truncated`` the relevant CVEs topic context
    held that the candidate section does not list only because of its limit, never a
    backend's own uncounted matches; ``unrelated_candidates_dropped`` the candidates the
    relevance rule removed. ``term_not_indexed`` names a word a direct FiGHT search sent
    that no technique holds; a topic's card search never raises it.
    ``result_limit_reached`` names ``max_results_per_search`` when a card's CVE search
    warned it reached that limit, so more matches may exist; it never counts them. A cut changes no
    status."""

    code: TopicContextWarningCode
    subject: str


class TopicContextResponse(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    query: str
    normalized_query: str
    requested_scope: QueryScope
    status: ResultStatus
    resolution: TopicResolution
    protocol_context: tuple[ThreatContextItem, ...] = Field(
        description="Threat context for the topic; empty under implementation_only."
    )
    implementation_candidates: tuple[TopicCandidate, ...] = Field(
        description="CVE candidates; empty under protocol_context_only."
    )
    excluded_implementation_candidates: tuple[ExcludedCandidate, ...] = Field(
        description="CVEs kept out of a protocol_context_only answer, with the reason."
    )
    source_outcomes: tuple[SourceOutcome, ...]
    evidence: tuple[EvidenceAnchor, ...] = Field(
        description="Every anchor the items and candidates cite, ordered by evidence_id."
    )
    warnings: tuple[TopicContextWarning, ...]
    result_sha256: str = Field(
        pattern=SHA256_PATTERN,
        description=(
            "SHA-256 of the canonical JSON of this response without this field; the server "
            "recomputes it and rejects a mismatch."
        ),
    )

    def compute_result_sha256(self) -> str:
        return canonical_sha256(self.model_dump(mode="json", exclude={"result_sha256"}))
