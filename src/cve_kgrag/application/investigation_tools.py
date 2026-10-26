"""The allowlisted investigation tools, run against the search and topic-context services.

Every call runs under the request's filters, semantic flag and per-call result cap;
a plan cannot change them. The cap bounds every backend search a call sends,
including each template search a ``topic_context`` call fans out to, and each step
records those searches as built from the same requests the tools run. A response
that fails its own evidence validation is recorded as an integrity failure, never
used as partial data.
"""

from dataclasses import dataclass
from typing import Literal

from cve_kgrag.application.investigation_policy import count_tool_calls
from cve_kgrag.application.search import SearchService
from cve_kgrag.application.topic_context import (
    TopicContextService,
    build_template_searches,
    consults_fight,
    decide_fight_search_limit,
    list_channel_failures,
    list_topic_terms,
)
from cve_kgrag.domain.evidence import EvidenceAnchor
from cve_kgrag.domain.hashing import canonical_json_bytes
from cve_kgrag.domain.investigation import (
    BackendRequest,
    CveBackendRequest,
    FightBackendRequest,
    InvestigationRequest,
    StepAdmission,
    StepReason,
    ToolStep,
)
from cve_kgrag.domain.planning import (
    CveExactLookupCall,
    CveSearchCall,
    PlannerKind,
    ToolCall,
    TopicContextCall,
    compute_call_key,
    format_cve_tool_query,
    list_tool_sources,
)
from cve_kgrag.domain.search import SearchRequest, SearchResponse, SearchWarning
from cve_kgrag.domain.taxonomy import ResultStatus, RetrievalChannel
from cve_kgrag.domain.topic import ProtocolTopic
from cve_kgrag.domain.topic_context import (
    KnowledgeSource,
    SourceOutcome,
    TopicContextRequest,
    TopicContextResponse,
    TopicContextWarning,
)
from cve_kgrag.domain.validation import EvidenceValidationError
from cve_kgrag.topics.registry import TopicRegistry


@dataclass(frozen=True)
class ToolExecution:
    """What one call returned: exactly one response, or the integrity violations it raised.
    A topic call also hands over the CVE IDs its response left out at its limit, which
    the answer counts as truncated and the sealed set does not carry; replay derives them
    again from the sources."""

    search_response: SearchResponse | None
    topic_response: TopicContextResponse | None
    integrity_violations: tuple[str, ...]
    context_bytes: int
    omitted_topic_cve_ids: tuple[str, ...] = ()

    def result_sha256(self) -> str | None:
        if self.search_response is not None:
            return self.search_response.result_sha256
        if self.topic_response is not None:
            return self.topic_response.result_sha256
        return None


# A call abandoned at the deadline left no response to record.
ABANDONED_CALL_EXECUTION = ToolExecution(None, None, (), 0)


class ToolExecutor:
    def __init__(
        self,
        search_service: SearchService,
        topic_context_service: TopicContextService,
        topic_registry: TopicRegistry,
    ) -> None:
        self._search_service = search_service
        self._topic_context_service = topic_context_service
        self._topic_registry = topic_registry

    def execute(self, call: ToolCall, request: InvestigationRequest) -> ToolExecution:
        try:
            if isinstance(call, TopicContextCall):
                topic = self._topic_registry.require_topic(call.topic_id)
                topic_exploration = self._topic_context_service.explore_with_omissions(
                    build_topic_request(topic, request)
                )
                topic_response = topic_exploration.response
                return ToolExecution(
                    None,
                    topic_response,
                    (),
                    measure_context_bytes(topic_response),
                    topic_exploration.omitted_cve_ids,
                )
            search_response = self._search_service.search(build_search_request(call, request))
        except EvidenceValidationError as error:
            # A source returned evidence that failed integrity; it is an observation,
            # never partial data.
            return ToolExecution(None, None, error.violations, 0)
        return build_search_execution(search_response)


def list_backend_requests(
    call: ToolCall, request: InvestigationRequest, topic_registry: TopicRegistry
) -> tuple[BackendRequest, ...]:
    """The searches a call sends, in the order it sends them, from the same request
    builders the executor runs it with: a CVE tool's one search, or a topic's FiGHT search
    (unless the scope is ``implementation_only``) then one search per card query template.
    Raises ``LookupError`` for a topic the registry does not hold."""
    if not isinstance(call, TopicContextCall):
        search_request = build_search_request(call, request)
        return (record_cve_request(search_request),)
    topic = topic_registry.require_topic(call.topic_id)
    topic_request = build_topic_request(topic, request)
    backend_requests: list[BackendRequest] = []
    if consults_fight(topic_request.scope):
        backend_requests.append(
            FightBackendRequest(
                source=KnowledgeSource.MITRE_FIGHT,
                terms=tuple(list_topic_terms(topic)),
                limit=decide_fight_search_limit(topic_request),
            )
        )
    for template_search in build_template_searches(topic, topic_request):
        backend_requests.append(record_cve_request(template_search))
    return tuple(backend_requests)


def build_search_request(
    call: CveExactLookupCall | CveSearchCall, request: InvestigationRequest
) -> SearchRequest:
    """A CVE tool's one search; an exact lookup never runs the semantic channel."""
    return SearchRequest(
        query=format_cve_tool_query(call),
        limit=request.budget.max_results_per_call,
        filters=request.filters,
        semantic=request.semantic and isinstance(call, CveSearchCall),
    )


def build_topic_request(topic: ProtocolTopic, request: InvestigationRequest) -> TopicContextRequest:
    """The topic exploration, asked by the card's canonical name, which resolves to the card
    itself; the result cap bounds each section and every search it fans out to."""
    max_results_per_call = request.budget.max_results_per_call
    return TopicContextRequest(
        query=topic.canonical_name,
        scope=request.scope,
        limit=max_results_per_call,
        max_results_per_search=max_results_per_call,
        semantic=request.semantic,
        filters=request.filters,
    )


def build_search_execution(search_response: SearchResponse) -> ToolExecution:
    return ToolExecution(search_response, None, (), measure_context_bytes(search_response))


def record_cve_request(search_request: SearchRequest) -> CveBackendRequest:
    return CveBackendRequest(
        source=KnowledgeSource.CVE_SEARCH, query=search_request.query, limit=search_request.limit
    )


def measure_context_bytes(response: SearchResponse | TopicContextResponse) -> int:
    return len(canonical_json_bytes(response.model_dump(mode="json")))


def describe_search_outcome(search_response: SearchResponse) -> SourceOutcome:
    """The CVE source's outcome for one search, naming each failing channel."""
    return SourceOutcome(
        source=KnowledgeSource.CVE_SEARCH,
        status=search_response.status,
        channel_failures=list_channel_failures([search_response]),
    )


@dataclass(frozen=True)
class IssuedStep:
    """A step as issued, before its result: its place in the run, call and charge."""

    step_index: int
    round_number: Literal[1, 2]
    call: ToolCall
    reason: StepReason
    planned_by: PlannerKind
    call_key: str
    backend_requests: tuple[BackendRequest, ...]
    charged_tool_calls: int
    sources: tuple[KnowledgeSource, ...]


def issue_step(
    step_index: int,
    round_number: Literal[1, 2],
    call: ToolCall,
    reason: StepReason,
    planned_by: PlannerKind,
    request: InvestigationRequest,
    topic_registry: TopicRegistry,
) -> IssuedStep:
    """A planned call as issued: its call key, the backend requests it sends, its charge and
    sources, all derived from the call, the request and the registry's card. Raises
    ``LookupError`` for a topic the registry does not hold."""
    return IssuedStep(
        step_index=step_index,
        round_number=round_number,
        call=call,
        reason=reason,
        planned_by=planned_by,
        call_key=compute_call_key(call),
        backend_requests=list_backend_requests(call, request, topic_registry),
        charged_tool_calls=count_tool_calls(call, request.scope, topic_registry),
        sources=list_tool_sources(call, request.scope),
    )


def build_tool_step(
    issued_step: IssuedStep, admission: StepAdmission, execution: ToolExecution
) -> ToolStep:
    """The typed record of a step; it keeps IDs, codes and hashes, never source text."""
    status: ResultStatus | None = None
    channels_executed: tuple[RetrievalChannel, ...] = ()
    source_outcomes: tuple[SourceOutcome, ...] = ()
    search_warnings: tuple[SearchWarning, ...] = ()
    topic_warnings: tuple[TopicContextWarning, ...] = ()
    evidence: tuple[EvidenceAnchor, ...] = ()
    answer_ids: list[str] = []
    search_response = execution.search_response
    topic_response = execution.topic_response
    if search_response is not None:
        status = search_response.status
        channels_executed = search_response.channels_executed
        source_outcomes = (describe_search_outcome(search_response),)
        search_warnings = search_response.warnings
        evidence = search_response.evidence
        for candidate in search_response.candidates:
            answer_ids.append(candidate.record.cve_id)
    elif topic_response is not None:
        status = topic_response.status
        source_outcomes = topic_response.source_outcomes
        topic_warnings = topic_response.warnings
        evidence = topic_response.evidence
        for topic_candidate in topic_response.implementation_candidates:
            answer_ids.append(topic_candidate.candidate.record.cve_id)
        for excluded_candidate in topic_response.excluded_implementation_candidates:
            answer_ids.append(excluded_candidate.candidate.candidate.record.cve_id)
        for item in topic_response.protocol_context:
            answer_ids.append(item.technique_id)
    evidence_ids: list[str] = []
    for anchor in evidence:
        evidence_ids.append(anchor.evidence_id)
    return ToolStep(
        step_index=issued_step.step_index,
        round_number=issued_step.round_number,
        call=issued_step.call,
        reason=issued_step.reason,
        planned_by=issued_step.planned_by,
        call_key=issued_step.call_key,
        backend_requests=issued_step.backend_requests,
        charged_tool_calls=issued_step.charged_tool_calls,
        sources=issued_step.sources,
        admission=admission,
        status=status,
        channels_executed=channels_executed,
        source_outcomes=source_outcomes,
        search_warnings=search_warnings,
        topic_warnings=topic_warnings,
        answer_ids=tuple(answer_ids),
        evidence_ids=tuple(evidence_ids),
        result_sha256=execution.result_sha256(),
        context_bytes=execution.context_bytes,
    )
