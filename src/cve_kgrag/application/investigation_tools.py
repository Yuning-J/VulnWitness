"""The allowlisted investigation tools, run against the search and topic-context services.

Every call runs under the request's filters, semantic flag and per-call result cap;
a plan cannot change them. The cap bounds every backend search a call sends,
including each template search a ``topic_context`` call fans out to and the one FiGHT
search of a ``fight_direct_search`` call, which sends the interpretation's words
(``list_fight_terms``) and nothing a planner chose. Each step records those searches as
built from the same requests the tools run. A response that fails its own evidence
validation is recorded as an integrity failure, never used as partial data.
"""

from dataclasses import dataclass, replace
from typing import Literal, assert_never

from cve_kgrag.application.investigation_policy import count_tool_calls, list_fight_terms
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
    FightDirectSearchCall,
    PlannerKind,
    ToolCall,
    TopicContextCall,
    compute_call_key,
    format_cve_tool_query,
    list_tool_sources,
)
from cve_kgrag.domain.result_prefix import (
    PrefixAdmission,
    build_prefix_admission,
    find_longest_prefix,
    measure_response_bytes,
)
from cve_kgrag.domain.search import SearchRequest, SearchResponse, SearchWarning
from cve_kgrag.domain.taxonomy import ResultStatus, RetrievalChannel
from cve_kgrag.domain.topic import ProtocolTopic
from cve_kgrag.domain.topic_context import (
    KnowledgeSource,
    QueryScope,
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
    prefix_admission: PrefixAdmission | None = None

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
        """Run the call. Raises ``LookupError`` for a direct FiGHT search of a query whose
        words may not go to FiGHT, a call the gate never admits."""
        try:
            if isinstance(call, CveExactLookupCall | CveSearchCall):
                search_response = self._search_service.search(build_search_request(call, request))
                return build_search_execution(search_response)
            if isinstance(call, TopicContextCall):
                topic = self._topic_registry.require_topic(call.topic_id)
                topic_exploration = self._topic_context_service.explore_with_omissions(
                    build_topic_request(topic, request)
                )
                return build_topic_execution(
                    topic_exploration.response, topic_exploration.omitted_cve_ids
                )
            if isinstance(call, FightDirectSearchCall):
                fight_terms = require_fight_terms(request, self._topic_registry)
                topic_response = self._topic_context_service.search_fight_directly(
                    build_fight_request(request), fight_terms
                )
                return build_topic_execution(topic_response, ())
            assert_never(call)
        except EvidenceValidationError as error:
            # A source returned evidence that failed integrity; it is an observation,
            # never partial data.
            return ToolExecution(None, None, error.violations, 0)


def require_fight_terms(
    request: InvestigationRequest, topic_registry: TopicRegistry
) -> tuple[str, ...]:
    """The words a direct FiGHT search of the request sends (``list_fight_terms``). Raises
    ``LookupError`` when the query's words may not go to FiGHT, a call the gate never
    admits."""
    fight_terms = list_fight_terms(request.query, topic_registry)
    if not fight_terms:
        raise LookupError("the interpretation allows no direct FiGHT search")
    return fight_terms


def list_backend_requests(
    call: ToolCall, request: InvestigationRequest, topic_registry: TopicRegistry
) -> tuple[BackendRequest, ...]:
    """The searches a call sends, in the order it sends them, from the same request
    builders the executor runs it with: a CVE tool's one search, a topic's FiGHT search
    (unless the scope is ``implementation_only``) then one search per card query template,
    or a direct FiGHT search of the query's ``list_fight_terms``. Raises ``LookupError``
    for a topic the registry does not hold, or a direct FiGHT search of a query whose
    words may not go to FiGHT."""
    if isinstance(call, CveExactLookupCall | CveSearchCall):
        search_request = build_search_request(call, request)
        return (record_cve_request(search_request),)
    if isinstance(call, FightDirectSearchCall):
        return (
            FightBackendRequest(
                source=KnowledgeSource.MITRE_FIGHT,
                terms=require_fight_terms(request, topic_registry),
                limit=decide_fight_search_limit(build_fight_request(request)),
            ),
        )
    if not isinstance(call, TopicContextCall):
        assert_never(call)
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


def build_fight_request(request: InvestigationRequest) -> TopicContextRequest:
    """The direct FiGHT search, asked by the caller's own query under
    ``protocol_context_only``, its one section and search bounded by the result cap. FiGHT
    is never filtered, so the request names no filter."""
    max_results_per_call = request.budget.max_results_per_call
    return TopicContextRequest(
        query=request.query,
        scope=QueryScope.PROTOCOL_CONTEXT_ONLY,
        limit=max_results_per_call,
        max_results_per_search=max_results_per_call,
    )


def build_search_execution(search_response: SearchResponse) -> ToolExecution:
    return ToolExecution(search_response, None, (), measure_response_bytes(search_response))


def build_topic_execution(
    topic_response: TopicContextResponse, omitted_cve_ids: tuple[str, ...]
) -> ToolExecution:
    return ToolExecution(
        search_response=None,
        topic_response=topic_response,
        integrity_violations=(),
        context_bytes=measure_response_bytes(topic_response),
        omitted_topic_cve_ids=omitted_cve_ids,
    )


def record_cve_request(search_request: SearchRequest) -> CveBackendRequest:
    return CveBackendRequest(
        source=KnowledgeSource.CVE_SEARCH, query=search_request.query, limit=search_request.limit
    )


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
    ``LookupError`` for a topic the registry does not hold, or a direct FiGHT search of a
    query whose words may not go to FiGHT."""
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
    """Record admitted observations and the compact witness for a prefix."""
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
        prefix_admission=execution.prefix_admission,
    )


def retain_context_prefix(execution: ToolExecution, remaining_bytes: int) -> ToolExecution:
    """Retain a whole-result prefix only when the complete response exceeds the cap."""
    if execution.context_bytes <= remaining_bytes:
        return execution
    original_response = execution.search_response or execution.topic_response
    if original_response is None:
        return execution
    prefix = find_longest_prefix(original_response, remaining_bytes)
    if prefix is None:
        return execution
    return replace(
        execution,
        search_response=prefix if isinstance(prefix, SearchResponse) else None,
        topic_response=prefix if isinstance(prefix, TopicContextResponse) else None,
        context_bytes=measure_response_bytes(prefix),
        prefix_admission=build_prefix_admission(original_response, prefix),
    )
