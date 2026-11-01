"""Answers knowledge-tool calls over the application services, bounded in argument size,
time, concurrency and response size. Imports no MCP SDK: a transport hands each call to
``KnowledgeToolbox.call`` and sends back what it returns."""

import json
import logging
from collections.abc import Callable, Mapping
from functools import partial
from typing import Any

from pydantic import ValidationError

from vulnwitness.application.affectedness import check_affectedness
from vulnwitness.application.investigate import InvestigationService
from vulnwitness.application.investigation_deployment import InvestigationDeployment
from vulnwitness.application.knowledge_lookup import find_served_evidence
from vulnwitness.application.threaded_call_runner import (
    CallTimedOut,
    NoFreeWorker,
    ThreadedCallRunner,
)
from vulnwitness.domain.affectedness import AffectednessCheck, AffectednessRequest
from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.investigation import (
    InvestigationRequest,
    KnowledgeEvidenceSet,
    SourceCapability,
)
from vulnwitness.domain.product_query import ProductQueryRequest, ProductQueryResponse
from vulnwitness.domain.product_query_cursor import InvalidProductCursor
from vulnwitness.domain.search import SearchRequest, SearchResponse, UnsupportedFilter
from vulnwitness.domain.served_dataset import ServedDataset
from vulnwitness.domain.tool_contracts import (
    CapabilitiesRequest,
    ConceptResolution,
    ConceptResolutionRequest,
    CveLookupRequest,
    EvidenceLookup,
    EvidenceLookupRequest,
    FightSearchRequest,
    InvalidField,
    KnowledgeCapabilities,
    ToolFailure,
    ToolFailureCode,
)
from vulnwitness.domain.topic_context import QueryScope, TopicContextRequest, TopicContextResponse
from vulnwitness.domain.validation import EvidenceValidationError
from vulnwitness.interfaces.knowledge_tools import (
    KNOWLEDGE_TOOL_SPECS,
    KnowledgeToolName,
    ToolAnswer,
    ToolLimits,
    build_tool_failure,
    list_invalid_fields,
    seconds_until,
)

# The error type a ``filter_unsupported`` failure gives the filter it names.
UNSUPPORTED_FILTER_ERROR = "filter_unsupported"
# A tool body takes the request its tool's request contract parsed; the dispatch table
# pairs each body with that contract, so the argument is always of the declared type.
ToolHandler = Callable[[Any], ContractModel]


class UnknownEvidenceId(LookupError):
    """``get_evidence`` named an evidence ID the deployment's catalog does not hold."""


def describe_knowledge_capabilities(
    deployment: InvestigationDeployment, source_capabilities: tuple[SourceCapability, ...]
) -> KnowledgeCapabilities:
    """The capabilities a service over ``deployment`` reports: its ``source_capabilities``,
    and whether the deployment's dataset can execute a ``purls`` filter."""
    tool_names: list[str] = []
    for tool_spec in KNOWLEDGE_TOOL_SPECS:
        tool_names.append(tool_spec.name.value)
    return KnowledgeCapabilities(
        tools=tuple(tool_names),
        source_capabilities=source_capabilities,
        weakness_associations=deployment.search_service.describe_weakness_snapshot(),
        purl_filter_available=deployment.search_service.serves_purl_filter(),
    )


def build_unsupported_filter_failure(error: UnsupportedFilter) -> ToolFailure:
    """The ``filter_unsupported`` failure naming the filter's field, never its values."""
    return build_tool_failure(
        ToolFailureCode.FILTER_UNSUPPORTED,
        (
            InvalidField(
                location=f"filters.{error.filter_name}", error_type=UNSUPPORTED_FILTER_ERROR
            ),
        ),
    )


class KnowledgeToolbox:
    """The knowledge tools over one deployment's services: its search service,
    topic-context service, topic registry, evidence catalog and affectedness port, and
    ``investigation_service``, which runs against the same deployment.

    ``call`` parses the arguments with the tool's request contract, runs the tool body on
    its own call runner until the tool's time limit on ``monotonic_clock``, and serializes
    the answer once. Every way a call can fail is a ``ToolFailure`` carrying a fixed
    message, never exception text or the caller's input.

    At most ``limits.max_calls_in_flight`` tool bodies run at once, and a call over that is
    answered ``server_busy`` without waiting. A body abandoned at its time limit keeps its
    thread, and its place under that cap, until it returns. An investigation plans with the
    deterministic policy, so it consults no planner and abandons at most one call, a
    blocked tool call at its own deadline, and still returns; an investigation is
    therefore also answered ``server_busy`` while the deployment's runner has
    ``max_calls_in_flight`` calls that have not returned. That check and counting the
    investigation's body live are one step under the runner's lock, so the calls
    investigations abandon stay below twice the cap however long they block.

    The services mutate nothing after construction and keep each request's state local,
    so concurrent calls share them.
    """

    def __init__(
        self,
        *,
        deployment: InvestigationDeployment,
        investigation_service: InvestigationService,
        monotonic_clock: Callable[[], float],
        limits: ToolLimits,
    ) -> None:
        self._deployment = deployment
        self._investigation_service = investigation_service
        self._call_runner = ThreadedCallRunner(max_live_calls=limits.max_calls_in_flight)
        self._monotonic_clock = monotonic_clock
        self._limits = limits
        self._capabilities = describe_knowledge_capabilities(
            deployment, investigation_service.describe_capabilities()
        )
        self._request_models: dict[KnowledgeToolName, type[ContractModel]] = {}
        for tool_spec in KNOWLEDGE_TOOL_SPECS:
            self._request_models[tool_spec.name] = tool_spec.request_model
        self._handlers: dict[KnowledgeToolName, ToolHandler] = {
            KnowledgeToolName.GET_KNOWLEDGE_CAPABILITIES: self._describe_capabilities,
            KnowledgeToolName.RESOLVE_TELECOM_CONCEPT: self._resolve_concept,
            KnowledgeToolName.LOOKUP_CVE: self._lookup_cve,
            KnowledgeToolName.SEARCH_VULNERABILITIES: self._search_vulnerabilities,
            KnowledgeToolName.QUERY_PRODUCT_VULNERABILITIES: self._query_product_vulnerabilities,
            KnowledgeToolName.SEARCH_FIGHT: self._search_fight,
            KnowledgeToolName.CHECK_AFFECTEDNESS: self._check_affectedness,
            KnowledgeToolName.GET_EVIDENCE: self._get_evidence,
            KnowledgeToolName.INVESTIGATE_TELECOM_TOPIC: self._investigate,
        }

    @property
    def limits(self) -> ToolLimits:
        return self._limits

    @property
    def deployment(self) -> InvestigationDeployment:
        """The deployment the tools run against."""
        return self._deployment

    def describe_served_dataset(self) -> ServedDataset:
        """The dataset the tools serve CVE records and evidence from."""
        return self._deployment.served_dataset

    def has_free_worker(self) -> bool:
        """Whether a tool body could start now: fewer than ``max_calls_in_flight`` bodies
        have not returned, abandoned ones included."""
        return self._call_runner.count_live_calls() < self._limits.max_calls_in_flight

    def call(
        self, tool_name: KnowledgeToolName, arguments: Mapping[str, object] | None
    ) -> ToolAnswer | ToolFailure:
        """The answer of ``tool_name`` to ``arguments`` (``None`` means none), or why it has
        none: arguments that do not serialize, are too large or do not parse; no free worker;
        the time limit; an unknown evidence ID; a filter the dataset cannot execute; a result
        its service rejected; a response too large; or any other exception, which is logged
        and answered ``internal_error``.
        """
        try:
            argument_bytes = json.dumps(
                dict(arguments or {}), ensure_ascii=False, allow_nan=False
            ).encode("utf-8")
        except (TypeError, ValueError):
            return build_tool_failure(ToolFailureCode.INVALID_ARGUMENTS)
        if len(argument_bytes) > self._limits.max_argument_bytes:
            return build_tool_failure(ToolFailureCode.ARGUMENTS_TOO_LARGE)
        try:
            request = self._request_models[tool_name].model_validate_json(argument_bytes)
        except ValidationError as error:
            invalid_fields, unexpected_field_count = list_invalid_fields(error)
            return build_tool_failure(
                ToolFailureCode.INVALID_ARGUMENTS, invalid_fields, unexpected_field_count
            )
        service_answer = self._run(tool_name, request)
        if isinstance(service_answer, ToolFailure):
            return service_answer
        structured_content = service_answer.model_dump(mode="json")
        json_text = json.dumps(structured_content, separators=(",", ":"), ensure_ascii=False)
        if len(json_text.encode("utf-8")) > self._limits.max_response_bytes:
            return build_tool_failure(ToolFailureCode.RESPONSE_TOO_LARGE)
        return ToolAnswer(structured_content=structured_content, json_text=json_text)

    def _run(
        self, tool_name: KnowledgeToolName, request: ContractModel
    ) -> ContractModel | ToolFailure:
        """The tool body's response, run on the call runner until the tool's deadline."""
        deadline = self._monotonic_clock() + self._decide_time_limit(request)
        try:
            service_answer = self._call_runner.run(
                partial(self._handlers[tool_name], request),
                partial(seconds_until, deadline, self._monotonic_clock),
                partial(self._admits, request),
            )
        except NoFreeWorker:
            return build_tool_failure(ToolFailureCode.SERVER_BUSY)
        except UnknownEvidenceId:
            return build_tool_failure(ToolFailureCode.UNKNOWN_EVIDENCE_ID)
        except UnsupportedFilter as error:
            return build_unsupported_filter_failure(error)
        except InvalidProductCursor:
            return build_tool_failure(ToolFailureCode.INVALID_CURSOR)
        except EvidenceValidationError:
            return build_tool_failure(ToolFailureCode.INTEGRITY_CHECK_FAILED)
        except Exception:
            logging.getLogger(__name__).error(
                "knowledge tool %s failed", tool_name.value, exc_info=True
            )
            return build_tool_failure(ToolFailureCode.INTERNAL_ERROR)
        if isinstance(service_answer, CallTimedOut):
            return build_tool_failure(ToolFailureCode.TIMED_OUT)
        return service_answer

    def _admits(self, request: ContractModel) -> bool:
        """Whether ``request`` may start: an investigation only while the deployment's
        runner has fewer than ``max_calls_in_flight`` planner or tool calls that have not
        returned. Asked under the toolbox runner's lock, so investigations are admitted
        one at a time."""
        if not isinstance(request, InvestigationRequest):
            return True
        return self._deployment.call_runner.count_live_calls() < self._limits.max_calls_in_flight

    def _decide_time_limit(self, request: ContractModel) -> float:
        """An investigation runs for its own wall-time budget plus the sealing margin; every
        other tool for the common limit."""
        if isinstance(request, InvestigationRequest):
            return (
                request.budget.max_wall_time_seconds
                + self._limits.investigation_seal_margin_seconds
            )
        return self._limits.time_limit_seconds

    def _describe_capabilities(self, request: CapabilitiesRequest) -> KnowledgeCapabilities:
        return self._capabilities

    def _resolve_concept(self, request: ConceptResolutionRequest) -> ConceptResolution:
        return ConceptResolution(resolution=self._deployment.topic_registry.resolve(request.query))

    def _lookup_cve(self, request: CveLookupRequest) -> SearchResponse:
        return self._deployment.search_service.lookup(request.cve_id)

    def _search_vulnerabilities(self, request: SearchRequest) -> SearchResponse:
        return self._deployment.search_service.search(request)

    def _search_fight(self, request: FightSearchRequest) -> TopicContextResponse:
        return self._deployment.topic_context_service.explore(
            TopicContextRequest(
                query=request.query, scope=QueryScope.PROTOCOL_CONTEXT_ONLY, limit=request.limit
            )
        )

    def _query_product_vulnerabilities(self, request: ProductQueryRequest) -> ProductQueryResponse:
        return self._deployment.product_query_service.query(request)

    def _check_affectedness(self, request: AffectednessRequest) -> AffectednessCheck:
        return check_affectedness(
            self._deployment.trustify_port, request, self._limits.affectedness_timeout_seconds
        )

    def _get_evidence(self, request: EvidenceLookupRequest) -> EvidenceLookup:
        """The catalogued anchor, served only when it passes the anchor rules
        (``find_served_evidence``)."""
        evidence_lookup = find_served_evidence(self._deployment, request.evidence_id)
        if evidence_lookup is None:
            raise UnknownEvidenceId(request.evidence_id)
        return evidence_lookup

    def _investigate(self, request: InvestigationRequest) -> KnowledgeEvidenceSet:
        return self._investigation_service.investigate(request)
