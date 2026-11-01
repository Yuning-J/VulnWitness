"""CLI session calls over injected services, emitting only committed JSON bytes."""

import argparse
import logging
import sys
from collections.abc import Callable
from functools import partial
from typing import Any, Literal

from pydantic import BaseModel

from vulnwitness.application.affectedness import check_affectedness
from vulnwitness.application.investigate import InvestigationService
from vulnwitness.application.investigation_deployment import InvestigationDeployment
from vulnwitness.application.knowledge_lookup import find_served_evidence
from vulnwitness.domain.affectedness import AffectednessRequest, ApplicabilityStatus
from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.evidence_set_verification_report import (
    VerificationReport,
    VerificationVerdict,
)
from vulnwitness.domain.investigation import KnowledgeEvidenceSet
from vulnwitness.domain.product_query import ProductQueryRequest, ProductQueryResponse
from vulnwitness.domain.product_query_cursor import InvalidProductCursor
from vulnwitness.domain.search import SearchResponse, UnsupportedFilter
from vulnwitness.domain.session_record import SessionRecordingError
from vulnwitness.domain.session_response import (
    SessionAffectednessRequest,
    SessionAffectednessResponse,
)
from vulnwitness.domain.taxonomy import ResultStatus
from vulnwitness.domain.tool_contracts import (
    ConceptResolution,
    ConceptResolutionRequest,
    CveLookupRequest,
    EvidenceLookupRequest,
    ToolFailure,
    ToolFailureCode,
)
from vulnwitness.domain.topic_context import TopicContextRequest, TopicContextResponse
from vulnwitness.domain.validation import EvidenceValidationError
from vulnwitness.interfaces.knowledge_toolbox import (
    build_unsupported_filter_failure,
    describe_knowledge_capabilities,
)
from vulnwitness.interfaces.knowledge_tools import ToolLimits, build_tool_failure
from vulnwitness.interfaces.product_query_output import (
    ProductOutputOptions,
    collect_product_pages,
    print_product_pages,
)
from vulnwitness.ports.session_recording import SessionRecording

SESSION_CLI_COMMANDS = (
    "lookup",
    "search",
    "product",
    "investigate",
    "topic",
    "evidence",
    "affectedness",
    "capabilities",
    "resolve",
    "verify",
)


def encode_cli_answer(answer: BaseModel) -> tuple[bytes, Literal["ok"] | ToolFailureCode, str]:
    outcome: Literal["ok"] | ToolFailureCode = "ok"
    if isinstance(answer, ToolFailure):
        outcome = answer.code
    return (answer.model_dump_json(indent=2) + "\n").encode("utf-8"), outcome, type(answer).__name__


def invoke_cli_operation(operation: Callable[[], BaseModel | None]) -> BaseModel:
    try:
        answer = operation()
        if answer is None:
            return build_tool_failure(ToolFailureCode.UNKNOWN_EVIDENCE_ID)
        return answer
    except InvalidProductCursor:
        return build_tool_failure(ToolFailureCode.INVALID_CURSOR)
    except UnsupportedFilter as error:
        return build_unsupported_filter_failure(error)
    except EvidenceValidationError:
        return build_tool_failure(ToolFailureCode.INTEGRITY_CHECK_FAILED)
    except Exception:
        logging.getLogger(__name__).error("session CLI operation failed", exc_info=True)
        return build_tool_failure(ToolFailureCode.INTERNAL_ERROR)


def exit_for_cli_answer(answer: BaseModel) -> int:
    if isinstance(answer, ToolFailure):
        if answer.code in {
            ToolFailureCode.UNKNOWN_EVIDENCE_ID,
            ToolFailureCode.INTEGRITY_CHECK_FAILED,
            ToolFailureCode.INTERNAL_ERROR,
        }:
            return 1
        return 2
    if isinstance(answer, VerificationReport):
        return 0 if answer.verdict is VerificationVerdict.VERIFIED else 1
    if isinstance(answer, SearchResponse | TopicContextResponse | KnowledgeEvidenceSet):
        return 0 if answer.status is ResultStatus.OK else 1
    if isinstance(answer, ProductQueryResponse):
        return 0 if answer.items else 1
    if isinstance(answer, ConceptResolution):
        return 0 if answer.resolution.matches else 1
    if isinstance(answer, SessionAffectednessResponse):
        return (
            0
            if all(check.applicability is not ApplicabilityStatus.UNKNOWN for check in answer.root)
            else 1
        )
    return 0


def build_simple_session_request(arguments: argparse.Namespace) -> ContractModel:
    """Requests whose CLI flags map directly to the public contracts."""
    if arguments.command == "lookup":
        return CveLookupRequest(cve_id=arguments.cve_id)
    if arguments.command == "product":
        return ProductQueryRequest(
            vendor=arguments.vendor,
            product=arguments.product,
            version=arguments.version,
            cursor=arguments.cursor,
            limit=arguments.limit,
        )
    if arguments.command == "resolve":
        return ConceptResolutionRequest(query=arguments.query)
    if arguments.command == "evidence":
        return EvidenceLookupRequest(evidence_id=arguments.evidence_id)
    if arguments.command == "affectedness":
        checks: list[AffectednessRequest] = []
        if len(arguments.cve_ids) > 20:
            raise ValueError("at most 20 CVE IDs per affectedness command")
        for cve_id in arguments.cve_ids:
            checks.append(AffectednessRequest(cve_id=cve_id, purl=arguments.purl))
        return SessionAffectednessRequest(checks=tuple(checks))
    if arguments.command == "topic":
        return TopicContextRequest(
            query=arguments.query,
            scope=arguments.scope,
            limit=arguments.limit,
            max_results_per_search=arguments.max_results_per_search,
            semantic=arguments.semantic,
        )
    raise ValueError("request must be supplied by the CLI")


class RecordedCliFailure(Exception):
    """A committed tool failure that stops a multi-page CLI traversal."""

    def __init__(self, failure: ToolFailure) -> None:
        super().__init__(failure.code)
        self.failure = failure


class SessionCli:
    """A recorded invocation uses the same services and planners as the ordinary CLI."""

    def __init__(
        self,
        recorder: SessionRecording,
        deployment: InvestigationDeployment,
        investigation_service: InvestigationService,
    ) -> None:
        self._recorder = recorder
        self._deployment = deployment
        self._investigation_service = investigation_service

    def run(
        self,
        command: str,
        request: BaseModel,
        operation: Callable[[], BaseModel | None] | None = None,
    ) -> int:
        if operation is None:
            operation = partial(self._dispatch, command, request)
        try:
            answer = self._record(command, request, operation)
        except SessionRecordingError as error:
            print(build_tool_failure(error.code).model_dump_json(), file=sys.stderr)
            return 2
        print(encode_cli_answer(answer)[0].decode("utf-8"), end="")
        return exit_for_cli_answer(answer)

    def run_product(self, request: ProductQueryRequest, options: ProductOutputOptions) -> int:
        """Commit each page before printing the traversal or publishing its export."""
        try:
            pages = collect_product_pages(self._query_product_page, request, options)
            return print_product_pages(pages, options)
        except RecordedCliFailure as error:
            print(encode_cli_answer(error.failure)[0].decode("utf-8"), end="")
            return exit_for_cli_answer(error.failure)
        except SessionRecordingError as error:
            print(build_tool_failure(error.code).model_dump_json(), file=sys.stderr)
            return 2
        except (OSError, ValueError) as error:
            print(f"vulnwitness product: {error}", file=sys.stderr)
            return 2

    def _query_product_page(self, request: ProductQueryRequest) -> ProductQueryResponse:
        page = self._record(
            "product", request, partial(self._deployment.product_query_service.query, request)
        )
        if isinstance(page, ToolFailure):
            raise RecordedCliFailure(page)
        assert isinstance(page, ProductQueryResponse)
        return page

    def _record(
        self, command: str, request: BaseModel, operation: Callable[[], BaseModel | None]
    ) -> BaseModel:
        return self._recorder.run(
            "cli",
            command,
            request.model_dump(mode="json"),
            partial(invoke_cli_operation, operation),
            encode_cli_answer,
        )

    def _dispatch(self, command: str, request: Any) -> BaseModel | None:
        if command == "lookup":
            return self._deployment.search_service.lookup(request.cve_id)
        if command == "product":
            return self._deployment.product_query_service.query(request)
        if command == "search":
            return self._deployment.search_service.search(request)
        if command == "topic":
            return self._deployment.topic_context_service.explore(request)
        if command == "investigate":
            return self._investigation_service.investigate(request)
        if command == "evidence":
            return find_served_evidence(self._deployment, request.evidence_id)
        if command == "resolve":
            return ConceptResolution(
                resolution=self._deployment.topic_registry.resolve(request.query)
            )
        if command == "capabilities":
            return describe_knowledge_capabilities(
                self._deployment,
                self._investigation_service.describe_capabilities(),
            )
        if command == "affectedness":
            checks = []
            for check_request in request.checks:
                checks.append(
                    check_affectedness(
                        self._deployment.trustify_port,
                        check_request,
                        ToolLimits().affectedness_timeout_seconds,
                    )
                )
            return SessionAffectednessResponse(tuple(checks))
        raise ValueError("unknown session command")
