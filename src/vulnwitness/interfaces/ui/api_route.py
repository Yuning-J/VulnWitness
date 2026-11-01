"""Narrow, typed HTTP operations; all investigation semantics stay in the service."""

import json
from dataclasses import dataclass
from typing import Literal

import anyio.to_thread
from pydantic import BaseModel, ValidationError
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from vulnwitness.application.workspace_investigations import WorkspaceInvestigations
from vulnwitness.domain.data_readiness import WaitForDataRequest
from vulnwitness.domain.session_record import SessionRecordingError
from vulnwitness.domain.tool_contracts import ToolFailure, ToolFailureCode
from vulnwitness.domain.workspace import (
    InvestigationRequest,
    ReadCallRequest,
    RenderReportRequest,
    ReportStatus,
    StartInvestigationRequest,
    TriageProductRequest,
)
from vulnwitness.interfaces.http.guard import read_path_segment, read_route_body, send_json
from vulnwitness.interfaces.knowledge_tools import KnowledgeToolName, ToolAnswer, build_tool_failure
from vulnwitness.interfaces.rest.tool_routes import read_body_arguments, send_tool_failure
from vulnwitness.interfaces.ui.models import (
    InvestigateRequest,
    InvestigationList,
    InvestigationView,
    ListedInvestigation,
    LookupRequest,
)
from vulnwitness.interfaces.ui.state import UiState

Operation = Literal[
    "wait",
    "list",
    "triage",
    "start",
    "get",
    "view",
    "lookup",
    "investigate",
    "call",
    "check",
    "render",
    "report",
]
REQUEST_MODELS: dict[str, type[BaseModel]] = {
    "triage": TriageProductRequest,
    "start": StartInvestigationRequest,
    "lookup": LookupRequest,
    "investigate": InvestigateRequest,
    "call": ReadCallRequest,
    "check": InvestigationRequest,
    "render": RenderReportRequest,
}


def encode_ui_json(answer: BaseModel | ToolAnswer) -> bytes:
    """JSON remains JSON, with HTML metacharacters escaped even outside the browser."""
    content = answer.json_text if isinstance(answer, ToolAnswer) else answer.model_dump_json()
    for character, escaped in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026")):
        content = content.replace(character, escaped)
    return content.encode()


def html_report_status(
    workspace: WorkspaceInvestigations, request: InvestigationRequest
) -> ReportStatus:
    """Use the existing per-format binding, including reports rendered by other clients."""
    if "report.html" not in workspace.resource_artifacts(request):
        return "none"
    return workspace.resource_report_status(request, "report.html")


@dataclass(frozen=True)
class UiApiRoute:
    state: UiState
    operation: Operation

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        body = await read_route_body(receive)
        try:
            if self.operation == "wait":
                wait_request = WaitForDataRequest.model_validate_json(body)
                readiness = await self.state.readiness.wait(wait_request)
                await send_json(send, 200, encode_ui_json(readiness))
                return
            if self.state.deployment is None:
                if self.operation == "list":
                    await send_json(send, 200, encode_ui_json(InvestigationList(status="loading")))
                else:
                    await send_tool_failure(send, build_tool_failure(ToolFailureCode.DATA_LOADING))
                return
            request: BaseModel | None
            arguments = read_body_arguments(scope, body)
            if self.operation in {"get", "view", "report"}:
                request = InvestigationRequest(session_id=read_path_segment(scope).decode("ascii"))
            elif self.operation == "list":
                request = None
            else:
                if arguments is None:
                    raise ValueError("expected JSON object")
                if (
                    len(json.dumps(arguments, ensure_ascii=False, allow_nan=False).encode())
                    > self.state.deployment.toolbox.limits.max_argument_bytes
                ):
                    await send_tool_failure(
                        send, build_tool_failure(ToolFailureCode.ARGUMENTS_TOO_LARGE)
                    )
                    return
                request = REQUEST_MODELS[self.operation].model_validate_json(body)
            answer = await anyio.to_thread.run_sync(self.execute, request, abandon_on_cancel=True)
        except SessionRecordingError as error:
            await send_tool_failure(send, build_tool_failure(error.code))
            return
        except (ValidationError, ValueError, UnicodeError):
            await send_tool_failure(send, build_tool_failure(ToolFailureCode.INVALID_ARGUMENTS))
            return
        if isinstance(answer, ToolFailure):
            await send_tool_failure(send, answer)
        elif isinstance(answer, str):
            # This is only the fixed report.html artifact, with its renderer's own CSP.
            await Response(
                answer,
                media_type="text/html",
                headers={
                    "Content-Security-Policy": (
                        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'self'"
                    ),
                    "Referrer-Policy": "no-referrer",
                },
            )(scope, receive, send)
        elif isinstance(answer, ToolAnswer):
            # Escape HTML metacharacters without changing the tool answer.
            await send_json(send, 200, encode_ui_json(answer))
        else:
            await send_json(send, 200, encode_ui_json(answer))

    def execute(self, request: BaseModel | None) -> BaseModel | ToolAnswer | str:
        deployment = self.state.deployment
        assert deployment is not None and deployment.workspace is not None
        workspace = deployment.workspace
        if self.operation == "list":
            investigations = []
            for entry in workspace.list().investigations:
                snapshot = workspace.get(InvestigationRequest(session_id=entry.session_id))
                investigations.append(
                    ListedInvestigation(
                        **entry.model_dump(exclude={"report"}),
                        report=html_report_status(
                            workspace, InvestigationRequest(session_id=entry.session_id)
                        ),
                        dataset=snapshot.session.dataset,
                    )
                )
            return InvestigationList(status="ready", investigations=tuple(investigations))
        assert isinstance(request, BaseModel)
        if self.operation == "triage":
            assert isinstance(request, TriageProductRequest)
            if not request.product or not request.product.strip():
                return build_tool_failure(ToolFailureCode.INVALID_ARGUMENTS)
            return workspace.triage(request)
        if self.operation == "start":
            assert isinstance(request, StartInvestigationRequest)
            return workspace.start(request)
        if self.operation in {"lookup", "investigate"}:
            assert isinstance(request, LookupRequest | InvestigateRequest)
            name = (
                KnowledgeToolName.LOOKUP_CVE
                if self.operation == "lookup"
                else KnowledgeToolName.INVESTIGATE_TELECOM_TOPIC
            )
            answer = workspace.record(
                request.session_id,
                name.value,
                request.model_dump(mode="json", exclude={"session_id"}),
            )
            assert isinstance(answer, ToolAnswer | ToolFailure)
            return answer
        if self.operation == "call":
            assert isinstance(request, ReadCallRequest)
            return workspace.read_call(request)
        if self.operation == "render":
            assert isinstance(request, RenderReportRequest)
            if request.format != "html":
                return build_tool_failure(ToolFailureCode.INVALID_ARGUMENTS)
            return workspace.render(request)
        assert isinstance(request, InvestigationRequest)
        if self.operation == "get":
            return workspace.get(request).model_copy(
                update={"report": html_report_status(workspace, request)}
            )
        if self.operation == "check":
            return workspace.check(request)
        if self.operation == "view":
            return InvestigationView(report=workspace.report_model(request))
        if "report.html" not in workspace.resource_artifacts(request):
            return build_tool_failure(ToolFailureCode.UNKNOWN_INVESTIGATION)
        return workspace.read_resource_artifact(request, "report.html")
