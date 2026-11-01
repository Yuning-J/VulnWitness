"""Compose workspace investigations with the ordinary session and knowledge services."""

import secrets
import time
from collections.abc import Callable
from contextlib import nullcontext
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import Literal

from vulnwitness.adapters.session.recorder import SessionRecorder
from vulnwitness.adapters.session.triage_artifacts import SessionTriageArtifacts
from vulnwitness.adapters.session.workspace_files import LocalWorkspaceFiles
from vulnwitness.application.serving_data_plane import ServingDataPlane
from vulnwitness.application.triage_workflow import TriageWorkflow
from vulnwitness.application.workspace_investigations import WorkflowCall, WorkspaceInvestigations
from vulnwitness.composition import (
    build_investigation_deployment,
    build_investigation_service,
    utc_now,
)
from vulnwitness.domain.session_report import SessionReport
from vulnwitness.domain.triage import TriageLimits
from vulnwitness.domain.workspace import TriageProductRequest
from vulnwitness.interfaces.cli_session import encode_cli_answer
from vulnwitness.interfaces.knowledge_toolbox import (
    KnowledgeToolbox,
    describe_knowledge_capabilities,
)
from vulnwitness.interfaces.mcp.session_calls import record_tool_call
from vulnwitness.interfaces.report_html import render_html_report
from vulnwitness.interfaces.report_markdown import render_markdown_report


def record_workspace_call(
    files: LocalWorkspaceFiles,
    plane: ServingDataPlane,
    toolbox: KnowledgeToolbox,
    clock: Callable[[], datetime],
    session_id: str,
    name: str,
    arguments: dict[str, object],
) -> object:
    recorder = SessionRecorder(
        files.resolve(session_id),
        plane.session_dataset,
        clock,
        lock=nullcontext,
        record_response_digest=True,
    )
    return record_tool_call(recorder, toolbox, name, arguments)


def run_workspace_triage(
    files: LocalWorkspaceFiles,
    plane: ServingDataPlane,
    clock: Callable[[], datetime],
    monotonic: Callable[[], float],
    session_id: str,
    request: TriageProductRequest,
    limits: TriageLimits,
) -> None:
    deployment = build_investigation_deployment(plane, wall_clock=clock)
    directory = files.resolve(session_id)
    workflow = TriageWorkflow(
        capabilities=partial(
            describe_knowledge_capabilities,
            deployment,
            build_investigation_service(plane).describe_capabilities(),
        ),
        query_product=deployment.product_query_service.query,
        lookup=deployment.search_service.lookup,
        recorder=SessionRecorder(
            directory,
            plane.session_dataset,
            clock,
            lock=nullcontext,
            allow_incomplete_triage=True,
            record_response_digest=True,
        ),
        artifacts=SessionTriageArtifacts(directory, prepared=True),
        clock=monotonic,
        limits=limits,
        encode=encode_cli_answer,
    )
    workflow.run(request.product_request(), request.select)


def render_workspace_report(report: SessionReport, format: Literal["html", "md"]) -> str:
    return render_html_report(report) if format == "html" else render_markdown_report(report)


def build_workspace_investigations(
    root: Path,
    plane: ServingDataPlane,
    toolbox: KnowledgeToolbox,
    *,
    store_root: Path | None = None,
    workspace_limit: int = 200,
    call_limit: int = 100,
    clock: Callable[[], datetime] = utc_now,
    random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    monotonic: Callable[[], float] = time.monotonic,
    workflow: WorkflowCall | None = None,
) -> WorkspaceInvestigations:
    files = LocalWorkspaceFiles(root, store_root)
    return WorkspaceInvestigations(
        files=files,
        dataset=plane.session_dataset,
        clock=clock,
        random_bytes=random_bytes,
        record_call=partial(record_workspace_call, files, plane, toolbox, clock),
        workflow=workflow or partial(run_workspace_triage, files, plane, clock, monotonic),
        renderer=render_workspace_report,
        workspace_limit=workspace_limit,
        call_limit=call_limit,
    )
