"""Investigation lifecycle over injected storage, recording, workflow and rendering."""

import base64
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime
from typing import Literal

from vulnwitness.application.session_report import build_session_report
from vulnwitness.application.triage_workflow import plan_triage_calls
from vulnwitness.application.workspace_progress import remaining_triage_steps
from vulnwitness.domain.hashing import canonical_json_bytes
from vulnwitness.domain.session_record import (
    SessionCall,
    SessionCheckReport,
    SessionDatasetIdentity,
    SessionFindings,
    SessionRecord,
    SessionRecordingError,
)
from vulnwitness.domain.session_report import SessionReport
from vulnwitness.domain.tool_contracts import (
    TOOL_FAILURE_MESSAGES,
    ToolFailure,
    ToolFailureCode,
)
from vulnwitness.domain.triage import TriageLimits, TriageSummary
from vulnwitness.domain.workspace import (
    AddFindingsRequest,
    AddFindingsResponse,
    InvestigationListItem,
    InvestigationRequest,
    InvestigationSnapshot,
    ListInvestigationsResponse,
    ReadCallRequest,
    ReadCallResponse,
    RenderReportRequest,
    RenderReportResponse,
    ReportRecord,
    RequestRecord,
    StartInvestigationRequest,
    TriageOutcome,
    TriageProductRequest,
    TriageProductResponse,
    TriageStarted,
    WorkflowStatus,
)
from vulnwitness.ports.workspace import WorkspaceFiles

RecorderCall = Callable[[str, str, dict[str, object]], object]
WorkflowCall = Callable[[str, TriageProductRequest, TriageLimits], None]
Renderer = Callable[[SessionReport, Literal["html", "md"]], str]


def triage_outcome(summary: TriageSummary) -> TriageOutcome:
    if summary.stop_reason in {"complete", "no_match"}:
        return summary.stop_reason
    if summary.stop_reason in {"max_pages", "time_limit"}:
        return "stopped_at_cap"
    return "failed"


class WorkspaceInvestigations:
    """Keep creation atomic across processes and writes exclusive per investigation."""

    def __init__(
        self,
        *,
        files: WorkspaceFiles,
        dataset: SessionDatasetIdentity,
        clock: Callable[[], datetime],
        random_bytes: Callable[[int], bytes],
        record_call: RecorderCall,
        workflow: WorkflowCall,
        renderer: Renderer,
        workspace_limit: int = 200,
        call_limit: int = 100,
    ) -> None:
        if workspace_limit < 1 or not 1 <= call_limit <= 100:
            raise ValueError("invalid workspace limits")
        self._files = files
        self._dataset = dataset
        self._clock = clock
        self._random_bytes = random_bytes
        self._record_call = record_call
        self._workflow = workflow
        self._renderer = renderer
        self._workspace_limit = workspace_limit
        self._call_limit = call_limit

    def _create(
        self,
        tool: Literal["start_investigation", "triage_product"],
        request: StartInvestigationRequest | TriageProductRequest,
        limits: TriageLimits | None = None,
    ) -> tuple[str, bool]:
        arguments = request.model_dump(mode="json", exclude={"request_key"})
        if isinstance(request, TriageProductRequest):
            product = request.product_request()
            arguments.update(product.model_dump(mode="json", exclude={"cursor", "limit"}))
        dataset = self._dataset.model_dump(mode="json")
        with self._files.workspace_lock():
            if request.request_key is not None:
                indexed = self._files.read_request(request.request_key)
                if indexed is not None:
                    if (
                        indexed.tool != tool
                        or canonical_json_bytes(indexed.arguments)
                        != canonical_json_bytes(arguments)
                        or indexed.dataset != dataset
                    ):
                        raise SessionRecordingError(ToolFailureCode.REQUEST_KEY_CONFLICT)
                    return indexed.session_id, False
            if limits is not None:
                assert isinstance(request, TriageProductRequest)
                plan_triage_calls(request.product_request(), request.select, limits)
            session_ids = self._files.list_ids()
            if len(session_ids) >= self._workspace_limit:
                raise SessionRecordingError(ToolFailureCode.WORKSPACE_FULL)
            for _ in range(10):
                session_id = "inv_" + base64.b32encode(self._random_bytes(13)).decode().lower()[:20]
                if session_id not in session_ids:
                    break
            else:
                raise ValueError("random source repeatedly returned an existing ID")
            is_triage = isinstance(request, TriageProductRequest)
            session = SessionRecord(
                name=session_id,
                dataset=self._dataset,
                created_at=self._clock(),
                goal=request.goal,
                scope=request.scope if isinstance(request, StartInvestigationRequest) else None,
                origin="triage" if is_triage else "manual",
                triage_request=arguments if is_triage else None,
                request_key=request.request_key,
                call_limit=self._call_limit,
            )
            self._files.create(session)
            if request.request_key is not None:
                self._files.write_request(
                    request.request_key,
                    RequestRecord(
                        tool=tool, arguments=arguments, dataset=dataset, session_id=session_id
                    ),
                )
        return session_id, True

    def start(self, request: StartInvestigationRequest) -> InvestigationSnapshot:
        session_id, _ = self._create("start_investigation", request)
        return self.get(InvestigationRequest(session_id=session_id))

    def triage(self, request: TriageProductRequest) -> TriageProductResponse:
        limits = TriageLimits(
            max_pages=request.max_pages, lookups=request.lookups, call_limit=self._call_limit
        )
        session_id, created = self._create("triage_product", request, limits)
        if created:
            with self._files.investigation_lock(session_id):
                marker = TriageStarted(
                    request=SessionRecord.model_validate_json(
                        self._files.read(session_id, "session.json")
                    ).triage_request
                    or {},
                    started_at=self._clock(),
                    remaining_steps=("capabilities", "product inventory", "selected CVE lookups"),
                )
                self._files.write(
                    session_id, "triage.started.json", marker.model_dump_json().encode()
                )
                self._workflow(session_id, request, limits)
        snapshot = self.get(InvestigationRequest(session_id=session_id))
        return TriageProductResponse(
            **snapshot.model_dump(),
            outcome=triage_outcome(snapshot.triage) if snapshot.triage is not None else None,
        )

    def _require_appendable(self, session_id: str) -> None:
        session = SessionRecord.model_validate_json(self._files.read(session_id, "session.json"))
        if session.dataset != self._dataset:
            raise SessionRecordingError(ToolFailureCode.SESSION_DATASET_MISMATCH)
        if session.origin == "triage" and not self._files.exists(session_id, "triage.json"):
            raise SessionRecordingError(ToolFailureCode.INVESTIGATION_INTERRUPTED)
        contents = self._files.check(session_id)
        if not contents.check.record.consistent:
            raise SessionRecordingError(ToolFailureCode.SESSION_RECORDING_FAILED)

    def record(self, session_id: str, name: str, arguments: dict[str, object]) -> object:
        with self._files.investigation_lock(session_id):
            self._require_appendable(session_id)
            return self._record_call(session_id, name, arguments)

    def get(self, request: InvestigationRequest) -> InvestigationSnapshot:
        session_id = request.session_id
        contents = self._files.check(session_id)
        session = contents.session
        if session is None:
            raise ValueError("invalid investigation metadata")
        summary = None
        workflow: WorkflowStatus = "none"
        remaining_steps: tuple[str, ...] = ()
        if session.origin == "triage":
            if self._files.exists(session_id, "triage.json"):
                summary = TriageSummary.model_validate_json(
                    self._files.read(session_id, "triage.json")
                )
                workflow = triage_outcome(summary)
                remaining_steps = summary.remaining_steps
            else:
                workflow = "running" if self._files.is_busy(session_id) else "interrupted"
                planned_steps: tuple[str, ...] = (
                    "capabilities",
                    "product inventory",
                    "selected CVE lookups",
                )
                if self._files.exists(session_id, "triage.started.json"):
                    marker = TriageStarted.model_validate_json(
                        self._files.read(session_id, "triage.started.json")
                    )
                    planned_steps = marker.remaining_steps
                triage_request = (
                    TriageProductRequest.model_validate(session.triage_request)
                    if session.triage_request is not None
                    else None
                )
                remaining_steps = remaining_triage_steps(contents, planned_steps, triage_request)
        report: Literal["none", "current", "stale"] = "none"
        has_report = any(
            self._files.exists(session_id, "report." + format) for format in ("html", "md")
        )
        if has_report:
            report = "stale"
            if self._files.exists(session_id, "report.json"):
                record = ReportRecord.model_validate_json(
                    self._files.read(session_id, "report.json")
                )
                has_bound_report = any(
                    self._files.exists(session_id, "report." + format) for format in record.formats
                )
                if has_bound_report and record.input_digest == self._files.input_digest(session_id):
                    report = "current"
        findings_count = len(contents.findings.effective_findings()) if contents.findings else 0
        return InvestigationSnapshot(
            session_id=session_id,
            session=session,
            workflow=workflow,
            record=contents.check.record,
            check=contents.check,
            report=report,
            triage=summary,
            calls=contents.calls,
            effective_findings=findings_count,
            superseded_findings=contents.check.superseded_count,
            orphan=self._files.is_orphan(session_id),
            remaining_steps=remaining_steps,
        )

    def list(self) -> ListInvestigationsResponse:
        investigations: list[InvestigationListItem] = []
        for session_id in self._files.list_ids():
            snapshot = self.get(InvestigationRequest(session_id=session_id))
            investigations.append(
                InvestigationListItem(
                    session_id=session_id,
                    goal=snapshot.session.goal,
                    created_at=snapshot.session.created_at,
                    workflow=snapshot.workflow,
                    record=snapshot.record,
                    report=snapshot.report,
                    orphan=snapshot.orphan,
                )
            )
        return ListInvestigationsResponse(investigations=tuple(investigations))

    def check(self, request: InvestigationRequest) -> SessionCheckReport:
        with self._files.investigation_lock(request.session_id):
            return self._files.check(request.session_id).check

    def read_call(self, request: ReadCallRequest) -> ReadCallResponse:
        with self._files.investigation_lock(request.session_id):
            call = SessionCall.model_validate_json(
                self._files.read(request.session_id, f"calls/{request.call:04d}.json")
            )
            # The filename is derived from the validated number, never from stored text.
            content = self._files.read_response(request.session_id, request.call)
            failure = None
            if len(content) > 1024 * 1024:
                failure = ToolFailure(
                    code=ToolFailureCode.RESPONSE_TOO_LARGE,
                    message=TOOL_FAILURE_MESSAGES[ToolFailureCode.RESPONSE_TOO_LARGE],
                    invalid_fields=(),
                    unexpected_field_count=0,
                )
            return ReadCallResponse(
                call=call,
                response_json=content.decode("utf-8") if failure is None else None,
                failure=failure,
            )

    def add_findings(self, request: AddFindingsRequest) -> AddFindingsResponse:
        session_id = request.session_id
        with self._files.investigation_lock(session_id):
            self._require_appendable(session_id)
            contents = self._files.check(session_id)
            assert contents.findings is not None
            existing = contents.findings
            findings_by_id = {}
            for finding in existing.findings:
                findings_by_id[finding.id] = finding
            additions = []
            call_numbers = set()
            for call in contents.calls:
                call_numbers.add(call.sequence)
            for finding in request.findings:
                previous = findings_by_id.get(finding.id)
                if previous is not None:
                    if previous.model_dump(mode="json") != finding.model_dump(mode="json"):
                        raise SessionRecordingError(ToolFailureCode.FINDING_ID_CONFLICT)
                    continue
                for citation in finding.citations:
                    if citation.call not in call_numbers:
                        raise SessionRecordingError(ToolFailureCode.INVALID_ARGUMENTS)
                if finding.claim is not None and finding.claim.call not in call_numbers:
                    raise SessionRecordingError(ToolFailureCode.INVALID_ARGUMENTS)
                findings_by_id[finding.id] = finding
                additions.append(finding)
            combined = SessionFindings(
                findings=existing.findings + tuple(additions),
                selections=existing.selections,
                open_questions=existing.open_questions,
            )
            if additions:
                self._files.write_findings(session_id, combined)
            batch_ids = set()
            for finding in request.findings:
                batch_ids.add(finding.id)
            batch = []
            for finding in combined.effective_findings():
                if finding.id in batch_ids:
                    batch.append(finding)
            batch_findings = combined.model_copy(update={"findings": tuple(batch)})
            return AddFindingsResponse(
                written=bool(additions),
                ids_written=tuple(finding.id for finding in additions),
                batch_check=self._files.check_findings(session_id, batch_findings),
                check=self._files.check(session_id).check,
            )

    def render(self, request: RenderReportRequest) -> RenderReportResponse:
        session_id = request.session_id
        with self._files.investigation_lock(session_id):
            digest = self._files.input_digest(session_id)
            contents = self._files.check(session_id)
            triage = None
            if self._files.exists(session_id, "triage.json"):
                triage = self._files.read(session_id, "triage.json").decode()
            report = replace(build_session_report(contents, triage), input_digest=digest)
            content = self._renderer(report, request.format).encode()
            name = "report." + request.format
            self._files.write(session_id, name, content)
            self._files.write(
                session_id,
                "report.json",
                ReportRecord(input_digest=digest, formats=(request.format,))
                .model_dump_json()
                .encode(),
            )
            return RenderReportResponse(
                session_id=session_id,
                resource_uri=f"vulnwitness://investigations/{session_id}/{name}",
                local_path=self._files.local_path(session_id, name),
                byte_size=len(content),
                input_digest=digest,
                report="current",
                check=contents.check,
                markdown=content.decode()
                if request.format == "md" and len(content) < 200 * 1024
                else None,
            )
