"""Workspace investigation requests, derived status and tool answers."""

from typing import Annotated, Literal, Self

from pydantic import Field, JsonValue, StrictBool, field_validator, model_validator

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.cve import CveId
from vulnwitness.domain.product_query import ProductQueryRequest
from vulnwitness.domain.search import JsonInteger
from vulnwitness.domain.session_record import (
    Digest,
    SessionCall,
    SessionCheckReport,
    SessionFinding,
    SessionRecord,
    SessionRecordCheck,
)
from vulnwitness.domain.timestamps import Timestamp
from vulnwitness.domain.tool_contracts import ToolFailure
from vulnwitness.domain.triage import TriageSummary

INVESTIGATION_ID_PATTERN = r"^inv_[a-z2-7]{20}$"
MAX_FINDING_STATEMENT_BYTES = 8 * 1024
MAX_FINDINGS_PER_BATCH = 200
MAX_FINDINGS_REQUEST_BYTES = 1024 * 1024
MAX_WORKSPACE_FINDINGS_BYTES = 16 * 1024 * 1024
InvestigationId = Annotated[str, Field(pattern=INVESTIGATION_ID_PATTERN)]
RequestKey = Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")]
WorkflowStatus = Literal[
    "none", "running", "interrupted", "complete", "stopped_at_cap", "no_match", "failed"
]
TriageOutcome = Literal["complete", "stopped_at_cap", "no_match", "failed"]
ReportStatus = Literal["none", "current", "stale"]


class StartInvestigationRequest(ContractModel):
    goal: str = Field(min_length=1, max_length=4096)
    scope: str | None = Field(default=None, max_length=4096)
    request_key: RequestKey | None = None


class TriageProductRequest(ContractModel):
    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    lookups: JsonInteger = Field(default=5, ge=0, le=10)
    max_pages: JsonInteger = Field(default=20, ge=1, le=99)
    select: tuple[CveId, ...] = ()
    goal: str | None = Field(default=None, max_length=4096)
    request_key: RequestKey | None = None

    def product_request(self) -> ProductQueryRequest:
        return ProductQueryRequest(
            vendor=self.vendor.casefold() if self.vendor is not None else None,
            product=self.product.casefold() if self.product is not None else None,
            version=self.version,
            limit=20,
        )


class InvestigationRequest(ContractModel):
    session_id: InvestigationId


class ReadCallRequest(InvestigationRequest):
    call: JsonInteger = Field(ge=1, le=100)


class AgentFinding(SessionFinding):
    author: Literal["agent"] = "agent"
    statement: str | None = Field(
        default=None, min_length=1, max_length=MAX_FINDING_STATEMENT_BYTES
    )

    @field_validator("statement")
    @classmethod
    def bound_statement(cls, statement: str | None) -> str | None:
        if statement is not None and len(statement.encode("utf-8")) > MAX_FINDING_STATEMENT_BYTES:
            raise ValueError("finding statement exceeds the 8 KiB UTF-8 limit")
        return statement


class AddFindingsRequest(InvestigationRequest):
    findings: tuple[AgentFinding, ...] = Field(min_length=1, max_length=MAX_FINDINGS_PER_BATCH)

    @model_validator(mode="after")
    def bound_request(self) -> Self:
        if len(self.model_dump_json().encode("utf-8")) > MAX_FINDINGS_REQUEST_BYTES:
            raise ValueError("findings request exceeds the 1 MiB serialized limit")
        return self


class RenderReportRequest(InvestigationRequest):
    format: Literal["html", "md"] = "html"


class ListInvestigationsRequest(ContractModel):
    pass


class InvestigationSnapshot(ContractModel):
    session_id: InvestigationId
    session: SessionRecord
    workflow: WorkflowStatus
    record: SessionRecordCheck
    check: SessionCheckReport
    report: ReportStatus
    triage: TriageSummary | None
    calls: tuple[SessionCall, ...]
    effective_findings: JsonInteger = Field(ge=0)
    superseded_findings: JsonInteger = Field(ge=0)
    orphan: StrictBool
    remaining_steps: tuple[str, ...]


class TriageProductResponse(InvestigationSnapshot):
    outcome: TriageOutcome | None


class ReadCallResponse(ContractModel):
    call: SessionCall
    response_json: str | None
    failure: ToolFailure | None = None


class AddFindingsResponse(ContractModel):
    written: StrictBool
    ids_written: tuple[str, ...]
    batch_check: SessionCheckReport
    check: SessionCheckReport


class RenderReportResponse(ContractModel):
    session_id: InvestigationId
    resource_uri: str
    local_path: str
    byte_size: JsonInteger = Field(ge=0)
    input_digest: Digest
    report: ReportStatus
    check: SessionCheckReport
    markdown: str | None


class InvestigationListItem(ContractModel):
    session_id: InvestigationId
    goal: str | None
    created_at: Timestamp
    workflow: WorkflowStatus
    record: SessionRecordCheck
    report: ReportStatus
    orphan: StrictBool


class ListInvestigationsResponse(ContractModel):
    investigations: tuple[InvestigationListItem, ...]


class RequestRecord(ContractModel):
    tool: Literal["start_investigation", "triage_product"]
    arguments: dict[str, JsonValue]
    dataset: dict[str, JsonValue]
    session_id: InvestigationId


class TriageStarted(ContractModel):
    request: dict[str, JsonValue]
    started_at: Timestamp
    remaining_steps: tuple[str, ...]


class ReportRecord(ContractModel):
    input_digest: Digest
    formats: tuple[Literal["html", "md"], ...]
