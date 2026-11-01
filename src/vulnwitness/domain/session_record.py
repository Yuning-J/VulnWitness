"""Version-one session files: recorded facts and separately authored findings."""

from operator import not_
from typing import Annotated, Literal, Self

from pydantic import BeforeValidator, ConfigDict, Field, JsonValue, StrictBool, model_validator

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.cve import CveId
from vulnwitness.domain.evidence import SHA256_PATTERN, EvidenceId
from vulnwitness.domain.search import (
    SCHEMA_VERSION,
    JsonInteger,
    SchemaVersion,
    require_json_number,
)
from vulnwitness.domain.served_dataset import ServedDataset, ServedDatasetKind
from vulnwitness.domain.session_claim import SessionClaim, SessionSequence, render_claim
from vulnwitness.domain.timestamps import Timestamp
from vulnwitness.domain.tool_contracts import ToolFailureCode

Digest = Annotated[str, Field(pattern=SHA256_PATTERN)]


class SessionCorpusIdentity(ContractModel):
    model_config = ConfigDict(
        json_schema_extra={
            "if": {"properties": {"served": {"properties": {"kind": {"const": "corpus_store"}}}}},
            "then": {"properties": {"store_name": {"type": "string", "minLength": 1}}},
            "else": {"properties": {"store_name": {"type": "null"}}},
        }
    )

    served: ServedDataset
    store_name: str | None = Field(min_length=1)
    store_manifest_sha256: Digest
    corpus_content_sha256: Digest

    @model_validator(mode="after")
    def check_store_name(self) -> Self:
        if (self.served.kind is ServedDatasetKind.CORPUS_STORE) != (self.store_name is not None):
            raise ValueError(
                "a corpus store requires its name; the synthetic fixture has no store name"
            )
        return self


class SessionDatasetIdentity(SessionCorpusIdentity):
    fight_snapshot_sha256: Digest | None
    mitre_snapshot_sha256: Digest | None


class SessionRecord(ContractModel):
    format_version: Annotated[Literal[1], BeforeValidator(require_json_number)] = 1
    name: str = Field(min_length=1, max_length=256)
    created_at: Timestamp
    goal: str | None = None
    scope: str | None = None
    dataset: SessionDatasetIdentity
    contract_version: SchemaVersion = SCHEMA_VERSION
    call_limit: JsonInteger = Field(default=100, ge=1, le=100)
    request_key: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._-]{1,64}$")
    origin: Literal["triage", "manual"] = "manual"
    triage_request: dict[str, JsonValue] | None = None


class SessionCall(ContractModel):
    sequence: SessionSequence
    interface: Literal["cli", "mcp"]
    command: str
    request: dict[str, JsonValue] | None = Field(
        description="Validated request with defaults; null if argument validation failed."
    )
    dataset: SessionDatasetIdentity
    outcome: Literal["ok"] | ToolFailureCode
    response_file: str = Field(pattern=r"^responses/[0-9]{4}\.json$")
    response_schema: str = Field(min_length=1, max_length=128)
    response_sha256: Digest | None = None
    started_at: Timestamp
    finished_at: Timestamp

    @model_validator(mode="after")
    def check_finish(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("finish precedes start")
        return self


class SessionCitation(ContractModel):
    call: SessionSequence
    evidence_id: EvidenceId


def describe_finding_shape() -> dict[str, JsonValue]:
    rules: list[JsonValue] = []
    for kind in (
        "product_field_match",
        "description_mention",
        "catalogue_association",
        "version_note",
        "need_status",
        "record_fact",
    ):
        rules.append(
            {
                "if": {"properties": {"kind": {"const": kind}}},
                "then": {
                    "required": ["claim"],
                    "properties": {
                        "claim": {"type": "object", "properties": {"kind": {"const": kind}}}
                    },
                },
            }
        )
    rules.append(
        {
            "if": {"properties": {"kind": {"enum": ["model_judgement", "analyst_note"]}}},
            "then": {
                "required": ["statement"],
                "properties": {
                    "statement": {"type": "string"},
                    "claim": {"type": "null"},
                    "author": {"enum": ["user", "agent"]},
                },
            },
        }
    )
    rules.append(
        {
            "if": {"properties": {"author": {"const": "workflow"}}},
            "then": {"properties": {"status": {"const": "unconfirmed"}}},
        }
    )
    return {"allOf": rules}


class SessionFinding(ContractModel):
    model_config = ConfigDict(json_schema_extra=describe_finding_shape())

    id: str = Field(min_length=1, max_length=128)
    statement: str | None = Field(default=None, min_length=1)
    author: Literal["user", "agent", "workflow"]
    claim: SessionClaim | None = Field(default=None, exclude_if=not_)
    kind: Literal[
        "product_field_match",
        "description_mention",
        "catalogue_association",
        "version_note",
        "need_status",
        "record_fact",
        "model_judgement",
        "analyst_note",
    ]
    status: Literal["confirmed", "unconfirmed"]
    citations: tuple[SessionCitation, ...]
    supersedes: str | None = Field(default=None, min_length=1, max_length=128)

    @model_validator(mode="after")
    def check_authorship_and_statement(self) -> Self:
        if self.kind in {"model_judgement", "analyst_note"}:
            if self.claim is not None or self.statement is None:
                raise ValueError("narrative findings require a statement and no claim")
            if self.author == "workflow":
                raise ValueError("workflows may author deterministic findings only")
        else:
            if self.claim is None or self.claim.kind != self.kind:
                raise ValueError("deterministic findings require a claim of the same kind")
            statement = render_claim(self.claim)
            if self.statement is not None and self.statement != statement:
                raise ValueError("statement must equal the canonical claim rendering or be omitted")
            object.__setattr__(self, "statement", statement)
        if self.author == "workflow" and self.status != "unconfirmed":
            raise ValueError("workflow findings must start unconfirmed; user or agent may confirm")
        return self


class ProductPaginationProgress(ContractModel):
    """Calls in one product-query chain, with the last page's continuation."""

    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    calls: tuple[SessionSequence, ...]
    next_cursor: str | None
    complete: StrictBool


class SessionSelections(ContractModel):
    cve_ids: tuple[CveId, ...] = ()
    product_queries: tuple[ProductPaginationProgress, ...] = ()


class SessionFindings(ContractModel):
    findings: tuple[SessionFinding, ...]
    selections: SessionSelections
    open_questions: tuple[str, ...]

    @model_validator(mode="after")
    def check_unique_ids(self) -> Self:
        finding_ids: set[str] = set()
        superseded_ids: set[str] = set()
        for finding in self.findings:
            if finding.id in finding_ids:
                raise ValueError("finding IDs must be unique")
            if finding.supersedes is not None:
                if finding.supersedes not in finding_ids:
                    raise ValueError("supersedes must name an earlier finding")
                if finding.supersedes in superseded_ids:
                    raise ValueError("a finding may be superseded only once")
                superseded_ids.add(finding.supersedes)
            finding_ids.add(finding.id)
        return self

    def effective_findings(self) -> tuple[SessionFinding, ...]:
        superseded_ids: set[str] = set()
        for finding in self.findings:
            if finding.supersedes is not None:
                superseded_ids.add(finding.supersedes)
        effective: list[SessionFinding] = []
        for finding in self.findings:
            if finding.id not in superseded_ids:
                effective.append(finding)
        return tuple(effective)


class SessionViolation(ContractModel):
    location: str
    message: str


class SessionRecordCheck(ContractModel):
    consistent: StrictBool
    calls_checked: JsonInteger = Field(ge=0)
    violations: tuple[SessionViolation, ...]


class SessionCitationCheck(ContractModel):
    resolved: StrictBool
    citations_checked: JsonInteger = Field(ge=0)
    violations: tuple[SessionViolation, ...]


class SessionClaimCheck(ContractModel):
    finding_id: str
    call: SessionSequence
    status: Literal["verified", "contradicted", "unverifiable"]
    field: str | None = None
    expected: JsonValue = None
    recorded: JsonValue = None
    message: str


class SessionClaimsCheck(ContractModel):
    verified: StrictBool
    checks: tuple[SessionClaimCheck, ...]


class SessionNotChecked(ContractModel):
    count: JsonInteger = Field(ge=0)
    finding_ids: tuple[str, ...]


class SessionCheckReport(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    record: SessionRecordCheck
    citations: SessionCitationCheck
    claims: SessionClaimsCheck
    not_checked: SessionNotChecked
    superseded_count: JsonInteger = Field(default=0, ge=0)
    support_limitation: Literal[
        "Free narrative is not checked. This check does not establish that a statement is "
        "supported by cited evidence or prove real-world truth."
    ] = (
        "Free narrative is not checked. This check does not establish that a statement is "
        "supported by cited evidence or prove real-world truth."
    )


class SessionRecordingError(ValueError):
    """A refusal that must reach the caller instead of an unrecorded answer."""

    def __init__(self, code: ToolFailureCode) -> None:
        super().__init__(code.value)
        self.code = code
