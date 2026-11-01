"""Version-one session files: recorded facts and separately authored findings."""

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
from vulnwitness.domain.timestamps import Timestamp
from vulnwitness.domain.tool_contracts import ToolFailureCode

SessionSequence = Annotated[int, Field(ge=1, le=100), BeforeValidator(require_json_number)]
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


class SessionFinding(ContractModel):
    id: str = Field(min_length=1, max_length=128)
    statement: str = Field(min_length=1)
    kind: Literal[
        "product_field_match",
        "description_mention",
        "catalogue_association",
        "version_note",
        "need_status",
        "model_judgement",
        "analyst_note",
    ]
    status: Literal["confirmed", "unconfirmed"]
    citations: tuple[SessionCitation, ...]


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
        for finding in self.findings:
            if finding.id in finding_ids:
                raise ValueError("finding IDs must be unique")
            finding_ids.add(finding.id)
        return self


class SessionViolation(ContractModel):
    location: str
    message: str


class SessionCheckReport(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    passed: StrictBool
    calls_checked: JsonInteger = Field(ge=0)
    citations_checked: JsonInteger = Field(ge=0)
    violations: tuple[SessionViolation, ...]
    support_limitation: Literal[
        "This check does not establish that a statement is supported by its evidence. "
        "Narrative support is never established by IDs alone."
    ] = (
        "This check does not establish that a statement is supported by its evidence. "
        "Narrative support is never established by IDs alone."
    )


class SessionRecordingError(ValueError):
    """A refusal that must reach the caller instead of an unrecorded answer."""

    def __init__(self, code: ToolFailureCode) -> None:
        super().__init__(code.value)
        self.code = code
