"""The MCP tool contracts that no other service contract already covers: the requests of
the lookup tools, the wrappers that give a bare record a ``schema_version``, and the
failure every tool answers with when it cannot answer."""

from enum import StrEnum
from typing import Self

from pydantic import ConfigDict, Field, StrictBool, model_validator

from vulnwitness.domain.contract_model import ContractModel, describe_fixed_messages
from vulnwitness.domain.cve import CveId
from vulnwitness.domain.evidence import EvidenceAnchor, EvidenceId
from vulnwitness.domain.investigation import (
    CAPABILITY_ORDER_DESCRIPTION,
    SourceCapability,
    pin_capability_order,
)
from vulnwitness.domain.investigation_validation import find_capability_shape_violations
from vulnwitness.domain.search import (
    MAX_RESULTS_PER_CALL,
    SCHEMA_VERSION,
    FilterName,
    JsonInteger,
    QueryText,
    SchemaVersion,
)
from vulnwitness.domain.topic import TopicResolution
from vulnwitness.domain.weakness_associations import WeaknessSnapshotCapability

MAX_INVALID_FIELDS = 20
MAX_INVALID_FIELD_LOCATION_CHARS = 128


class CapabilitiesRequest(ContractModel):
    """Asks for the deployment's capabilities; takes no arguments."""


class KnowledgeCapabilities(ContractModel):
    """What the deployment serves, in the shape every evidence set reports it, and which
    search filters its dataset can execute."""

    schema_version: SchemaVersion = SCHEMA_VERSION
    tools: tuple[FilterName, ...] = Field(description="Available deterministic, read-only tools.")
    source_capabilities: tuple[SourceCapability, ...] = Field(
        description=CAPABILITY_ORDER_DESCRIPTION,
        json_schema_extra=pin_capability_order,
    )
    weakness_associations: WeaknessSnapshotCapability | None = None
    purl_filter_available: StrictBool = Field(
        description=(
            "Whether a search or investigation may filter by package URL (filters.purls): "
            "only a dataset whose records name package URLs can execute it, and an NVD "
            "import names none. Without it, a request with a purls filter is refused "
            "(filter_unsupported) instead of answered as if nothing matched."
        )
    )

    @model_validator(mode="after")
    def check_capability_shape(self) -> Self:
        """The rules the published schema states for ``source_capabilities``."""
        shape_violations = find_capability_shape_violations(self.source_capabilities)
        if shape_violations:
            raise ValueError("; ".join(shape_violations))
        return self


class ConceptResolutionRequest(ContractModel):
    query: QueryText


class ConceptResolution(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    resolution: TopicResolution


class CveLookupRequest(ContractModel):
    cve_id: CveId


class FightSearchRequest(ContractModel):
    """A FiGHT search through a reviewed topic the query resolves to."""

    query: QueryText
    limit: JsonInteger = Field(
        default=10,
        ge=1,
        le=MAX_RESULTS_PER_CALL,
        description=(
            "Techniques the answer lists; a protocol_context_truncated warning counts the "
            "ones the snapshot matched beyond them."
        ),
    )


class EvidenceLookupRequest(ContractModel):
    evidence_id: EvidenceId


class EvidenceLookup(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    evidence: EvidenceAnchor


class ToolFailureCode(StrEnum):
    FINDING_ID_CONFLICT = "finding_id_conflict"
    INVESTIGATION_INTERRUPTED = "investigation_interrupted"
    WORKSPACE_FULL = "workspace_full"
    REQUEST_KEY_CONFLICT = "request_key_conflict"
    WORKSPACE_BUSY = "workspace_busy"
    INVESTIGATION_BUSY = "investigation_busy"
    UNKNOWN_INVESTIGATION = "unknown_investigation"
    INVESTIGATIONS_NOT_ENABLED = "investigations_not_enabled"
    SESSION_CALL_LIMIT = "session_call_limit"
    SESSION_DATASET_MISMATCH = "session_dataset_mismatch"
    SESSION_RECORDING_FAILED = "session_recording_failed"
    INVALID_ARGUMENTS = "invalid_arguments"
    INVALID_CURSOR = "invalid_cursor"
    ARGUMENTS_TOO_LARGE = "arguments_too_large"
    UNKNOWN_EVIDENCE_ID = "unknown_evidence_id"
    SERVER_BUSY = "server_busy"
    DATA_LOADING = "data_loading"
    TIMED_OUT = "timed_out"
    RESPONSE_TOO_LARGE = "response_too_large"
    INTEGRITY_CHECK_FAILED = "integrity_check_failed"
    INTERNAL_ERROR = "internal_error"
    FILTER_UNSUPPORTED = "filter_unsupported"


# The one sentence a failure of each code carries; it never quotes the caller's input.
TOOL_FAILURE_MESSAGES: dict[ToolFailureCode, str] = {
    ToolFailureCode.FINDING_ID_CONFLICT: "A finding ID already has different content.",
    ToolFailureCode.INVESTIGATION_INTERRUPTED: (
        "The interrupted investigation cannot accept appends."
    ),
    ToolFailureCode.WORKSPACE_FULL: "The workspace investigation limit has been reached.",
    ToolFailureCode.REQUEST_KEY_CONFLICT: (
        "The request key belongs to different arguments or dataset."
    ),
    ToolFailureCode.WORKSPACE_BUSY: "The workspace is busy; retry later.",
    ToolFailureCode.INVESTIGATION_BUSY: "The investigation is busy; retry later.",
    ToolFailureCode.UNKNOWN_INVESTIGATION: "No investigation has that ID.",
    ToolFailureCode.INVESTIGATIONS_NOT_ENABLED: "Workspace investigations are not enabled.",
    ToolFailureCode.SESSION_CALL_LIMIT: "The session call limit has been reached.",
    ToolFailureCode.SESSION_DATASET_MISMATCH: (
        "The served dataset differs from the session dataset."
    ),
    ToolFailureCode.SESSION_RECORDING_FAILED: "The requested session could not be recorded.",
    ToolFailureCode.INVALID_ARGUMENTS: "The arguments do not match the tool's input schema.",
    ToolFailureCode.INVALID_CURSOR: "The cursor is invalid for this product query.",
    ToolFailureCode.ARGUMENTS_TOO_LARGE: "The arguments exceed the size limit.",
    ToolFailureCode.UNKNOWN_EVIDENCE_ID: "No evidence anchor has that evidence ID.",
    ToolFailureCode.SERVER_BUSY: "Too many calls are in flight; retry later.",
    ToolFailureCode.DATA_LOADING: "The data is still loading; retry later.",
    ToolFailureCode.TIMED_OUT: "The call did not finish within the tool's time limit.",
    ToolFailureCode.RESPONSE_TOO_LARGE: (
        "The response exceeds the size limit; lower the limit argument."
    ),
    ToolFailureCode.INTEGRITY_CHECK_FAILED: "The service rejected its own result as invalid.",
    ToolFailureCode.INTERNAL_ERROR: "The call failed with an internal error.",
    ToolFailureCode.FILTER_UNSUPPORTED: (
        "A filter cannot be executed on this dataset, which holds no value it could match; "
        "invalid_fields names it."
    ),
}


class InvalidField(ContractModel):
    """One argument that failed to parse, or a filter the dataset cannot execute: where it
    is and the error type (the parser's, or ``filter_unsupported``), never the value
    sent."""

    location: str = Field(min_length=1, max_length=MAX_INVALID_FIELD_LOCATION_CHARS)
    error_type: str = Field(pattern=r"^[a-z_]+$", max_length=64)


class ToolFailure(ContractModel):
    """Why a tool call gave no answer. Keys the request contract does not declare are
    counted, never named."""

    model_config = ConfigDict(json_schema_extra=describe_fixed_messages(TOOL_FAILURE_MESSAGES))

    schema_version: SchemaVersion = SCHEMA_VERSION
    code: ToolFailureCode
    message: str = Field(min_length=1, max_length=200)
    invalid_fields: tuple[InvalidField, ...] = Field(max_length=MAX_INVALID_FIELDS)
    unexpected_field_count: JsonInteger = Field(ge=0)

    @model_validator(mode="after")
    def check_message(self) -> Self:
        """The message is the fixed sentence of the code (``TOOL_FAILURE_MESSAGES``), so a
        failure never carries other text."""
        if self.message != TOOL_FAILURE_MESSAGES[self.code]:
            raise ValueError("message must be the fixed sentence of the failure's code")
        return self
