"""The MCP tool contracts that no other service contract already covers: the requests of
the lookup tools, the wrappers that give a bare record a ``schema_version``, and the
failure every tool answers with when it cannot answer."""

from enum import StrEnum
from typing import Self

from pydantic import ConfigDict, Field, model_validator

from cve_kgrag.domain.contract_model import ContractModel, describe_fixed_messages
from cve_kgrag.domain.cve import CveId
from cve_kgrag.domain.evidence import EvidenceAnchor, EvidenceId
from cve_kgrag.domain.investigation import (
    CAPABILITY_ORDER_DESCRIPTION,
    SourceCapability,
    pin_capability_order,
)
from cve_kgrag.domain.investigation_validation import find_capability_shape_violations
from cve_kgrag.domain.search import (
    MAX_RESULTS_PER_CALL,
    SCHEMA_VERSION,
    JsonInteger,
    QueryText,
    SchemaVersion,
)
from cve_kgrag.domain.topic import TopicResolution

MAX_INVALID_FIELDS = 20
MAX_INVALID_FIELD_LOCATION_CHARS = 128


class CapabilitiesRequest(ContractModel):
    """Asks for the deployment's capabilities; takes no arguments."""


class KnowledgeCapabilities(ContractModel):
    """What the deployment serves, in the shape every evidence set reports it."""

    schema_version: SchemaVersion = SCHEMA_VERSION
    source_capabilities: tuple[SourceCapability, ...] = Field(
        description=CAPABILITY_ORDER_DESCRIPTION,
        json_schema_extra=pin_capability_order,
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
    limit: JsonInteger = Field(default=10, ge=1, le=MAX_RESULTS_PER_CALL)


class EvidenceLookupRequest(ContractModel):
    evidence_id: EvidenceId


class EvidenceLookup(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    evidence: EvidenceAnchor


class ToolFailureCode(StrEnum):
    INVALID_ARGUMENTS = "invalid_arguments"
    ARGUMENTS_TOO_LARGE = "arguments_too_large"
    UNKNOWN_EVIDENCE_ID = "unknown_evidence_id"
    SERVER_BUSY = "server_busy"
    TIMED_OUT = "timed_out"
    RESPONSE_TOO_LARGE = "response_too_large"
    INTEGRITY_CHECK_FAILED = "integrity_check_failed"
    INTERNAL_ERROR = "internal_error"


# The one sentence a failure of each code carries; it never quotes the caller's input.
TOOL_FAILURE_MESSAGES: dict[ToolFailureCode, str] = {
    ToolFailureCode.INVALID_ARGUMENTS: "The arguments do not match the tool's input schema.",
    ToolFailureCode.ARGUMENTS_TOO_LARGE: "The arguments exceed the size limit.",
    ToolFailureCode.UNKNOWN_EVIDENCE_ID: "No evidence anchor has that evidence ID.",
    ToolFailureCode.SERVER_BUSY: "Too many calls are in flight; retry later.",
    ToolFailureCode.TIMED_OUT: "The call did not finish within the tool's time limit.",
    ToolFailureCode.RESPONSE_TOO_LARGE: (
        "The response exceeds the size limit; lower the limit argument."
    ),
    ToolFailureCode.INTEGRITY_CHECK_FAILED: "The service rejected its own result as invalid.",
    ToolFailureCode.INTERNAL_ERROR: "The call failed with an internal error.",
}


class InvalidField(ContractModel):
    """One argument that failed to parse: where it is and the parser's error type, never
    the value sent."""

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
