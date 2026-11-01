"""Workflow bookkeeping over recorded calls; no vulnerability conclusions."""

from typing import Annotated, Literal

from pydantic import BeforeValidator, Field, StrictBool

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.cve import CveId
from vulnwitness.domain.search import (
    SCHEMA_VERSION,
    JsonInteger,
    SchemaVersion,
    require_json_number,
)
from vulnwitness.domain.tool_contracts import ToolFailureCode

TriageStopReason = Literal[
    "complete",
    "no_match",
    "max_pages",
    "time_limit",
    "call_failed",
    "recording_failed",
    "invalid_selection",
    "lookup_claim_unavailable",
    "check_failed",
]


class TriageLimits(ContractModel):
    max_pages: JsonInteger = Field(default=20, ge=1)
    lookups: JsonInteger = Field(default=5, ge=0, le=10)
    time_limit: float = Field(default=120, gt=0, allow_inf_nan=False)
    call_limit: JsonInteger = Field(default=100, ge=1, le=100)


class TriageInventory(ContractModel):
    pages_read: JsonInteger = Field(ge=0)
    items_seen: JsonInteger = Field(ge=0)
    total_available: Annotated[int, Field(ge=0), BeforeValidator(require_json_number)] | None
    complete: StrictBool
    page_calls: tuple[JsonInteger, ...]
    cve_ids: tuple[CveId, ...]


class TriageDeepDive(ContractModel):
    selection_rule: Literal[
        "product_field before description_mention; with version, hit before unknown before "
        "no_hit; newest published first (missing dates last); CVE ID ascending"
    ] = (
        "product_field before description_mention; with version, hit before unknown before "
        "no_hit; newest published first (missing dates last); CVE ID ascending"
    )
    selection_mode: Literal["first N by the stated order", "user-chosen IDs"]
    selected_ids: tuple[CveId, ...]
    looked_up_ids: tuple[CveId, ...]
    lookups_completed: JsonInteger = Field(ge=0)
    lookup_calls: tuple[JsonInteger, ...]


class TriageSummary(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    planned_call_count: JsonInteger = Field(ge=1)
    limits: TriageLimits
    inventory: TriageInventory
    deep_dive: TriageDeepDive
    stop_reason: TriageStopReason
    caps_hit: tuple[Literal["max_pages", "lookups", "time_limit"], ...]
    failure_code: ToolFailureCode | None = None
    remaining_steps: tuple[str, ...]
