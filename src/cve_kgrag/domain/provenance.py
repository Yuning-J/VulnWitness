"""Licensing and provenance of every data source the service reads or cites."""

from enum import StrEnum

from pydantic import Field

from cve_kgrag.domain.contract_model import ContractModel
from cve_kgrag.domain.timestamps import CalendarDate


class Redistribution(StrEnum):
    ALLOWED = "allowed"
    ALLOWED_WITH_CONDITIONS = "allowed_with_conditions"
    NOT_ALLOWED = "not_allowed"
    UNKNOWN = "unknown"


class LocalStoragePolicy(StrEnum):
    COMMITTED_EXCERPT = "committed_excerpt"
    OPERATOR_SUPPLIED = "operator_supplied"
    REFERENCE_ONLY = "reference_only"
    NOT_STORED = "not_stored"


class DataSource(ContractModel):
    name: str = Field(pattern=r"^[a-z0-9-]+$")
    official_url: str = Field(min_length=1)
    terms_or_license_url: str | None = Field(
        description=(
            "Null when no terms could be verified; the rebuild commits no data from such a source."
        )
    )
    version_strategy: str = Field(min_length=1)
    attribution: str | None
    redistribution_allowed: Redistribution
    redistribution_conditions: str
    local_storage_policy: LocalStoragePolicy
    terms_verified_on: CalendarDate | None
    notes: str = ""


class SourceRegistry(ContractModel):
    sources: tuple[DataSource, ...] = Field(min_length=1)
