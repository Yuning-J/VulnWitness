"""Licensing and provenance of every data source the service reads or cites."""

from enum import StrEnum

from pydantic import Field

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.timestamps import CalendarDate


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
    artifact_uri_template: str | None = Field(
        default=None,
        description=(
            "The canonical upstream URL of a published artifact, cited as an imported "
            "anchor's source_uri; {format} and {name} stand for an NVD feed's format and "
            "its year or series. Null for a source nothing imports."
        ),
    )
    notes: str = ""


class SourceRegistry(ContractModel):
    sources: tuple[DataSource, ...] = Field(min_length=1)

    def find_source(self, name: str) -> DataSource:
        """The source named ``name``; raises ``KeyError`` when the registry lists none."""
        for source in self.sources:
            if source.name == name:
                return source
        raise KeyError(name)

    def require_terms(self, name: str) -> str:
        """The verified terms URL of the source named ``name``; raises ``ValueError`` for a
        source whose terms are unverified, from which no data may be imported."""
        terms = self.find_source(name).terms_or_license_url
        if terms is None:
            raise ValueError(f"{name} has no verified terms")
        return terms
