"""Analyst-authored assets and applicability assessments (ADR 0016 §2)."""

from typing import Annotated, Literal, Self

from pydantic import BeforeValidator, ConfigDict, Field, model_validator

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.cve import CveId
from vulnwitness.domain.hashing import canonical_sha256
from vulnwitness.domain.search import require_json_number
from vulnwitness.domain.timestamps import CalendarDate

Applicability = Literal["affected", "not_affected", "unknown"]
SystemCategory = Literal["external_connection", "software_update", "other", "unknown"]
NonblankText = Annotated[str, Field(min_length=1, pattern=r"\S")]
Market = Annotated[str, Field(pattern=r"^[A-Z]{2}$")]
FormatVersion = Annotated[Literal[1], BeforeValidator(require_json_number)]


class Asset(ContractModel):
    name: NonblankText
    markets: tuple[Market, ...]
    system_category: SystemCategory


class AssetAssessment(ContractModel):
    model_config = ConfigDict(
        json_schema_extra={
            "if": {"properties": {"applicability": {"enum": ["affected", "not_affected"]}}},
            "then": {
                "required": ["justification"],
                "properties": {"justification": {"type": "string"}},
            },
        }
    )

    asset: NonblankText
    cve_id: CveId
    applicability: Applicability
    justification: NonblankText | None = None
    assessor: NonblankText
    assessed_at: CalendarDate

    @model_validator(mode="after")
    def require_justification(self) -> Self:
        if self.applicability != "unknown" and self.justification is None:
            raise ValueError("affected and not_affected require a justification")
        return self


class AssetRegister(ContractModel):
    format_version: FormatVersion
    assets: tuple[Asset, ...]
    assessments: tuple[AssetAssessment, ...]

    @model_validator(mode="after")
    def check_unique_declared_assets(self) -> Self:
        asset_names: set[str] = set()
        for asset in self.assets:
            if asset.name in asset_names:
                raise ValueError("duplicate asset name")
            asset_names.add(asset.name)
        assessment_keys: set[tuple[str, str]] = set()
        for assessment in self.assessments:
            if assessment.asset not in asset_names:
                raise ValueError("assessment names an undeclared asset")
            assessment_key = (assessment.asset, assessment.cve_id)
            if assessment_key in assessment_keys:
                raise ValueError("duplicate asset and CVE assessment")
            assessment_keys.add(assessment_key)
        return self

    def compute_content_sha256(self) -> str:
        """SHA-256 of the validated register's canonical JSON, including defaults."""
        return canonical_sha256(self.model_dump(mode="json"))
