"""The four explicit facts a priority policy can read; no source or store access."""

from typing import Literal, Self

from pydantic import ConfigDict, model_validator

from vulnwitness.domain.asset_register import Applicability, SystemCategory
from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.evidence import EvidenceId
from vulnwitness.domain.timestamps import CalendarDate

FactName = Literal["applicability", "system_category", "kev", "high_grade"]
KevStatus = Literal["listed", "not_listed_in_snapshot", "unknown"]
HighGradeStatus = Literal["present", "absent", "none_available"]
GradeAuthority = Literal["NVD", "CNVD"]


class ApplicabilityFact(ContractModel):
    value: Applicability
    evidence_ids: tuple[EvidenceId, ...]


class SystemCategoryFact(ContractModel):
    value: SystemCategory
    evidence_ids: tuple[EvidenceId, ...]


class KevFact(ContractModel):
    model_config = ConfigDict(
        json_schema_extra={
            "if": {"properties": {"value": {"const": "not_listed_in_snapshot"}}},
            "then": {
                "required": ["snapshot_retrieved_at"],
                "properties": {"snapshot_retrieved_at": {"type": "string"}},
            },
            "else": {"properties": {"snapshot_retrieved_at": {"type": "null"}}},
        }
    )

    value: KevStatus
    evidence_ids: tuple[EvidenceId, ...]
    snapshot_retrieved_at: CalendarDate | None = None

    @model_validator(mode="after")
    def check_snapshot_date(self) -> Self:
        if (self.value == "not_listed_in_snapshot") != (self.snapshot_retrieved_at is not None):
            raise ValueError("only not_listed_in_snapshot requires the snapshot retrieval date")
        return self


class HighGradeFact(ContractModel):
    model_config = ConfigDict(
        json_schema_extra={
            "if": {"properties": {"value": {"const": "present"}}},
            "then": {
                "required": ["triggering_authorities"],
                "properties": {"triggering_authorities": {"minItems": 1}},
            },
            "else": {"properties": {"triggering_authorities": {"maxItems": 0}}},
        }
    )

    value: HighGradeStatus
    evidence_ids: tuple[EvidenceId, ...]
    triggering_authorities: tuple[GradeAuthority, ...] = ()

    @model_validator(mode="after")
    def check_triggering_authorities(self) -> Self:
        if (self.value == "present") != bool(self.triggering_authorities):
            raise ValueError("present requires the authorities whose high grades triggered it")
        if len(set(self.triggering_authorities)) != len(self.triggering_authorities):
            raise ValueError("triggering authorities must be unique")
        return self


class PriorityFacts(ContractModel):
    applicability: ApplicabilityFact
    system_category: SystemCategoryFact
    kev: KevFact
    high_grade: HighGradeFact

    def list_unknown_facts(self) -> tuple[FactName, ...]:
        """Unknowns in the ADR's fact order, including unavailable grades."""
        unknown_facts: list[FactName] = []
        for fact_name in ("applicability", "system_category", "kev", "high_grade"):
            if getattr(self, fact_name).value in ("unknown", "none_available"):
                unknown_facts.append(fact_name)
        return tuple(unknown_facts)
