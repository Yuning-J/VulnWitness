"""The five explicit facts a priority policy can read; no source or store access."""

from typing import Literal, Self

from pydantic import ConfigDict, Field, model_validator

from vulnwitness.domain.asset_register import Applicability, SystemCategory
from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.cve import CNVD_ID_PATTERN
from vulnwitness.domain.evidence import EvidenceId
from vulnwitness.domain.timestamps import CalendarDate

FactName = Literal["applicability", "system_category", "kev", "high_grade", "public_exploit"]
FACT_NAMES: tuple[FactName, ...] = (
    "applicability",
    "system_category",
    "kev",
    "high_grade",
    "public_exploit",
)
KevStatus = Literal["listed", "not_listed_in_snapshot", "unknown"]
HighGradeStatus = Literal["present", "absent", "none_available"]
GradeAuthority = Literal["NVD", "CNVD"]
PublicExploitStatus = Literal["referenced", "not_referenced_in_record", "unknown"]
# NVD's reference-tag vocabulary spells the tag exactly so; matching is case-sensitive.
EXPLOIT_REFERENCE_TAG = "Exploit"
# The fact keeps a bounded, ordered sample of URLs; evidence IDs lead to the full record.
MAX_EXPLOIT_REFERENCE_URLS = 20


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


class CnvdLinkToReview(ContractModel):
    cnvd_id: str = Field(pattern=CNVD_ID_PATTERN)
    cnvd_name: str = Field(min_length=1)


class HighGradeFact(ContractModel):
    model_config = ConfigDict(
        json_schema_extra={
            "if": {"properties": {"value": {"const": "present"}}},
            "then": {
                "required": ["triggering_authorities"],
                "properties": {"triggering_authorities": {"minItems": 1}},
            },
            "else": {"properties": {"triggering_authorities": {"maxItems": 0}}},
            "allOf": [
                {
                    "if": {
                        "required": ["cnvd_links_to_review"],
                        "properties": {"cnvd_links_to_review": {"minItems": 1}},
                    },
                    "then": {
                        "required": ["triggering_authorities"],
                        "properties": {"triggering_authorities": {"contains": {"const": "CNVD"}}},
                    },
                }
            ],
        }
    )

    value: HighGradeStatus
    evidence_ids: tuple[EvidenceId, ...]
    triggering_authorities: tuple[GradeAuthority, ...] = ()
    cnvd_links_to_review: tuple[CnvdLinkToReview, ...] = ()

    @model_validator(mode="after")
    def check_triggering_authorities(self) -> Self:
        if (self.value == "present") != bool(self.triggering_authorities):
            raise ValueError("present requires the authorities whose high grades triggered it")
        if len(set(self.triggering_authorities)) != len(self.triggering_authorities):
            raise ValueError("triggering authorities must be unique")
        if self.cnvd_links_to_review and "CNVD" not in self.triggering_authorities:
            raise ValueError("links to review require a triggering CNVD high grade")
        previous_id = ""
        for link in self.cnvd_links_to_review:
            if link.cnvd_id <= previous_id:
                raise ValueError("links to review must have unique CNVD IDs in order")
            previous_id = link.cnvd_id
        return self


class PublicExploitFact(ContractModel):
    """Whether the looked-up record cites a reference its source tagged as an exploit."""

    model_config = ConfigDict(
        json_schema_extra={
            "if": {"properties": {"value": {"const": "referenced"}}},
            "then": {
                "required": ["reference_urls"],
                "properties": {"reference_urls": {"minItems": 1}},
            },
            "else": {"properties": {"reference_urls": {"maxItems": 0}}},
        }
    )

    value: PublicExploitStatus
    evidence_ids: tuple[EvidenceId, ...]
    reference_urls: tuple[str, ...] = Field(
        default=(),
        max_length=MAX_EXPLOIT_REFERENCE_URLS,
        description=(
            "Exploit-tagged reference URLs in record order, deduplicated and capped; "
            "untrusted source text that is cited, never fetched."
        ),
    )

    @model_validator(mode="after")
    def check_reference_urls(self) -> Self:
        if (self.value == "referenced") != bool(self.reference_urls):
            raise ValueError("only referenced requires the exploit-tagged reference URLs")
        if len(set(self.reference_urls)) != len(self.reference_urls):
            raise ValueError("exploit reference URLs must be unique")
        if self.value != "unknown" and not self.evidence_ids:
            raise ValueError("a known public-exploit value requires the record's evidence")
        return self


class PriorityFacts(ContractModel):
    applicability: ApplicabilityFact
    system_category: SystemCategoryFact
    kev: KevFact
    high_grade: HighGradeFact
    public_exploit: PublicExploitFact

    def list_unknown_facts(self) -> tuple[FactName, ...]:
        """Unknowns in the ADR's fact order, including unavailable grades."""
        unknown_facts: list[FactName] = []
        for fact_name in FACT_NAMES:
            if getattr(self, fact_name).value in ("unknown", "none_available"):
                unknown_facts.append(fact_name)
        return tuple(unknown_facts)
