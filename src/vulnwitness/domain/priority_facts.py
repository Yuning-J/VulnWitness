"""The explicit facts a priority policy can read; no source or store access."""

from typing import Literal, Self

from pydantic import ConfigDict, Field, model_validator

from vulnwitness.domain.asset_register import Applicability, SystemCategory
from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.cve import CNVD_ID_PATTERN
from vulnwitness.domain.epss import LevEstimate
from vulnwitness.domain.evidence import EvidenceId
from vulnwitness.domain.exploit_index import ExploitModuleRef
from vulnwitness.domain.timestamps import CalendarDate, Timestamp

FactName = Literal[
    "applicability",
    "system_category",
    "kev",
    "high_grade",
    "public_exploit",
    "exploitation",
    "automatable",
    "technical_impact",
    "source_high_grade",
    "forensic_triage",
    "exploit_probability",
    "exploit_module",
]
FACT_NAMES: tuple[FactName, ...] = (
    "applicability",
    "system_category",
    "kev",
    "high_grade",
    "public_exploit",
    "exploitation",
    "automatable",
    "technical_impact",
    "source_high_grade",
    "forensic_triage",
    "exploit_probability",
    "exploit_module",
)
KevStatus = Literal["listed", "not_listed_in_snapshot", "unknown"]
HighGradeStatus = Literal["present", "absent", "none_available"]
GradeAuthority = Literal["NVD", "CNVD"]
PublicExploitStatus = Literal["referenced", "not_referenced_in_record", "unknown"]
ExploitationStatus = Literal["active", "poc", "none", "unknown"]
AutomatableStatus = Literal["yes", "no", "unknown"]
TechnicalImpactStatus = Literal["total", "partial", "unknown"]
ForensicTriageStatus = Literal["yes", "no", "unknown"]
ExploitModuleStatus = Literal["present", "not_in_index", "unknown"]
ExploitProbabilityStatus = Literal["at_or_above_threshold", "below_threshold", "unknown"]
# The SSVC role CISA's ADP container scores in; ADR 0021 reads only its assessment.
CISA_SSVC_ROLE = "CISA Coordinator"
MAX_SOURCE_GRADE_SCORERS = 16
# NVD's reference-tag vocabulary spells the tag exactly so; matching is case-sensitive.
EXPLOIT_REFERENCE_TAG = "Exploit"
# The fact keeps a bounded, ordered sample of URLs; evidence IDs lead to the full record.
MAX_EXPLOIT_REFERENCE_URLS = 20
MAX_FACT_MODULES = 16


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


class SsvcFactFields(ContractModel):
    """Who scored an SSVC decision point and when; both null exactly when it is unknown."""

    evidence_ids: tuple[EvidenceId, ...]
    assessor: str | None = Field(
        default=None, description="The assessment's source and role, as the record gives them."
    )
    assessed_at: Timestamp | None = None

    def check_assessment(self, value: str) -> None:
        if value == "unknown":
            if self.assessor is not None or self.assessed_at is not None:
                raise ValueError("an unknown SSVC fact names no assessment")
        elif self.assessor is None or not self.evidence_ids:
            raise ValueError("a known SSVC fact requires its assessor and evidence")


class ExploitationFact(SsvcFactFields):
    """CISA's SSVC exploitation point; ``none`` is CISA's view at its time, not "no exploit"."""

    value: ExploitationStatus

    @model_validator(mode="after")
    def check_value(self) -> Self:
        self.check_assessment(self.value)
        return self


class AutomatableFact(SsvcFactFields):
    value: AutomatableStatus

    @model_validator(mode="after")
    def check_value(self) -> Self:
        self.check_assessment(self.value)
        return self


class TechnicalImpactFact(SsvcFactFields):
    value: TechnicalImpactStatus

    @model_validator(mode="after")
    def check_value(self) -> Self:
        self.check_assessment(self.value)
        return self


class SourceHighGradeFact(ContractModel):
    """CVSS v3.x or v4.0 severity from scorers other than NVD; never NVD's own grade."""

    value: HighGradeStatus
    evidence_ids: tuple[EvidenceId, ...]
    triggering_scorers: tuple[str, ...] = Field(
        default=(),
        max_length=MAX_SOURCE_GRADE_SCORERS,
        description="Each scorer whose HIGH or CRITICAL metric triggered present, with its "
        "CVSS version, e.g. 'cna@example.org CVSS 4.0'.",
    )

    @model_validator(mode="after")
    def check_triggering_scorers(self) -> Self:
        if (self.value == "present") != bool(self.triggering_scorers):
            raise ValueError("present requires the scorers whose high grades triggered it")
        if self.value != "none_available" and not self.evidence_ids:
            raise ValueError("an available source grade requires the record's evidence")
        return self


class ForensicTriageFact(ContractModel):
    """CISA's KEV forensicTriage column for a listed CVE."""

    value: ForensicTriageStatus
    evidence_ids: tuple[EvidenceId, ...]

    @model_validator(mode="after")
    def check_evidence(self) -> Self:
        if self.value != "unknown" and not self.evidence_ids:
            raise ValueError("a known forensic-triage value requires the KEV evidence")
        return self


class ExploitProbabilityFact(ContractModel):
    """EPSS and NIST's LEV from operator-supplied snapshots, banded by the policy's
    threshold on their larger value. ``below_threshold`` is a low probability estimate,
    never evidence that the CVE is not exploited."""

    value: ExploitProbabilityStatus
    evidence_ids: tuple[EvidenceId, ...] = ()
    epss: float | None = Field(default=None, ge=0, le=1)
    percentile: float | None = Field(default=None, ge=0, le=1)
    score_date: CalendarDate | None = None
    model_version: str | None = None
    lev: LevEstimate | None = Field(
        default=None, description="LEV over the supplied snapshots only."
    )
    threshold: float | None = Field(default=None, gt=0, le=1)

    @model_validator(mode="after")
    def check_scores(self) -> Self:
        known = self.value != "unknown"
        fields = (self.epss, self.percentile, self.score_date, self.model_version, self.lev)
        if known != all(field is not None for field in fields) or known != (
            self.threshold is not None
        ):
            raise ValueError("a known exploit probability needs its scores and threshold")
        if any(field is not None for field in fields) and not known:
            raise ValueError("an unknown exploit probability carries no scores")
        if known and self.epss is not None and self.lev is not None and self.threshold:
            above = max(self.epss, self.lev.lev) >= self.threshold
            if above != (self.value == "at_or_above_threshold"):
                raise ValueError("the band does not match the scores and threshold")
        return self


class ExploitModuleFact(ContractModel):
    """Whether the supplied exploit-module index names the CVE. ``not_in_index`` means
    only that the indexed checkouts name no module for it, never "no exploit exists"."""

    value: ExploitModuleStatus
    evidence_ids: tuple[EvidenceId, ...] = ()
    modules: tuple[ExploitModuleRef, ...] = Field(default=(), max_length=MAX_FACT_MODULES)
    omitted_modules: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def check_modules(self) -> Self:
        if (self.value == "present") != bool(self.modules):
            raise ValueError("only present names its modules")
        return self


def unknown_ssvc_facts() -> tuple[ExploitationFact, AutomatableFact, TechnicalImpactFact]:
    return (
        ExploitationFact(value="unknown", evidence_ids=()),
        AutomatableFact(value="unknown", evidence_ids=()),
        TechnicalImpactFact(value="unknown", evidence_ids=()),
    )


class PriorityFacts(ContractModel):
    applicability: ApplicabilityFact
    system_category: SystemCategoryFact
    kev: KevFact
    high_grade: HighGradeFact
    public_exploit: PublicExploitFact
    exploitation: ExploitationFact
    automatable: AutomatableFact
    technical_impact: TechnicalImpactFact
    source_high_grade: SourceHighGradeFact
    forensic_triage: ForensicTriageFact
    exploit_probability: ExploitProbabilityFact
    exploit_module: ExploitModuleFact

    def list_unknown_facts(self) -> tuple[FactName, ...]:
        """Unknowns in the ADR's fact order, including unavailable grades."""
        unknown_facts: list[FactName] = []
        for fact_name in FACT_NAMES:
            if getattr(self, fact_name).value in ("unknown", "none_available"):
                unknown_facts.append(fact_name)
        return tuple(unknown_facts)
