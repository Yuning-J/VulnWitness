"""Typed assertions over specific fields of one recorded response."""

import json
from typing import Annotated, Literal

from pydantic import BeforeValidator, Field

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.cve import CveId, CweId, KevEntry, Severity
from vulnwitness.domain.investigation import EvidenceNeedKind, NeedOutcome
from vulnwitness.domain.search import require_json_number
from vulnwitness.domain.timestamps import Timestamp
from vulnwitness.domain.weakness_associations import AssociationHop, CapecId, TechniqueId

SessionSequence = Annotated[int, Field(ge=1, le=100), BeforeValidator(require_json_number)]
ClaimText = Annotated[str, Field(min_length=1)]


class ProductFieldClaim(ContractModel):
    kind: Literal["product_field_match"]
    call: SessionSequence
    cve_id: CveId
    vendor: ClaimText
    product: ClaimText


class DescriptionMentionClaim(ContractModel):
    kind: Literal["description_mention"]
    call: SessionSequence
    cve_id: CveId
    phrase: ClaimText


class VersionNoteClaim(ContractModel):
    kind: Literal["version_note"]
    call: SessionSequence
    cve_id: CveId
    version: ClaimText
    mention: ClaimText
    outcome: Literal["hit", "unknown", "no_hit"]
    applicability: Literal["unknown"] = "unknown"


class CatalogueAssociationClaim(ContractModel):
    kind: Literal["catalogue_association"]
    call: SessionSequence
    cve_id: CveId
    cwe_id: CweId
    capec_id: CapecId
    technique_id: TechniqueId | None = None
    terminal_reason: Literal["no_attack_mapping"] | None
    inherited_from: CapecId | None = None
    inherited_from_cwe: CweId | None = None
    hops: tuple[AssociationHop, ...] = Field(min_length=1)


class NeedStatusClaim(ContractModel):
    kind: Literal["need_status"]
    call: SessionSequence
    need_kind: EvidenceNeedKind
    subject: str | None
    outcome: NeedOutcome


class PublishedFact(ContractModel):
    field: Literal["published"]
    value: Timestamp


class CweIdsFact(ContractModel):
    field: Literal["cwe_ids"]
    value: tuple[CweId, ...] = Field(min_length=1)


class KevFact(ContractModel):
    field: Literal["kev"]
    value: KevEntry


class CvssSeverityFact(ContractModel):
    field: Literal["cvss.base_severity"]
    version: Literal["2.0", "3.0", "3.1", "4.0"]
    scorer: ClaimText
    scorer_type: Literal["primary", "secondary"] | None
    value: Severity


RecordFact = Annotated[
    PublishedFact | CweIdsFact | KevFact | CvssSeverityFact, Field(discriminator="field")
]


class RecordFactClaim(ContractModel):
    kind: Literal["record_fact"]
    call: SessionSequence
    cve_id: CveId
    fact: RecordFact


SessionClaim = Annotated[
    ProductFieldClaim
    | DescriptionMentionClaim
    | VersionNoteClaim
    | CatalogueAssociationClaim
    | NeedStatusClaim
    | RecordFactClaim,
    Field(discriminator="kind"),
]


def quote_claim_value(value: object) -> str:
    """Keep response text visibly quoted and prevent embedded line/control formatting."""
    return json.dumps(value, sort_keys=True, ensure_ascii=True)


def render_claim(claim: SessionClaim) -> str:
    """Render only the typed assertion, keeping source text quoted as data."""
    prefix = f"Call {claim.call} records "
    if isinstance(claim, ProductFieldClaim):
        return (
            f"{prefix}{claim.cve_id} with a product-field match for vendor "
            f"{quote_claim_value(claim.vendor)} and product {quote_claim_value(claim.product)}. "
            "Deployed applicability is not established."
        )
    if isinstance(claim, DescriptionMentionClaim):
        return (
            f"{prefix}{claim.cve_id} with a description mention of "
            f"{quote_claim_value(claim.phrase)}. Vendor ownership is not established."
        )
    if isinstance(claim, VersionNoteClaim):
        return (
            f"{prefix}an NVD version note for {claim.cve_id}, version "
            f"{quote_claim_value(claim.version)}, mention {quote_claim_value(claim.mention)}: "
            f"{claim.outcome}. Applicability remains unknown."
        )
    if isinstance(claim, CatalogueAssociationClaim):
        path = "; ".join(f"{hop.from_id} [{hop.relation}] {hop.to_id}" for hop in claim.hops)
        return (
            f"{prefix}a catalogue association for {claim.cve_id}: "
            f"{claim.cwe_id} -> {claim.capec_id} -> {quote_claim_value(claim.technique_id)}; "
            f"terminal reason {quote_claim_value(claim.terminal_reason)}; "
            f"CAPEC ancestor {quote_claim_value(claim.inherited_from)}; "
            f"CWE ancestor {quote_claim_value(claim.inherited_from_cwe)}; "
            f"hops {quote_claim_value(path)}. "
            "Catalogue association only; exploitation and attack paths are not established."
        )
    if isinstance(claim, NeedStatusClaim):
        return (
            f"{prefix}coverage need {claim.need_kind.value} for subject "
            f"{quote_claim_value(claim.subject)} with outcome {claim.outcome.value}. "
            "This outcome does not establish evidence sufficiency."
        )
    fact = claim.fact
    selector = ""
    if isinstance(fact, CvssSeverityFact):
        selector = (
            f" (version {fact.version}, scorer {quote_claim_value(fact.scorer)}, "
            f"scorer type {quote_claim_value(fact.scorer_type)})"
        )
    value = quote_claim_value(fact.model_dump(mode="json")["value"])
    return f"{prefix}{claim.cve_id} field {fact.field}{selector} as {value}."
