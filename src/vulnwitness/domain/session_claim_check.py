"""Compare narrow session claims with validated response fields, without inference."""

from typing import Any

from pydantic import BaseModel

from vulnwitness.domain.cve import CveRecord
from vulnwitness.domain.investigation import KnowledgeEvidenceSet
from vulnwitness.domain.product_query import (
    DescriptionMentionBasis,
    ProductFieldBasis,
    ProductQueryResponse,
    ProductVulnerability,
)
from vulnwitness.domain.search import SearchResponse
from vulnwitness.domain.session_claim import (
    CatalogueAssociationClaim,
    CvssSeverityFact,
    DescriptionMentionClaim,
    NeedStatusClaim,
    ProductFieldClaim,
    RecordFactClaim,
    SessionClaim,
    VersionNoteClaim,
)
from vulnwitness.domain.session_record import SessionClaimCheck


def unavailable_claim(finding_id: str, claim: SessionClaim, field: str) -> SessionClaimCheck:
    return SessionClaimCheck(
        finding_id=finding_id,
        call=claim.call,
        status="unverifiable",
        field=field,
        message="Call failed, is missing or invalid, or the required response field is absent.",
    )


def compare_claim_fields(
    finding_id: str, claim: SessionClaim, expected: dict[str, Any], recorded: dict[str, Any]
) -> SessionClaimCheck:
    for field, expected_value in expected.items():
        if expected_value != recorded[field]:
            return SessionClaimCheck(
                finding_id=finding_id,
                call=claim.call,
                status="contradicted",
                field=field,
                expected=expected_value,
                recorded=recorded[field],
                message="Recorded field differs from the claim.",
            )
    return SessionClaimCheck(
        finding_id=finding_id,
        call=claim.call,
        status="verified",
        message="Claim fields equal the recorded response fields.",
    )


def find_product_item(answer: BaseModel, cve_id: str) -> ProductVulnerability | None:
    if isinstance(answer, ProductQueryResponse):
        for item in answer.items:
            if item.record.cve_id == cve_id:
                return item
    return None


def check_product_claim(
    finding_id: str,
    claim: ProductFieldClaim | DescriptionMentionClaim | VersionNoteClaim,
    answer: BaseModel,
) -> SessionClaimCheck:
    item = find_product_item(answer, claim.cve_id)
    if item is None:
        return unavailable_claim(finding_id, claim, "items.record.cve_id")
    if isinstance(claim, ProductFieldClaim):
        expected: dict[str, Any] = {"basis.kind": "product_field"}
        recorded: dict[str, Any] = {"basis.kind": item.basis.kind}
        if isinstance(item.basis, ProductFieldBasis):
            nearest_product = item.basis.matched_products[0]
            nearest_score = -1
            for product in item.basis.matched_products:
                score = (product.product == claim.product) + (product.vendor == claim.vendor)
                if score > nearest_score:
                    nearest_product, nearest_score = product, score
            expected = {
                "basis.matched_products.vendor": claim.vendor,
                "basis.matched_products.product": claim.product,
            }
            recorded = {
                "basis.matched_products.vendor": nearest_product.vendor,
                "basis.matched_products.product": nearest_product.product,
            }
        return compare_claim_fields(finding_id, claim, expected, recorded)
    if isinstance(claim, DescriptionMentionClaim):
        expected = {"basis.kind": "description_mention"}
        recorded = {"basis.kind": item.basis.kind}
        if isinstance(item.basis, DescriptionMentionBasis):
            expected["basis.matched_phrase"] = claim.phrase
            recorded["basis.matched_phrase"] = item.basis.matched_phrase
        return compare_claim_fields(finding_id, claim, expected, recorded)
    note = item.nvd_version_note
    if note is None:
        return unavailable_claim(finding_id, claim, "nvd_version_note")
    assert isinstance(answer, ProductQueryResponse)
    return compare_claim_fields(
        finding_id,
        claim,
        {
            "version": claim.version,
            "nvd_version_note.mention": claim.mention,
            "nvd_version_note.outcome": claim.outcome,
            "applicability": claim.applicability,
        },
        {
            "version": answer.version,
            "nvd_version_note.mention": note.mention,
            "nvd_version_note.outcome": note.outcome,
            "applicability": item.applicability,
        },
    )


def check_catalogue_claim(
    finding_id: str, claim: CatalogueAssociationClaim, answer: BaseModel
) -> SessionClaimCheck:
    if not isinstance(answer, SearchResponse):
        return unavailable_claim(finding_id, claim, "candidates.weakness_associations")
    for candidate in answer.candidates:
        if candidate.record.cve_id != claim.cve_id:
            continue
        associations = candidate.weakness_associations
        if associations is None:
            return unavailable_claim(finding_id, claim, "weakness_associations")
        expected = claim.model_dump(mode="json", exclude={"kind", "call", "cve_id"})
        nearest_path: dict[str, Any] | None = None
        nearest_score = -1
        for path in associations.paths:
            recorded = {
                "cwe_id": path.cwe_id,
                "capec_id": path.capec_id,
                "technique_id": path.technique.technique_id if path.technique else None,
                "terminal_reason": path.terminal_reason,
                "inherited_from": path.inherited_from,
                "inherited_from_cwe": path.inherited_from_cwe,
                "hops": path.model_dump(mode="json")["hops"],
            }
            score = sum(expected[field] == value for field, value in recorded.items())
            if score > nearest_score:
                nearest_path, nearest_score = recorded, score
        if nearest_path is None:
            return compare_claim_fields(
                finding_id,
                claim,
                {"weakness_associations.paths": expected},
                {"weakness_associations.paths": []},
            )
        return compare_claim_fields(finding_id, claim, expected, nearest_path)
    return unavailable_claim(finding_id, claim, "candidates.record.cve_id")


def check_need_claim(
    finding_id: str, claim: NeedStatusClaim, answer: BaseModel
) -> SessionClaimCheck:
    if isinstance(answer, KnowledgeEvidenceSet):
        for need in answer.coverage.needs:
            if need.kind == claim.need_kind and need.subject == claim.subject:
                return compare_claim_fields(
                    finding_id,
                    claim,
                    {"coverage.needs.outcome": claim.outcome.value},
                    {"coverage.needs.outcome": need.outcome.value},
                )
    return unavailable_claim(finding_id, claim, "coverage.needs")


def find_returned_record(answer: BaseModel, cve_id: str) -> CveRecord | None:
    item = find_product_item(answer, cve_id)
    if item is not None:
        return item.record
    if isinstance(answer, SearchResponse):
        for candidate in answer.candidates:
            if candidate.record.cve_id == cve_id:
                return candidate.record
    if isinstance(answer, KnowledgeEvidenceSet):
        for investigation_candidate in answer.implementation_candidates:
            if investigation_candidate.candidate.record.cve_id == cve_id:
                return investigation_candidate.candidate.record
    return None


def check_record_claim(
    finding_id: str, claim: RecordFactClaim, answer: BaseModel
) -> SessionClaimCheck:
    record = find_returned_record(answer, claim.cve_id)
    if record is None:
        return unavailable_claim(finding_id, claim, "record.cve_id")
    fact = claim.fact
    if isinstance(fact, CvssSeverityFact):
        severities: list[str | None] = []
        for metric in record.cvss:
            if (metric.version, metric.scorer, metric.scorer_type) == (
                fact.version,
                fact.scorer,
                fact.scorer_type,
            ):
                severities.append(metric.base_severity)
        if len(severities) != 1 or severities[0] is None:
            return unavailable_claim(finding_id, claim, "cvss.base_severity")
        recorded_value: Any = severities[0]
    else:
        recorded_value = record.model_dump(mode="json")[fact.field]
        if recorded_value is None or recorded_value == []:
            return unavailable_claim(finding_id, claim, fact.field)
    return compare_claim_fields(
        finding_id,
        claim,
        {fact.field: fact.model_dump(mode="json")["value"]},
        {fact.field: recorded_value},
    )


def check_session_claim(
    finding_id: str, claim: SessionClaim, answer: BaseModel | None
) -> SessionClaimCheck:
    if answer is None:
        return unavailable_claim(finding_id, claim, "call")
    if isinstance(claim, ProductFieldClaim | DescriptionMentionClaim | VersionNoteClaim):
        return check_product_claim(finding_id, claim, answer)
    if isinstance(claim, CatalogueAssociationClaim):
        return check_catalogue_claim(finding_id, claim, answer)
    if isinstance(claim, NeedStatusClaim):
        return check_need_claim(finding_id, claim, answer)
    return check_record_claim(finding_id, claim, answer)
