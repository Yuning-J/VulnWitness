"""Copy returned fields into deterministic, unconfirmed workflow claims."""

from vulnwitness.domain.cve import CveRecord
from vulnwitness.domain.evidence import EvidenceAnchor
from vulnwitness.domain.product_query import ProductQueryResponse
from vulnwitness.domain.search import SearchResponse
from vulnwitness.domain.session_claim import (
    CatalogueAssociationClaim,
    CvssSeverityFact,
    CweIdsFact,
    DescriptionMentionClaim,
    KevFact,
    ProductFieldClaim,
    PublishedFact,
    RecordFact,
    RecordFactClaim,
    SessionClaim,
    VersionNoteClaim,
)
from vulnwitness.domain.session_record import SessionCitation, SessionFinding


def make_workflow_finding(
    claim: SessionClaim, record: CveRecord, evidence: tuple[EvidenceAnchor, ...], suffix: str
) -> SessionFinding:
    """Attach only record citations whose complete anchors occur in the same call."""
    anchor_ids: set[str] = set()
    for anchor in evidence:
        anchor_ids.add(anchor.evidence_id)
    citations: list[SessionCitation] = []
    for evidence_id in record.evidence_ids:
        if evidence_id in anchor_ids:
            citations.append(SessionCitation(call=claim.call, evidence_id=evidence_id))
    return SessionFinding(
        id=f"{claim.call}-{record.cve_id}-{suffix}",
        author="workflow",
        status="unconfirmed",
        kind=claim.kind,
        claim=claim,
        citations=tuple(citations),
    )


def build_page_findings(page: ProductQueryResponse, call: int) -> list[SessionFinding]:
    """Copy each returned match and optional version note into canonical claims."""
    findings: list[SessionFinding] = []
    for vulnerability in page.items:
        record = vulnerability.record
        basis = vulnerability.basis
        claim: SessionClaim
        if basis.kind == "product_field":
            for index, product in enumerate(basis.matched_products, start=1):
                claim = ProductFieldClaim(
                    kind="product_field_match",
                    call=call,
                    cve_id=record.cve_id,
                    vendor=product.vendor,
                    product=product.product,
                )
                findings.append(
                    make_workflow_finding(claim, record, page.evidence, f"match-{index}")
                )
        else:
            claim = DescriptionMentionClaim(
                kind="description_mention",
                call=call,
                cve_id=record.cve_id,
                phrase=basis.matched_phrase,
            )
            findings.append(make_workflow_finding(claim, record, page.evidence, "mention"))
        if page.version is not None:
            note = vulnerability.nvd_version_note
            assert note is not None  # The product service supplies one for every versioned item.
            claim = VersionNoteClaim(
                kind="version_note",
                call=call,
                cve_id=record.cve_id,
                version=page.version,
                mention=note.mention,
                outcome=note.outcome,
                applicability=vulnerability.applicability,
            )
            findings.append(make_workflow_finding(claim, record, page.evidence, "version"))
    return findings


def choose_record_fact(record: CveRecord) -> RecordFact | None:
    """Choose a present, unambiguous source field, or decline to invent a fact."""
    if record.published is not None:
        return PublishedFact(field="published", value=record.published)
    if record.cwe_ids:
        return CweIdsFact(field="cwe_ids", value=record.cwe_ids)
    if record.kev is not None:
        return KevFact(field="kev", value=record.kev)
    for metric in record.cvss:
        selector_count = sum(
            (candidate.version, candidate.scorer, candidate.scorer_type)
            == (metric.version, metric.scorer, metric.scorer_type)
            for candidate in record.cvss
        )
        if metric.base_severity is not None and selector_count == 1:
            return CvssSeverityFact(
                field="cvss.base_severity",
                version=metric.version,
                scorer=metric.scorer,
                scorer_type=metric.scorer_type,
                value=metric.base_severity,
            )
    return None


def build_lookup_findings(lookup: SearchResponse, call: int) -> list[SessionFinding]:
    """Copy returned catalogue paths, falling back to one source fact per record."""
    findings: list[SessionFinding] = []
    for candidate in lookup.candidates:
        record = candidate.record
        associations = candidate.weakness_associations
        if associations is not None and associations.paths:
            for index, path in enumerate(associations.paths, start=1):
                claim = CatalogueAssociationClaim(
                    kind="catalogue_association",
                    call=call,
                    cve_id=record.cve_id,
                    cwe_id=path.cwe_id,
                    capec_id=path.capec_id,
                    technique_id=None if path.technique is None else path.technique.technique_id,
                    terminal_reason=path.terminal_reason,
                    inherited_from=path.inherited_from,
                    inherited_from_cwe=path.inherited_from_cwe,
                    hops=path.hops,
                )
                findings.append(
                    make_workflow_finding(claim, record, lookup.evidence, f"path-{index}")
                )
        else:
            fact = choose_record_fact(record)
            if fact is not None:
                fact_claim = RecordFactClaim(
                    kind="record_fact",
                    call=call,
                    cve_id=record.cve_id,
                    fact=fact,
                )
                findings.append(make_workflow_finding(fact_claim, record, lookup.evidence, "fact"))
    return findings
