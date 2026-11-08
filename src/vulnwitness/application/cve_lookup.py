"""Build exact lookup views from validated NVD records and the served CNVD index."""

from vulnwitness.domain.cnvd import CnvdIndex
from vulnwitness.domain.cve_lookup import (
    CNVD_NOT_FOUND_STATEMENT,
    ComparedCnvdEntry,
    CveLookupResponse,
    LookupCandidate,
    LookupCveRecord,
    PendingCnvdLookup,
)
from vulnwitness.domain.evidence_catalog import EvidenceCatalog
from vulnwitness.domain.search import SearchResponse, SearchWarningCode
from vulnwitness.domain.source_comparison import compare_cnvd_severity
from vulnwitness.domain.taxonomy import ResultStatus
from vulnwitness.domain.validation import (
    EvidenceValidationError,
    validate_search_response,
    validate_served_anchor,
)


def build_cve_lookup(
    search: SearchResponse,
    identifier: str,
    cve_id: str | None,
    cnvd_index: CnvdIndex,
    evidence_catalog: EvidenceCatalog,
    cnvd_attribution: str | None,
    cnvd_language: str | None,
) -> CveLookupResponse:
    """Add source comparisons and pending entries to an already validated exact search.

    Pending content comes from the verified store index; each cited anchor must also
    pass serving rules. Raises ``EvidenceValidationError`` for missing anchors or credit.
    """
    candidates: list[LookupCandidate] = []
    carries_cnvd = False
    for candidate in search.candidates:
        record = candidate.record
        compared_entries: list[ComparedCnvdEntry] = []
        for entry in record.cnvd:
            compared_entries.append(
                ComparedCnvdEntry(
                    **entry.model_dump(),
                    source_comparison=compare_cnvd_severity(entry, record),
                )
            )
        carries_cnvd = carries_cnvd or bool(compared_entries)
        lookup_record = LookupCveRecord.model_validate(
            {
                **record.model_dump(),
                "cnvd": tuple(compared_entries),
            }
        )
        candidates.append(
            LookupCandidate.model_validate(
                {
                    **candidate.model_dump(),
                    "record": lookup_record,
                }
            )
        )
    pending_entries = cnvd_index.pending_by_cve_id.get(cve_id or "", ())
    if identifier.startswith("CNVD-"):
        pending = cnvd_index.pending_by_cnvd_id.get(identifier)
        pending_entries = () if pending is None else (pending,)
    pending_lookups: list[PendingCnvdLookup] = []
    anchors_by_id = {}
    for anchor in search.evidence:
        anchors_by_id[anchor.evidence_id] = anchor
    for pending in pending_entries:
        entry = pending.entry
        pending_lookups.append(
            PendingCnvdLookup(
                **entry.model_dump(),
                cve_id=pending.cve_id,
                outcome=pending.outcome,
                source_comparison=compare_cnvd_severity(entry, None, pending.outcome),
            )
        )
        pending_anchor = evidence_catalog.get_evidence(entry.evidence_id)
        if pending_anchor is None:
            raise EvidenceValidationError(["a pending CNVD entry cites unstored evidence"])
        validate_served_anchor(pending_anchor, None)
        anchors_by_id[pending_anchor.evidence_id] = pending_anchor
    carries_cnvd = carries_cnvd or bool(pending_lookups)
    if carries_cnvd and cnvd_attribution is None:
        raise EvidenceValidationError(["CNVD content requires source registry attribution"])
    warnings = []
    for warning in search.warnings:
        if pending_lookups and warning.code is SearchWarningCode.UNKNOWN_CVE_ID:
            continue
        warnings.append(warning)
    anchors = []
    for evidence_id in sorted(anchors_by_id):
        anchors.append(anchors_by_id[evidence_id])
    lookup = CveLookupResponse.model_validate(
        {
            **search.model_dump(),
            "query": identifier,
            "normalized_query": identifier.lower(),
            "candidates": tuple(candidates),
            "pending_cnvd": tuple(pending_lookups),
            "evidence": tuple(anchors),
            "warnings": tuple(warnings),
            "status": ResultStatus.OK if pending_lookups else search.status,
            "cnvd_attribution": cnvd_attribution if carries_cnvd else None,
            "cnvd_language": cnvd_language if carries_cnvd else None,
            "not_found_statement": (
                CNVD_NOT_FOUND_STATEMENT
                if identifier.startswith("CNVD-") and not candidates and not pending_lookups
                else None
            ),
        }
    )
    lookup = lookup.model_copy(update={"result_sha256": lookup.compute_result_sha256()})
    validate_search_response(lookup, evidence_catalog)
    return lookup
