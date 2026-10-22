"""Lookups every surface answers the same way: one CVE by its ID, and one served evidence
anchor by its evidence ID."""

from cve_kgrag.application.investigation_deployment import InvestigationDeployment
from cve_kgrag.application.search import SearchService
from cve_kgrag.domain.search import SearchRequest, SearchResponse
from cve_kgrag.domain.tool_contracts import EvidenceLookup
from cve_kgrag.domain.validation import validate_served_anchor


def lookup_cve(search_service: SearchService, cve_id: str) -> SearchResponse:
    """The search for exactly ``cve_id``, one result at most: ``ok`` with its record, or
    ``no_match`` with an ``unknown_cve_id`` warning."""
    return search_service.search(SearchRequest(query=cve_id, limit=1))


def find_served_evidence(
    deployment: InvestigationDeployment, evidence_id: str
) -> EvidenceLookup | None:
    """The anchor ``deployment`` catalogues under ``evidence_id``, or ``None`` when it holds
    none. An anchor is served only when it passes the anchor rules every response applies
    (``validate_served_anchor``, which raises ``EvidenceValidationError``)."""
    anchor = deployment.evidence_catalog.get_evidence(evidence_id)
    if anchor is None:
        return None
    validate_served_anchor(anchor, deployment.pinned_fight_snapshot)
    return EvidenceLookup(evidence=anchor)
