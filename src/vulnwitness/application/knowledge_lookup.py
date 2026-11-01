"""Evidence-anchor lookup shared by every serving surface."""

from vulnwitness.application.investigation_deployment import InvestigationDeployment
from vulnwitness.domain.tool_contracts import EvidenceLookup
from vulnwitness.domain.validation import validate_served_anchor


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
