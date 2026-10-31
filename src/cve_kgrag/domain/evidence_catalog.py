"""The lookup final validation re-checks served content against."""

from typing import Protocol

from cve_kgrag.domain.cve import CveRecord
from cve_kgrag.domain.evidence import EvidenceAnchor
from cve_kgrag.domain.product_query import ProductIdentity
from cve_kgrag.domain.threat_context import ThreatContextItem
from cve_kgrag.domain.weakness_associations import WeaknessAssociations


class EvidenceCatalog(Protocol):
    """What a deployment's configured sources hold: evidence anchors by evidence ID, CVE
    records by CVE ID and FiGHT techniques by technique ID.

    Final validation re-checks every anchor, CVE record and FiGHT technique a response
    serves against the catalog. Evidence IDs and result hashes show a response is
    internally consistent; the catalog shows its content comes from this service's
    sources.
    """

    def get_evidence(self, evidence_id: str) -> EvidenceAnchor | None:
        """The anchor with this ID, or ``None`` when the catalog has none."""
        ...

    def get_cve(self, cve_id: str) -> CveRecord | None:
        """The record for an upper-case CVE ID, or ``None`` when the catalog has none."""
        ...

    def get_technique(self, technique_id: str) -> ThreatContextItem | None:
        """The technique as its source indexes it, with no ``matched_fields`` or
        ``matched_terms``, or ``None`` when the catalog has none."""
        ...

    def get_weakness_associations(self, cve_id: str) -> WeaknessAssociations | None:
        """The snapshot-derived associations for this record, or None without a mapping."""
        ...

    def find_product_identities(self, name: str) -> tuple[ProductIdentity, ...]:
        """Unique served pairs naming this whole vendor or product, sorted by name."""
        ...

    def names_product(self, name: str) -> bool:
        """Whether some record names a product it is not marked unaffected by with ``name``,
        case-folded, as its whole vendor or product."""
        ...
