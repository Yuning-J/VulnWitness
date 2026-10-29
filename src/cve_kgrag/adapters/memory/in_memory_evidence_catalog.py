"""In-memory catalog of what a deployment's sources hold."""

from collections.abc import Callable, Iterable
from operator import attrgetter
from typing import TypeVar

from cve_kgrag.domain.cve import CveRecord
from cve_kgrag.domain.evidence import EvidenceAnchor
from cve_kgrag.domain.threat_context import ThreatContextItem
from cve_kgrag.domain.validation import EvidenceValidationError

CatalogEntry = TypeVar("CatalogEntry", EvidenceAnchor, CveRecord, ThreatContextItem)


def index_entries(
    entries: Iterable[CatalogEntry],
    read_entry_id: Callable[[CatalogEntry], str],
    entry_kind: str,
    violations: list[str],
) -> dict[str, CatalogEntry]:
    """``entries`` by ID; two different entries under one ID add a violation."""
    entries_by_id: dict[str, CatalogEntry] = {}
    for entry in entries:
        entry_id = read_entry_id(entry)
        catalogued_entry = entries_by_id.setdefault(entry_id, entry)
        if catalogued_entry != entry:
            violations.append(f"two different {entry_kind} share id {entry_id}")
    return entries_by_id


class InMemoryEvidenceCatalog:
    """Implements ``EvidenceCatalog`` over the anchors, CVE records and FiGHT techniques the
    composition root collects.

    The same entry may be supplied more than once; two different entries under one ID
    are rejected on construction, so a lookup never depends on order. Techniques are
    supplied as their source indexes them, with no matched fields or terms.
    """

    def __init__(
        self,
        anchors: Iterable[EvidenceAnchor],
        records: Iterable[CveRecord],
        techniques: Iterable[ThreatContextItem] = (),
    ) -> None:
        violations: list[str] = []
        self._anchors_by_id = index_entries(
            anchors, attrgetter("evidence_id"), "anchors", violations
        )
        self._records_by_id = index_entries(records, attrgetter("cve_id"), "records", violations)
        self._techniques_by_id = index_entries(
            techniques, attrgetter("technique_id"), "techniques", violations
        )
        if violations:
            raise EvidenceValidationError(violations)
        product_names: set[str] = set()
        for record in self._records_by_id.values():
            for implicated_product in record.list_implicated_products():
                product_names.add(implicated_product.vendor.casefold())
                product_names.add(implicated_product.product.casefold())
        self._product_names = frozenset(product_names)

    def get_evidence(self, evidence_id: str) -> EvidenceAnchor | None:
        return self._anchors_by_id.get(evidence_id)

    def get_cve(self, cve_id: str) -> CveRecord | None:
        return self._records_by_id.get(cve_id)

    def get_technique(self, technique_id: str) -> ThreatContextItem | None:
        return self._techniques_by_id.get(technique_id)

    def names_product(self, name: str) -> bool:
        return name.casefold() in self._product_names
