"""In-memory catalog of what a deployment's sources hold."""

from collections.abc import Callable, Iterable
from itertools import chain
from operator import attrgetter
from typing import TypeVar

from vulnwitness.domain.cve import CveRecord
from vulnwitness.domain.evidence import EvidenceAnchor
from vulnwitness.domain.product_query import ProductIdentity, list_product_identities
from vulnwitness.domain.threat_context import ThreatContextItem
from vulnwitness.domain.validation import EvidenceValidationError
from vulnwitness.domain.weakness_associations import WeaknessAssociations
from vulnwitness.domain.weakness_mapping import WeaknessMapping

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
        weakness_mapping: WeaknessMapping | None = None,
    ) -> None:
        self._weakness_mapping = weakness_mapping
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
        product_entries = chain.from_iterable(
            map(CveRecord.list_implicated_products, self._records_by_id.values())
        )
        identities_by_name: dict[str, list[ProductIdentity]] = {}
        for identity in list_product_identities(product_entries):
            for name in sorted({identity.vendor, identity.product}):
                identities_by_name.setdefault(name, []).append(identity)
        self._identities_by_name: dict[str, tuple[ProductIdentity, ...]] = {}
        for name, named_identities in identities_by_name.items():
            self._identities_by_name[name] = tuple(named_identities)

    def get_evidence(self, evidence_id: str) -> EvidenceAnchor | None:
        return self._anchors_by_id.get(evidence_id)

    def get_cve(self, cve_id: str) -> CveRecord | None:
        return self._records_by_id.get(cve_id)

    def get_technique(self, technique_id: str) -> ThreatContextItem | None:
        return self._techniques_by_id.get(technique_id)

    def get_weakness_associations(self, cve_id: str) -> WeaknessAssociations | None:
        record = self.get_cve(cve_id)
        if record is None or self._weakness_mapping is None:
            return None
        return self._weakness_mapping.associate(record)

    def find_product_identities(self, name: str) -> tuple[ProductIdentity, ...]:
        return self._identities_by_name.get(name.casefold(), ())

    def names_product(self, name: str) -> bool:
        return name.casefold() in self._identities_by_name
