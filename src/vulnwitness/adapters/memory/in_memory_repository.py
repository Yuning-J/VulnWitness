"""In-memory CVE record store, checked for referential integrity on construction."""

from collections.abc import Iterable, Sequence

from vulnwitness.domain.cve import CveRecord
from vulnwitness.domain.evidence import EvidenceAnchor
from vulnwitness.domain.validation import EvidenceValidationError, find_anchor_violations


class InMemoryKnowledgeRepository:
    """Implements ``CveRepository`` over immutable records.

    Construction rejects duplicate IDs, records citing evidence outside ``anchors`` and
    anchors that break a scope invariant, so lookups only ever return stored, valid
    data.
    """

    def __init__(self, records: Iterable[CveRecord], anchors: Iterable[EvidenceAnchor]) -> None:
        record_anchors = list(anchors)
        violations = find_anchor_violations(record_anchors)
        evidence_ids: set[str] = set()
        for anchor in record_anchors:
            if anchor.evidence_id in evidence_ids:
                violations.append(f"duplicate evidence id {anchor.evidence_id}")
            evidence_ids.add(anchor.evidence_id)

        self._records_by_id: dict[str, CveRecord] = {}
        for record in sorted(records, key=lambda record: record.cve_id):
            if record.cve_id in self._records_by_id:
                violations.append(f"duplicate record {record.cve_id}")
            for evidence_id in record.evidence_ids:
                if evidence_id not in evidence_ids:
                    violations.append(f"{record.cve_id} cites unknown evidence {evidence_id}")
            self._records_by_id[record.cve_id] = record

        if violations:
            raise EvidenceValidationError(violations)

    def get_cve(self, cve_id: str) -> CveRecord | None:
        return self._records_by_id.get(cve_id)

    def list_cves(self) -> Sequence[CveRecord]:
        return tuple(self._records_by_id.values())
