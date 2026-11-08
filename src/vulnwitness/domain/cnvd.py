"""Pending CNVD entries and the in-memory indexes a served corpus holds."""

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.cve import CnvdEntry, CveId, CveRecord

PendingCnvdOutcome = Literal[
    "cnvd_without_nvd_record",
    "cnvd_for_rejected_nvd_record",
    "cnvd_for_excluded_nvd_record",
]


class PendingCnvdEntry(ContractModel):
    """One CNVD entry whose CVE has no servable NVD record in this store."""

    cve_id: CveId
    outcome: PendingCnvdOutcome
    entry: CnvdEntry


@dataclass(frozen=True)
class CnvdIndex:
    """Pending entries by both identifiers, and every stored CNVD ID's CVE ID."""

    pending_by_cve_id: dict[str, tuple[PendingCnvdEntry, ...]] = field(default_factory=dict)
    pending_by_cnvd_id: dict[str, PendingCnvdEntry] = field(default_factory=dict)
    cve_id_by_cnvd_id: dict[str, str] = field(default_factory=dict)


def build_cnvd_index(
    records: Sequence[CveRecord], pending_entries: Sequence[PendingCnvdEntry]
) -> CnvdIndex:
    """Index entries already validated at the corpus loading boundary."""
    pending_groups: dict[str, list[PendingCnvdEntry]] = {}
    pending_by_cnvd_id: dict[str, PendingCnvdEntry] = {}
    cve_id_by_cnvd_id: dict[str, str] = {}
    for record in records:
        for entry in record.cnvd:
            cve_id_by_cnvd_id[entry.cnvd_id] = record.cve_id
    for pending in pending_entries:
        pending_groups.setdefault(pending.cve_id, []).append(pending)
        pending_by_cnvd_id[pending.entry.cnvd_id] = pending
        cve_id_by_cnvd_id[pending.entry.cnvd_id] = pending.cve_id
    pending_by_cve_id: dict[str, tuple[PendingCnvdEntry, ...]] = {}
    for cve_id, entries in pending_groups.items():
        pending_by_cve_id[cve_id] = tuple(entries)
    return CnvdIndex(pending_by_cve_id, pending_by_cnvd_id, cve_id_by_cnvd_id)


def cnvd_source_row(entry: CnvdEntry, cve_id: str) -> dict[str, str]:
    """The six source columns represented by a stored entry, for anchor verification."""
    source_severity = {"high": "高", "medium": "中", "low": "低"}
    return {
        "id": entry.cnvd_id,
        "title": entry.title,
        "description": entry.description,
        "severity": source_severity[entry.severity],
        "cve_id": cve_id,
        "source": "cnvd",
    }
