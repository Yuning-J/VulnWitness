"""Pending CNVD entries and the in-memory indexes a served corpus holds."""

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal, Self

from pydantic import ConfigDict, Field, model_validator

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
    imported_revision: str | None = None
    source_name: str | None = None


class CnvdCapability(ContractModel):
    model_config = ConfigDict(
        json_schema_extra={
            "if": {"properties": {"imported": {"const": True}}},
            "then": {},
            "else": {"properties": {"revision": {"type": "null"}}},
        }
    )

    imported: bool
    revision: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{40}$",
        description="Pinned Hugging Face revision; null for raw CNVD inputs.",
    )

    @model_validator(mode="after")
    def check_import_revision(self) -> Self:
        if not self.imported and self.revision is not None:
            raise ValueError("only an imported CNVD source names a pinned revision")
        return self


def build_cnvd_index(
    records: Sequence[CveRecord],
    pending_entries: Sequence[PendingCnvdEntry],
    imported_revision: str | None = None,
    source_name: str | None = None,
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
    return CnvdIndex(
        pending_by_cve_id,
        pending_by_cnvd_id,
        cve_id_by_cnvd_id,
        imported_revision,
        source_name or ("circl-cnvd" if imported_revision is not None else None),
    )


def cnvd_source_row(entry: CnvdEntry, cve_id: str, *, raw: bool = False) -> dict[str, object]:
    """The retained CNVD fields for one CVE link, bound by its row anchor."""
    source_severity = {"high": "高", "medium": "中", "low": "低"}
    source_fields: dict[str, object] = {
        "id": entry.cnvd_id,
        "title": entry.title,
        "description": entry.description,
        "severity": source_severity[entry.severity],
        "cve_id": cve_id,
        "source": "cnvd",
    }
    if raw:
        source_fields.update(
            {
                "products": entry.products,
                "submit_time": None if entry.submit_time is None else entry.submit_time.isoformat(),
                "open_time": None if entry.open_time is None else entry.open_time.isoformat(),
                "handling_advice": entry.handling_advice,
            }
        )
    return source_fields
