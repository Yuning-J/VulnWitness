"""CNVD entries and their row anchors, joined only after NVD candidate resolution."""

from dataclasses import dataclass
from typing import Literal

from vulnwitness.adapters.migration.cnvd_types import CnvdRow
from vulnwitness.adapters.migration.input_resolution import ResolvedInput
from vulnwitness.adapters.nvd.normalizer import NormalizedCve
from vulnwitness.domain.cnvd import cnvd_source_row
from vulnwitness.domain.corpus_store_manifest import StoreSource
from vulnwitness.domain.cve import CnvdEntry
from vulnwitness.domain.evidence import (
    UNSEALED_EVIDENCE_ID,
    EvidenceAnchor,
    seal_evidence_anchor,
)
from vulnwitness.domain.hashing import canonical_sha256
from vulnwitness.domain.taxonomy import AssertionKind, KnowledgeScope, SourceType, TrustLevel


@dataclass(frozen=True)
class SourcedCnvdRow:
    row: CnvdRow
    input: ResolvedInput
    revision: str


def build_cnvd_entry(source: SourcedCnvdRow, terms: str) -> tuple[CnvdEntry, EvidenceAnchor]:
    """Normalize retained CNVD fields and bind each CVE link to its own source anchor."""
    row = source.row
    is_raw = source.input.source is StoreSource.VULNERABILITY_LOOKUP_CNVD
    severities: dict[str, Literal["high", "medium", "low"]] = {
        "高": "high",
        "中": "medium",
        "低": "low",
    }
    entry = CnvdEntry(
        cnvd_id=row.cnvd_id,
        title=row.title,
        description=row.description,
        severity=severities[row.severity],
        products=row.products,
        submit_time=row.submit_time,
        open_time=row.open_time,
        handling_advice=row.handling_advice,
        evidence_id=UNSEALED_EVIDENCE_ID,
    )
    anchor = seal_evidence_anchor(
        EvidenceAnchor(
            evidence_id=UNSEALED_EVIDENCE_ID,
            source_name=source.input.source.value,
            source_type=(
                SourceType.VULNERABILITY_LOOKUP_CNVD_NDJSON
                if is_raw
                else SourceType.CIRCL_CNVD_PARQUET
            ),
            authoritative_record_id=row.cnvd_id,
            source_uri=source.input.source_uri,
            source_version=source.revision,
            retrieved_at=source.input.retrieved_at,
            content_sha256=canonical_sha256(cnvd_source_row(entry, row.cve_id, raw=is_raw)),
            locator=f"id={row.cnvd_id}",
            scope=KnowledgeScope.IMPLEMENTATION_VULNERABILITY,
            assertion_kind=AssertionKind.ASSERTED,
            license_or_terms_ref=terms,
            trust_level=TrustLevel.SECONDARY,
        )
    )
    return entry.model_copy(update={"evidence_id": anchor.evidence_id}), anchor


def enrich_cnvd(
    normalized: NormalizedCve, sources: list[SourcedCnvdRow], terms: str
) -> NormalizedCve:
    """Attach all the CVE's CNVD entries in CNVD ID order, with their evidence."""
    entries: list[CnvdEntry] = []
    anchors = list(normalized.evidence)
    evidence_ids = list(normalized.record.evidence_ids)
    for source in sources:
        entry, anchor = build_cnvd_entry(source, terms)
        entries.append(entry)
        anchors.append(anchor)
        evidence_ids.append(anchor.evidence_id)
    record = normalized.record.model_copy(
        update={"cnvd": tuple(entries), "evidence_ids": tuple(evidence_ids)}
    )
    return NormalizedCve(record, tuple(anchors))
