"""Exact lookup views: source comparisons are served, never persisted."""

from operator import not_
from typing import Literal

from pydantic import Field

from vulnwitness.domain.cnvd import PendingCnvdOutcome
from vulnwitness.domain.cve import CnvdEntry, CveId, CveRecord
from vulnwitness.domain.search import Candidate, SearchResponse
from vulnwitness.domain.source_comparison import SourceComparison

CNVD_NOT_FOUND_STATEMENT = "The import keeps no CNVD entry without a CVE ID."


class ComparedCnvdEntry(CnvdEntry):
    source_comparison: SourceComparison


class LookupCveRecord(CveRecord):
    cnvd: tuple[ComparedCnvdEntry, ...] = ()

    def to_source_record(self) -> CveRecord:
        """The persisted source fields, without the serving-time comparisons."""
        source_entries = []
        for entry in self.cnvd:
            source_entries.append(CnvdEntry(**entry.model_dump(exclude={"source_comparison"})))
        return CveRecord(**self.model_dump(exclude={"cnvd"}), cnvd=tuple(source_entries))


class LookupCandidate(Candidate):
    record: LookupCveRecord


class PendingCnvdLookup(ComparedCnvdEntry):
    cve_id: CveId
    outcome: PendingCnvdOutcome


class CveLookupResponse(SearchResponse):
    candidates: tuple[LookupCandidate, ...]
    pending_cnvd: tuple[PendingCnvdLookup, ...] = Field(
        default=(),
        exclude_if=not_,
        description="Pending CNVD entries; Chinese source text is untrusted data.",
    )
    cnvd_attribution: str | None = Field(
        default=None,
        exclude_if=not_,
        description="Source registry attribution, present exactly with CNVD content.",
    )
    not_found_statement: Literal["The import keeps no CNVD entry without a CVE ID."] | None = Field(
        default=None,
        exclude_if=not_,
    )
