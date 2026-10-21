"""Read-only record lookups the application depends on."""

from collections.abc import Sequence
from typing import Protocol

from cve_kgrag.domain.cve import CveRecord


class CveRepository(Protocol):
    def get_cve(self, cve_id: str) -> CveRecord | None:
        """The record for an upper-case CVE ID, or ``None`` when the store has none."""
        ...

    def list_cves(self) -> Sequence[CveRecord]:
        """Every record, ordered by CVE ID."""
        ...
