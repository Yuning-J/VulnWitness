"""Knowledge sources other than the CVE retrieval channels."""

from collections.abc import Sequence
from typing import Protocol

from vulnwitness.domain.evidence import EvidenceAnchor
from vulnwitness.domain.threat_context import (
    FightSnapshotInfo,
    ThreatContextItem,
    ThreatContextOutcome,
)


class FightSource(Protocol):
    def describe(self) -> FightSnapshotInfo | None:
        """The verified snapshot served, or ``None`` when no snapshot is available."""
        ...

    def search(self, terms: Sequence[str], limit: int) -> ThreatContextOutcome:
        """Up to ``limit`` techniques naming any of ``terms``, each with its evidence anchor."""
        ...

    def list_evidence(self) -> Sequence[EvidenceAnchor]:
        """Every anchor ``search`` can return; empty when no snapshot is served."""
        ...

    def list_techniques(self) -> Sequence[ThreatContextItem]:
        """Every technique ``search`` can return, as indexed: with no ``matched_fields`` or
        ``matched_terms``. Empty when no snapshot is served."""
        ...
