"""Workflow artifact storage is independent of the application orchestration."""

from typing import Protocol

from vulnwitness.domain.session_record import SessionCheckReport, SessionFindings
from vulnwitness.domain.triage import TriageSummary


class TriageArtifacts(Protocol):
    def require_empty(self) -> None:
        """Refuse a linked, non-directory or non-empty session path without writing."""
        ...

    def write_findings(self, findings: SessionFindings) -> None: ...

    def check(self) -> SessionCheckReport: ...

    def write_summary(self, summary: TriageSummary) -> None: ...
