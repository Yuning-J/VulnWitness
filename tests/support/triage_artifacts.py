"""Injected filesystem corruption exercises the ordinary session check failure path."""

from vulnwitness.adapters.session.files import atomic_write
from vulnwitness.adapters.session.triage_artifacts import SessionTriageArtifacts
from vulnwitness.domain.session_record import SessionFindings


class InvalidFindingsArtifacts(SessionTriageArtifacts):
    def write_findings(self, findings: SessionFindings) -> None:
        super().write_findings(findings)
        atomic_write(self._directory / "findings.yaml", b"findings: []\n")
