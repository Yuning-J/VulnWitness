"""Private, atomic workflow artifacts beside the existing session record."""

from pathlib import Path

import yaml

from vulnwitness.adapters.session.check import SessionChecker
from vulnwitness.adapters.session.files import atomic_write, check_session_path
from vulnwitness.domain.session_record import SessionCheckReport, SessionFindings
from vulnwitness.domain.triage import TriageSummary


class SessionTriageArtifacts:
    """Publish workflow files atomically and delegate verification to the session checker."""

    def __init__(
        self, directory: Path, store_root: Path | None = None, *, prepared: bool = False
    ) -> None:
        self._prepared = prepared
        self._directory = directory
        self._store_root = store_root

    def require_empty(self) -> None:
        check_session_path(self._directory, self._store_root)
        if self._prepared:
            if (
                any((self._directory / "calls").iterdir())
                or not (self._directory / "triage.started.json").is_file()
            ):
                raise ValueError("prepared triage must have no calls and a started marker")
            return
        if self._directory.exists() and any(self._directory.iterdir()):
            raise ValueError(
                "triage requires an empty or new session directory; no resume or append"
            )

    def write_findings(self, findings: SessionFindings) -> None:
        document = yaml.safe_dump(findings.model_dump(mode="json"), sort_keys=False)
        atomic_write(self._directory / "findings.yaml", document.encode("utf-8"))

    def check(self) -> SessionCheckReport:
        return SessionChecker(self._directory).check()

    def write_summary(self, summary: TriageSummary) -> None:
        atomic_write(
            self._directory / "triage.json", (summary.model_dump_json(indent=2) + "\n").encode()
        )
