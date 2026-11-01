"""Check untrusted session files for consistency and citation resolution only."""

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from yaml import YAMLError

from vulnwitness.adapters.session.files import check_session_path, read_session_file
from vulnwitness.adapters.session.validation import parse_session_document
from vulnwitness.adapters.strict_yaml import load_declaration_yaml
from vulnwitness.domain.evidence import EvidenceAnchor
from vulnwitness.domain.session_contracts import CLI_SESSION_CONTRACTS, MCP_SESSION_CONTRACTS
from vulnwitness.domain.session_record import (
    SessionCall,
    SessionCheckReport,
    SessionFindings,
    SessionRecord,
    SessionViolation,
)
from vulnwitness.domain.session_response import SESSION_RESPONSE_MODELS
from vulnwitness.domain.tool_contracts import ToolFailure


def collect_response_anchors(document: Any) -> set[str]:
    """Only complete anchor objects count; references containing a bare ID do not."""
    anchors: set[str] = set()
    pending = [document]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            if "evidence_id" in node:
                try:
                    anchor = EvidenceAnchor.model_validate(node)
                except ValidationError:
                    pass
                else:
                    anchors.add(anchor.evidence_id)
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    return anchors


class SessionChecker:
    """Read a bounded session tree. Never execute instructions or follow file links."""

    def __init__(self, directory: Path) -> None:
        self._directory = directory
        self._violations: list[SessionViolation] = []
        self._calls: dict[int, SessionCall] = {}
        self._anchors: dict[int, set[str]] = {}
        self._citations_checked = 0

    def check(self) -> SessionCheckReport:
        self._violations.clear()
        self._calls.clear()
        self._anchors.clear()
        self._citations_checked = 0
        try:
            check_session_path(self._directory)
            session = parse_session_document(
                read_session_file(self._directory / "session.json"), SessionRecord
            )
        except (OSError, ValueError, RecursionError):
            self._add("session.json", "session metadata is unreadable or invalid")
            return self._report()
        self._check_calls(session)
        self._check_findings(session)
        return self._report()

    def _add(self, location: str, message: str) -> None:
        self._violations.append(SessionViolation(location=location, message=message))

    def _report(self) -> SessionCheckReport:
        return SessionCheckReport(
            passed=not self._violations,
            calls_checked=len(self._calls),
            citations_checked=self._citations_checked,
            violations=tuple(self._violations),
        )

    def _list_files(self, name: str) -> list[Path]:
        directory = self._directory / name
        try:
            check_session_path(directory)
            paths: list[Path] = []
            for path in directory.iterdir():
                paths.append(path)
                if len(paths) > 100:
                    raise ValueError("too many session files")
            return sorted(paths)
        except (OSError, ValueError):
            self._add(name, "directory is unreadable, linked, or contains too many files")
            return []

    def _check_calls(self, session: SessionRecord) -> None:
        call_paths = self._list_files("calls")
        response_paths = self._list_files("responses")
        expected_responses: set[str] = set()
        if len(call_paths) > session.call_limit:
            self._add("calls", "call count exceeds the session limit")
        for expected_sequence, call_path in enumerate(call_paths, start=1):
            location = f"calls/{call_path.name}"
            if call_path.name != f"{expected_sequence:04d}.json":
                self._add(location, "sequence numbers must be contiguous starting at 1")
            try:
                call = parse_session_document(read_session_file(call_path), SessionCall)
            except (OSError, ValueError, RecursionError):
                self._add(location, "call is unreadable or invalid")
                continue
            if call.sequence != expected_sequence:
                self._add(location + ".sequence", "sequence differs from its file position")
            if call.sequence in self._calls:
                self._add(location + ".sequence", "duplicate sequence")
                continue
            self._calls[call.sequence] = call
            self._check_call_contract(call, location)
            if call.dataset != session.dataset:
                self._add(location + ".dataset", "dataset differs from session.json")
            expected_response = f"responses/{call.sequence:04d}.json"
            expected_responses.add(expected_response)
            if call.response_file != expected_response:
                self._add(location + ".response_file", "response filename differs from sequence")
            self._check_response(call, expected_response)
        for response_path in response_paths:
            relative = f"responses/{response_path.name}"
            if relative not in expected_responses:
                self._add(relative, "response has no corresponding call")

    def _check_call_contract(self, call: SessionCall, location: str) -> None:
        contracts = CLI_SESSION_CONTRACTS if call.interface == "cli" else MCP_SESSION_CONTRACTS
        contract = contracts.get(call.command)
        if contract is None:
            if call.outcome == "ok" or call.request is not None:
                self._add(location + ".command", "unknown command must be a failed invalid request")
            return
        request_model, response_model = contract
        expected_schema = response_model.__name__ if call.outcome == "ok" else "ToolFailure"
        if call.response_schema != expected_schema:
            self._add(location + ".response_schema", "schema differs from the command contract")
        if call.request is not None:
            try:
                request_model.model_validate_json(json.dumps(call.request))
            except ValueError:
                self._add(location + ".request", "request does not match the command contract")

    def _check_response(self, call: SessionCall, location: str) -> None:
        response_model = SESSION_RESPONSE_MODELS.get(call.response_schema)
        if response_model is None:
            self._add(location, "unknown response schema")
            return
        try:
            content = read_session_file(self._directory / location)
            answer = parse_session_document(content, response_model)
            document = json.loads(content)
        except (OSError, ValueError, RecursionError):
            self._add(location, "response is unreadable or does not match its schema")
            return
        if isinstance(answer, ToolFailure):
            if call.outcome != answer.code:
                self._add(location, "failure kind differs from call outcome")
        elif call.outcome != "ok":
            self._add(location, "failed call must have a failure response")
        if call.request is None and call.outcome == "ok":
            self._add(f"calls/{call.sequence:04d}.json.request", "successful call needs a request")
        self._anchors[call.sequence] = collect_response_anchors(document)

    def _check_findings(self, session: SessionRecord) -> None:
        try:
            findings = SessionFindings.model_validate(
                load_declaration_yaml(
                    read_session_file(self._directory / "findings.yaml").decode("utf-8")
                )
            )
        except (OSError, ValueError, YAMLError, RecursionError):
            self._add("findings.yaml", "findings are unreadable or invalid")
            return
        for finding_index, finding in enumerate(findings.findings):
            for citation_index, citation in enumerate(finding.citations):
                self._citations_checked += 1
                location = f"findings.yaml.findings[{finding_index}].citations[{citation_index}]"
                call = self._calls.get(citation.call)
                if call is None:
                    self._add(location, "cited call does not exist")
                elif call.outcome != "ok":
                    self._add(location, "cited call did not succeed")
                elif call.dataset != session.dataset:
                    self._add(location, "cited call belongs to another dataset")
                elif citation.evidence_id not in self._anchors.get(citation.call, set()):
                    self._add(location, "evidence anchor is absent from the cited response")


def render_session_check(report: SessionCheckReport) -> str:
    lines = [
        "Session check: " + ("passed" if report.passed else "failed"),
        f"Calls checked: {report.calls_checked}; citations checked: {report.citations_checked}.",
    ]
    for violation in report.violations:
        lines.append(f"{violation.location}: {violation.message}")
    lines.append(report.support_limitation)
    return "\n".join(lines)
