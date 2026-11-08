"""Check untrusted session files for consistency, citation resolution and structured claims."""

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError
from yaml import YAMLError

from vulnwitness.adapters.session.files import check_session_path, read_session_file
from vulnwitness.adapters.session.validation import parse_session_document
from vulnwitness.adapters.strict_yaml import load_declaration_yaml
from vulnwitness.domain.evidence import EvidenceAnchor
from vulnwitness.domain.hashing import sha256_hex
from vulnwitness.domain.session_claim_check import check_session_claim
from vulnwitness.domain.session_contracts import CLI_SESSION_CONTRACTS, MCP_SESSION_CONTRACTS
from vulnwitness.domain.session_record import (
    SessionCall,
    SessionCheckReport,
    SessionCitationCheck,
    SessionClaimCheck,
    SessionClaimsCheck,
    SessionFindings,
    SessionNotChecked,
    SessionRecord,
    SessionRecordCheck,
    SessionViolation,
)
from vulnwitness.domain.session_report import CheckedSession
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

    def __init__(self, directory: Path, findings: SessionFindings | None = None) -> None:
        self._findings_override = findings
        self._directory = directory
        self._violations: list[SessionViolation] = []
        self._calls: dict[int, SessionCall] = {}
        self._anchors: dict[int, set[str]] = {}
        self._citations_checked = 0
        self._citation_violations: list[SessionViolation] = []
        self._claim_checks: list[SessionClaimCheck] = []
        self._not_checked: list[str] = []
        self._responses: dict[int, BaseModel] = {}
        self._session: SessionRecord | None = None
        self._findings: SessionFindings | None = None
        self._recorded_responses: dict[int, BaseModel] = {}
        self._response_digests: dict[int, str] = {}

    def check_with_contents(self) -> CheckedSession:
        """Return the check and the same parsed files it checked, without rereading them."""
        report = self.check()
        response_digests: dict[int, str] = {}
        for sequence in self._responses:
            response_digests[sequence] = self._response_digests[sequence]
        return CheckedSession(
            check=report,
            session=self._session,
            calls=tuple(self._calls.values()),
            responses=dict(self._recorded_responses),
            response_digests=response_digests,
            findings=self._findings,
        )

    def check(self) -> SessionCheckReport:
        self._violations.clear()
        self._calls.clear()
        self._anchors.clear()
        self._citations_checked = 0
        self._citation_violations.clear()
        self._claim_checks.clear()
        self._not_checked.clear()
        self._responses.clear()
        self._session = None
        self._findings = None
        self._recorded_responses.clear()
        self._response_digests.clear()
        try:
            check_session_path(self._directory)
            session = parse_session_document(
                read_session_file(self._directory / "session.json"), SessionRecord
            )
        except (OSError, ValueError, RecursionError):
            self._add("session.json", "session metadata is unreadable or invalid")
            return self._report()
        self._session = session
        self._check_calls(session)
        self._check_findings(session)
        return self._report()

    def _add(self, location: str, message: str) -> None:
        self._violations.append(SessionViolation(location=location, message=message))

    def _report(self) -> SessionCheckReport:
        return SessionCheckReport(
            superseded_count=(
                len(self._findings.findings) - len(self._findings.effective_findings())
                if self._findings is not None
                else 0
            ),
            record=SessionRecordCheck(
                consistent=not self._violations,
                calls_checked=len(self._calls),
                violations=tuple(self._violations),
            ),
            citations=SessionCitationCheck(
                resolved=not self._citation_violations,
                citations_checked=self._citations_checked,
                violations=tuple(self._citation_violations),
            ),
            claims=SessionClaimsCheck(
                verified=all(check.status == "verified" for check in self._claim_checks),
                checks=tuple(self._claim_checks),
            ),
            not_checked=SessionNotChecked(
                count=len(self._not_checked), finding_ids=tuple(self._not_checked)
            ),
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
            violation_count = len(self._violations)
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
            answer = self._check_response(call, expected_response)
            if (
                answer is not None
                and call.outcome == "ok"
                and len(self._violations) == violation_count
            ):
                self._responses[call.sequence] = answer
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

    def _check_response(self, call: SessionCall, location: str) -> BaseModel | None:
        response_model = SESSION_RESPONSE_MODELS.get(call.response_schema)
        if response_model is None:
            self._add(location, "unknown response schema")
            return None
        try:
            content = read_session_file(self._directory / location)
            response_digest = sha256_hex(content)
            if call.response_sha256 is not None and call.response_sha256 != response_digest:
                self._add(location, "response bytes differ from the recorded input digest")
            answer = parse_session_document(content, response_model)
            document = json.loads(content)
        except (OSError, ValueError, RecursionError):
            self._add(location, "response is unreadable or does not match its schema")
            return None
        if isinstance(answer, ToolFailure):
            if call.outcome != answer.code:
                self._add(location, "failure kind differs from call outcome")
        elif call.outcome != "ok":
            self._add(location, "failed call must have a failure response")
        if call.request is None and call.outcome == "ok":
            self._add(f"calls/{call.sequence:04d}.json.request", "successful call needs a request")
        self._anchors[call.sequence] = collect_response_anchors(document)
        self._recorded_responses[call.sequence] = answer
        self._response_digests[call.sequence] = response_digest
        return answer

    def _check_findings(self, session: SessionRecord) -> None:
        try:
            findings = self._findings_override or SessionFindings.model_validate(
                load_declaration_yaml(
                    read_session_file(self._directory / "findings.yaml").decode("utf-8")
                )
            )
        except (OSError, ValueError, YAMLError, RecursionError):
            self._add("findings.yaml", "findings are unreadable or invalid")
            return
        self._findings = findings
        effective_ids: set[str] = set()
        for finding in findings.effective_findings():
            effective_ids.add(finding.id)
        for finding_index, finding in enumerate(findings.findings):
            if finding.id not in effective_ids:
                continue
            if finding.claim is None:
                self._not_checked.append(finding.id)
            else:
                self._claim_checks.append(
                    check_session_claim(
                        finding.id, finding.claim, self._responses.get(finding.claim.call)
                    )
                )
            for citation_index, citation in enumerate(finding.citations):
                self._citations_checked += 1
                location = f"findings.yaml.findings[{finding_index}].citations[{citation_index}]"
                call = self._calls.get(citation.call)
                if call is None:
                    self._add_citation(location, "cited call does not exist")
                elif call.outcome != "ok":
                    self._add_citation(location, "cited call did not succeed")
                elif call.dataset != session.dataset:
                    self._add_citation(location, "cited call belongs to another dataset")
                elif citation.evidence_id not in self._anchors.get(citation.call, set()):
                    self._add_citation(
                        location, "evidence anchor is absent from the cited response"
                    )

    def _add_citation(self, location: str, message: str) -> None:
        self._citation_violations.append(SessionViolation(location=location, message=message))


def render_session_check(report: SessionCheckReport) -> str:
    lines = [
        "Record consistency: " + ("consistent" if report.record.consistent else "violations"),
        f"Calls checked: {report.record.calls_checked}.",
        "Citation resolution: " + ("resolved" if report.citations.resolved else "violations"),
        f"Citations checked: {report.citations.citations_checked}.",
        "Structured claims: " + ("verified" if report.claims.verified else "not all verified"),
        f"Claims checked: {len(report.claims.checks)}.",
    ]
    for violation in (*report.record.violations, *report.citations.violations):
        location = json.dumps(violation.location, ensure_ascii=True)
        lines.append(f"{location}: {violation.message}")
    for check in report.claims.checks:
        detail = f"; field {check.field}" if check.field else ""
        finding_id = json.dumps(check.finding_id, ensure_ascii=True)
        lines.append(f"{finding_id} (call {check.call}): {check.status}{detail}. {check.message}")
    lines.append(
        f"Not checked (free narrative): {report.not_checked.count}; IDs: "
        + (
            ", ".join(
                json.dumps(name, ensure_ascii=True) for name in report.not_checked.finding_ids
            )
            or "none"
        )
        + "."
    )
    lines.append(report.support_limitation)
    return "\n".join(lines)
