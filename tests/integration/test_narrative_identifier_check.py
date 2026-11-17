"""Session check lists IDs that statements name but no recorded call returned; the
verdict is unchanged."""

from pathlib import Path

import pytest
import yaml

from tests.support.priority import build_priority_session
from tests.support.workspaces import build_test_workspace
from vulnwitness.adapters.session.check import SessionChecker, render_session_check
from vulnwitness.application.session_report import build_session_report
from vulnwitness.cli import main
from vulnwitness.domain.workspace import StartInvestigationRequest
from vulnwitness.interfaces.report_markdown import render_markdown_report


def write_note(directory: Path, statement: str) -> None:
    findings = {
        "findings": [
            {
                "id": "note-1",
                "statement": statement,
                "kind": "model_judgement",
                "author": "agent",
                "status": "unconfirmed",
                "citations": [],
            }
        ],
        "selections": {"cve_ids": [], "product_queries": []},
        "open_questions": [],
    }
    (directory / "findings.yaml").write_text(yaml.safe_dump(findings), encoding="utf-8")


def test_unrecorded_identifier_is_reported_without_failing_the_check(tmp_path: Path) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    write_note(directory, "CVE-9999-0001 matters; CVE-2031-77777 is similar.")

    contents = SessionChecker(directory).check_with_contents()
    report = contents.check

    identifiers = report.narrative_identifiers
    assert (identifiers.identifiers_checked, identifiers.recorded) == (2, 1)
    unrecorded_ids = []
    for entry in identifiers.unrecorded:
        unrecorded_ids.append(entry.identifier)
    assert unrecorded_ids == ["CVE-2031-77777"]
    assert report.record.consistent and report.citations.resolved and report.claims.verified
    text = render_session_check(report)
    assert '"note-1": CVE-2031-77777 was not returned by any recorded call.' in text
    rendered = render_markdown_report(build_session_report(contents))
    assert "Finding note-1 names CVE-2031-77777, which no recorded call returned." in rendered


def test_statement_without_identifiers_adds_no_report_row(tmp_path: Path) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    write_note(directory, "The gateway looks exposed.")

    contents = SessionChecker(directory).check_with_contents()

    assert contents.check.narrative_identifiers.identifiers_checked == 0
    assert "Identifiers in statements" not in render_markdown_report(build_session_report(contents))


@pytest.mark.parametrize(
    "command,arguments",
    [
        ("lookup_cve", {"cve_id": "CVE-2031-77777"}),
        ("search_vulnerabilities", {"query": "CVE-2031-77777 CWE-999999 CNVD-2031-77777"}),
        ("search_fight", {"query": "CVE-2031-77777 CWE-999999 CNVD-2031-77777"}),
        ("resolve_telecom_concept", {"query": "CVE-2031-77777 CWE-999999 CNVD-2031-77777"}),
        ("query_product_vulnerabilities", {"product": "CVE-2031-77777 CWE-999999 CNVD-2031-77777"}),
        ("query_product_vulnerabilities", {"vendor": "democorp", "version": "CVE-2031-77777"}),
        (
            "investigate_telecom_topic",
            {
                "query": "CVE-2031-77777 CWE-999999 CNVD-2031-77777",
                "scope": "mixed",
            },
        ),
        ("check_affectedness", {"cve_id": "CVE-2031-77777", "purl": "pkg:generic/example@1.0"}),
    ],
)
def test_request_echoes_leave_invented_identifiers_unrecorded(
    tmp_path: Path, command: str, arguments: dict[str, object]
) -> None:
    root = tmp_path / "sessions"
    _, workspace = build_test_workspace(root)
    started = workspace.start(StartInvestigationRequest(goal="Check returned identifiers"))
    workspace.record(started.session_id, command, arguments)
    directory = root / started.session_id
    write_note(directory, "CVE-2031-77777, CWE-999999 and CNVD-2031-77777 need review.")

    contents = SessionChecker(directory).check_with_contents()
    report = contents.check

    assert report.record.consistent, report.record.violations
    assert report.record.calls_checked == 1
    assert contents.calls[0].outcome == "ok"
    assert report.narrative_identifiers.recorded == 0
    assert report.narrative_identifiers.unrecorded_count == 3


def test_cli_affectedness_request_echo_leaves_identifier_unrecorded(tmp_path: Path) -> None:
    directory = tmp_path / "session"
    assert (
        main(
            [
                "affectedness",
                "CVE-2031-77777",
                "--purl",
                "pkg:generic/example@1.0",
                "--session",
                str(directory),
            ],
            {},
        )
        == 1
    )
    write_note(directory, "CVE-2031-77777 needs review.")

    report = SessionChecker(directory).check()

    assert report.record.consistent
    assert report.narrative_identifiers.recorded == 0
    assert report.narrative_identifiers.unrecorded_count == 1
