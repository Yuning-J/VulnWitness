"""Session check lists IDs that statements name but no recorded call returned; the
verdict is unchanged."""

from pathlib import Path

import yaml

from tests.support.priority import build_priority_session
from vulnwitness.adapters.session.check import SessionChecker, render_session_check
from vulnwitness.application.session_report import build_session_report
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
    assert [entry.identifier for entry in identifiers.unrecorded] == ["CVE-2031-77777"]
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
