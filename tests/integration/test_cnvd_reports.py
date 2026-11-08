"""Reports preserve recorded CNVD source statements without loading a live source."""

import json
from collections.abc import Callable
from dataclasses import replace
from html import escape
from pathlib import Path

import pytest

from tests.support.report_sessions import (
    CNVD_REPORT_CVE_IDS,
    CNVD_REPORT_DESCRIPTION,
    CNVD_REPORT_TITLE,
    build_cnvd_report_session,
    read_document,
    read_recorded_files,
)
from tests.support.workspaces import build_test_workspace
from vulnwitness.adapters.session.check import SessionChecker
from vulnwitness.application.session_report import build_session_report
from vulnwitness.cli import main
from vulnwitness.domain.cve_lookup import CveLookupResponse
from vulnwitness.domain.search import SearchResponse
from vulnwitness.domain.session_report import SessionReport
from vulnwitness.domain.source_comparison import COMPARISON_STATEMENT
from vulnwitness.domain.workspace import StartInvestigationRequest
from vulnwitness.interfaces.report_html import render_html_report
from vulnwitness.interfaces.report_markdown import escape_markdown, render_markdown_report


@pytest.fixture
def cnvd_session(tmp_path: Path) -> Path:
    return build_cnvd_report_session(tmp_path / "workspace")


@pytest.mark.parametrize("report_format", ("html", "md"))
def test_cnvd_cards_show_each_source_comparison_and_fold_escaped_descriptions(
    cnvd_session: Path, report_format: str
) -> None:
    # Arrange
    contents = SessionChecker(cnvd_session).check_with_contents()
    render = render_html_report if report_format == "html" else render_markdown_report
    literal = escape if report_format == "html" else escape_markdown

    # Act
    report = build_session_report(contents)
    document = render(report)

    # Assert
    assert contents.check.record.consistent
    assert literal(CNVD_REPORT_TITLE) in document
    assert "<img " not in document
    assert literal(COMPARISON_STATEMENT) in document
    assert literal("Rule: cnvd_severity_vs_nvd_primary_cvss3") in document
    assert "≠ disagree" in document
    assert "CNVD severity: 高" in document
    assert "CNVD severity: 中" in document
    assert "CNVD severity: 低" in document
    assert literal("NVD state: awaiting_analysis") in document
    assert literal("NVD state: deferred") in document
    assert literal("NVD severity used for comparison: MEDIUM · primary CVSS 3.1") in document
    assert "No primary CVSS v3.1 or v3.0 metric was recorded by NVD." in document
    assert literal("NVD's primary CVSS v3 severity is missing or NONE.") in document
    cards = report.sections[2].sections
    card_titles = []
    for card in cards:
        card_titles.append(card.title)
    assert tuple(card_titles) == CNVD_REPORT_CVE_IDS
    entries = cards[1].sections[0].sections[1].sections
    entry_titles = []
    for entry in entries:
        entry_titles.append(entry.title)
    assert entry_titles == ["CNVD-9999-00001", "CNVD-9999-00002"]
    if report_format == "html":
        assert "<script>" not in document
        assert '<span class="pill neutral">≠ disagree</span>' in document
        folded = document.split(
            "<summary>Full recorded CNVD description · untrusted text</summary>"
        )[1].split("</details>")[0]
        assert escape(CNVD_REPORT_DESCRIPTION) in folded
        assert '<div class="two">\n<section><h5>NVD</h5>' in document
    else:
        folded = document.split(
            "<summary>Full recorded CNVD description · untrusted text</summary>"
        )[1].split("</details>")[0]
        assert "\n".join("    " + line for line in CNVD_REPORT_DESCRIPTION.splitlines()) in folded


@pytest.mark.parametrize("report_format", ("html", "md"))
def test_recorded_attribution_appears_once_and_counts_distinct_cves(
    cnvd_session: Path, capsys: pytest.CaptureFixture[str], report_format: str
) -> None:
    # Arrange
    attribution = "Recorded CNVD credit: 中文 <credit> & CIRCL licence terms."
    for sequence in range(1, len(CNVD_REPORT_CVE_IDS) + 1):
        lookup = read_document(cnvd_session, sequence)
        lookup["cnvd_attribution"] = attribution
        (cnvd_session / f"responses/{sequence:04d}.json").write_text(json.dumps(lookup))
    literal = escape if report_format == "html" else escape_markdown

    # Act
    exit_code = main(
        ["report", str(cnvd_session), "--format", report_format],
        environment={"VULNWITNESS_STORE_ROOT": "/unavailable-store"},
    )
    document = capsys.readouterr().out

    # Assert
    # Editing recorded bytes remains a checker violation even when the text is rendered.
    assert exit_code == 1
    assert "response bytes differ from the recorded input digest" in document
    assert document.count(literal(attribution)) == 1
    assert "CNVD severity disagrees with NVD for 2 CVEs" in document
    assert "CNVD lists 5 CVEs" in document
    assert "they are not a ranking" in document
    assert "CIRCL/Vulnerability-CNVD (Hugging Face" not in document


@pytest.mark.parametrize(
    "cve_id,state",
    (
        ("CVE-9999-0006", "not_in_nvd_snapshot"),
        ("CVE-9999-0007", "rejected_by_nvd"),
        ("CVE-9999-0008", "excluded_by_import"),
    ),
    ids=("absent", "rejected", "excluded"),
)
@pytest.mark.parametrize("report_format", ("html", "md"))
def test_pending_only_lookup_has_its_own_card_with_nvd_state(
    tmp_path: Path, cve_id: str, state: str, report_format: str
) -> None:
    # Arrange
    directory = build_cnvd_report_session(tmp_path / "workspace", (cve_id,))
    contents = SessionChecker(directory).check_with_contents()
    render = render_html_report if report_format == "html" else render_markdown_report
    literal = escape if report_format == "html" else escape_markdown

    # Act
    report = build_session_report(contents)
    document = render(report)

    # Assert
    assert report.sections[2].title == "CVE details · 1 CVEs"
    assert report.sections[2].sections[0].title == cve_id
    assert literal("NVD's snapshot has no servable record.") in document
    assert literal(f"NVD state: {state}") in document
    assert literal("not_comparable") in document
    assert "CNVD lists 1 CVEs" in document
    assert "CIRCL/Vulnerability-CNVD" in document


def test_comparison_is_read_from_the_recording_instead_of_recomputed(cnvd_session: Path) -> None:
    # Arrange
    lookup = read_document(cnvd_session, 1)
    lookup["candidates"][0]["record"]["cnvd"][0]["source_comparison"]["severity"] = "agree"
    (cnvd_session / "responses/0001.json").write_text(json.dumps(lookup))

    # Act
    report = build_session_report(SessionChecker(cnvd_session).check_with_contents())
    document = render_html_report(report)

    # Assert
    assert "CNVD severity disagrees with NVD for 1 CVEs" in document
    assert (
        report.sections[2].sections[0].sections[0].sections[1].sections[0].badges[0].text == "agree"
    )


@pytest.mark.parametrize("render", (render_html_report, render_markdown_report), ids=("html", "md"))
def test_cnvd_rendering_is_byte_identical_and_preserves_recorded_files(
    cnvd_session: Path, render: Callable[[SessionReport], str]
) -> None:
    # Arrange
    recorded_files = read_recorded_files(cnvd_session)

    # Act
    first = build_session_report(SessionChecker(cnvd_session).check_with_contents())
    second = build_session_report(SessionChecker(cnvd_session).check_with_contents())

    # Assert
    assert render(first).encode() == render(second).encode()
    assert read_recorded_files(cnvd_session) == recorded_files


@pytest.mark.parametrize("render", (render_html_report, render_markdown_report), ids=("html", "md"))
def test_lookup_without_cnvd_renders_exactly_as_the_plain_nvd_response(
    tmp_path: Path, render: Callable[[SessionReport], str]
) -> None:
    # Arrange
    _, workspace = build_test_workspace(tmp_path / "workspace")
    started = workspace.start(StartInvestigationRequest(goal="NVD only"))
    workspace.record(started.session_id, "lookup_cve", {"cve_id": "CVE-9999-0001"})
    contents = SessionChecker(tmp_path / "workspace" / started.session_id).check_with_contents()
    lookup = contents.responses[1]
    assert isinstance(lookup, CveLookupResponse)
    plain = SearchResponse.model_validate(
        lookup.model_dump(exclude={"pending_cnvd", "cnvd_attribution", "not_found_statement"})
    )

    # Act
    document = render(build_session_report(contents))
    plain_document = render(build_session_report(replace(contents, responses={1: plain})))

    # Assert
    assert document.encode() == plain_document.encode()
    assert "Recorded source facts" not in document
    assert "CNVD severity" not in document
