"""Reports preserve recorded authority grades, source gaps and declared languages."""

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
    set_recorded_cnvd_language,
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
from vulnwitness.interfaces.lookup_summary import render_lookup_summary
from vulnwitness.interfaces.report_html import render_html_report
from vulnwitness.interfaces.report_markdown import escape_markdown, render_markdown_report


@pytest.fixture
def cnvd_session(tmp_path: Path) -> Path:
    return build_cnvd_report_session(tmp_path / "workspace")


@pytest.mark.parametrize("report_format", ("html", "md"))
def test_cnvd_cards_mark_only_higher_and_keep_source_grades_and_fixed_statement(
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
    assert literal("Rule: cnvd_grade_vs_nvd_own_cvss3") in document
    for grade in ("高", "中", "低"):
        assert f"CNVD severity: {grade}" in document
    assert "CNVD three-grade scheme (高 / 中 / 低) · assessed by CNVD" in document
    assert literal("NVD state: awaiting_analysis") in document
    assert literal("NVD state: deferred") in document
    assert (
        literal(
            "NVD severity used for comparison: MEDIUM · CVSS 3.1 "
            "· assessed by nvd@nist.gov · primary · channel: NVD"
        )
        in document
    )
    assert literal("CNVD grade relative to nvd@nist.gov's CVSS 3.1 MEDIUM: same") in document
    assert literal("CNVD grade relative to nvd@nist.gov's CVSS 3.1 MEDIUM: lower") in document
    cards = report.sections[2].sections
    card_titles = []
    for card in cards:
        card_titles.append(card.title)
    assert tuple(card_titles) == CNVD_REPORT_CVE_IDS
    higher = cards[0].sections[0].sections[1].sections[0]
    entries = cards[1].sections[0].sections[1].sections
    assert higher.badges[0].tone == "neutral"
    assert higher.badges[0].text == (
        "◇ CNVD grades higher than nvd@nist.gov's CVSS 3.1 MEDIUM under cnvd_grade_vs_nvd_own_cvss3"
    )
    entry_titles = []
    for entry in entries:
        entry_titles.append(entry.title)
    assert entry_titles == ["CNVD-9999-00001", "CNVD-9999-00002"]
    assert all(not entry.badges for entry in entries)
    assert "disagree" not in document
    if report_format == "html":
        assert "<script>" not in document
        assert '<span class="pill neutral">◇ CNVD grades higher' in document
        assert '<span class="pill neutral">lower</span>' not in document
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
def test_recorded_key_facts_name_distinct_cve_denominators_and_dataset(
    cnvd_session: Path, capsys: pytest.CaptureFixture[str], report_format: str
) -> None:
    # Arrange
    attribution = "Recorded CNVD credit: 中文 <credit> & CIRCL licence terms."
    for sequence in range(1, len(CNVD_REPORT_CVE_IDS) + 1):
        lookup = read_document(cnvd_session, sequence)
        lookup["cnvd_attribution"] = attribution
        (cnvd_session / f"responses/{sequence:04d}.json").write_text(json.dumps(lookup))
    literal = escape if report_format == "html" else escape_markdown
    metadata = json.loads((cnvd_session / "session.json").read_text())
    identity = (
        "dataset synthetic_fixture (corpus " + metadata["dataset"]["corpus_content_sha256"] + ")"
    )

    # Act
    exit_code = main(
        ["report", str(cnvd_session), "--format", report_format],
        environment={"VULNWITNESS_STORE_ROOT": "/unavailable-store"},
    )
    document = capsys.readouterr().out
    report = build_session_report(SessionChecker(cnvd_session).check_with_contents())
    facts = report.sections[1].sections[0].bullets[1:7]

    # Assert
    assert exit_code == 1
    assert "response bytes differ from the recorded input digest" in document
    assert document.count(literal(attribution)) == 1
    assert facts[0] == f"CNVD counts below cover recorded lookups from {identity}."
    assert facts[1].startswith(
        "CNVD grades higher under cnvd_grade_vs_nvd_own_cvss3: 1 of 3 distinct CVEs"
    )
    assert facts[2].startswith("NVD record gaps: 3 of 8 distinct CNVD-listed CVEs")
    assert facts[3].startswith(
        "NVD score gaps: 1 of 5 distinct CNVD-listed CVEs with a servable NVD record"
    )
    assert facts[4].startswith("NVD status awaiting_analysis: 1 of 5 distinct CNVD-listed CVEs")
    assert facts[5].startswith("NVD status deferred: 1 of 5 distinct CNVD-listed CVEs")
    for fact in facts:
        assert literal(fact) in document
    assert "they are not a ranking" in document
    assert literal("awaiting_analysis or deferred does not mean no score") in document
    assert "CIRCL/Vulnerability-CNVD (Hugging Face" not in document


@pytest.mark.parametrize(
    "cve_id,reason,explanation",
    (
        ("CVE-9999-0006", "no_nvd_record", "NVD's snapshot has no servable record."),
        (
            "CVE-9999-0002",
            "no_nvd_cvss3_metric",
            "NVD's own CVSS v3.1 or v3.0 metric is not recorded.",
        ),
        (
            "CVE-9999-0005",
            "no_usable_base_severity",
            "NVD's own CVSS v3 severity is missing or NONE.",
        ),
    ),
    ids=("no-record", "no-metric", "unusable-severity"),
)
@pytest.mark.parametrize("report_format", ("html", "md"))
def test_not_compared_reasons_remain_plain_and_distinct(
    tmp_path: Path, cve_id: str, reason: str, explanation: str, report_format: str
) -> None:
    # Arrange
    directory = build_cnvd_report_session(tmp_path / "workspace", (cve_id,))
    render = render_html_report if report_format == "html" else render_markdown_report
    literal = escape if report_format == "html" else escape_markdown

    # Act
    report = build_session_report(SessionChecker(directory).check_with_contents())
    document = render(report)

    # Assert
    assert literal(explanation) in document
    assert literal(f"not_compared ({reason})") in document
    assert "◇" not in document
    if reason == "no_usable_base_severity":
        assert "NVD score gaps: 0 of 1" in document


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
def test_pending_only_lookup_counts_one_record_gap_and_no_score_or_status_gap(
    tmp_path: Path, cve_id: str, state: str, report_format: str
) -> None:
    # Arrange
    directory = build_cnvd_report_session(tmp_path / "workspace", (cve_id,))
    render = render_html_report if report_format == "html" else render_markdown_report
    literal = escape if report_format == "html" else escape_markdown

    # Act
    report = build_session_report(SessionChecker(directory).check_with_contents())
    document = render(report)

    # Assert
    assert report.sections[2].title == "CVE details · 1 CVEs"
    assert report.sections[2].sections[0].title == cve_id
    assert literal(f"NVD state: {state}") in document
    assert "NVD record gaps: 1 of 1" in document
    assert literal("cnvd_grade_vs_nvd_own_cvss3: 0 of 0") in document
    assert "NVD score gaps: 0 of 0" in document
    assert literal("NVD status awaiting_analysis: 0 of 0") in document
    assert "NVD status deferred: 0 of 0" in document
    assert "CIRCL/Vulnerability-CNVD" in document


@pytest.mark.parametrize("render", (render_html_report, render_markdown_report), ids=("html", "md"))
def test_awaiting_analysis_with_cna_score_keeps_assessor_and_nvd_owned_comparison(
    tmp_path: Path, render: Callable[[SessionReport], str]
) -> None:
    # Arrange
    directory = build_cnvd_report_session(tmp_path / "workspace", ("CVE-9999-0003",))

    # Act
    report = build_session_report(SessionChecker(directory).check_with_contents())
    document = render(report)

    # Assert
    assert "cna@example.org" in document
    assert "Critical 9.8 · CVSS 3.1 · cna@example.org · primary" in document
    assert "CVSS 3.0 · assessed by nvd@nist.gov · secondary" in document
    assert "NVD score gaps: 0 of 1" in document
    assert "NVD status awaiting" in document
    assert "◇" not in document


def test_comparison_is_read_from_recording_instead_of_recomputed(cnvd_session: Path) -> None:
    # Arrange
    lookup = read_document(cnvd_session, 1)
    lookup["candidates"][0]["record"]["cnvd"][0]["source_comparison"]["grade_relative"] = "same"
    (cnvd_session / "responses/0001.json").write_text(json.dumps(lookup))

    # Act
    report = build_session_report(SessionChecker(cnvd_session).check_with_contents())
    document = render_html_report(report)

    # Assert
    assert "cnvd_grade_vs_nvd_own_cvss3: 0 of 3" in document
    assert not report.sections[2].sections[0].sections[0].sections[1].sections[0].badges
    assert "◇" not in document


@pytest.mark.parametrize("cve_id", ("CVE-9999-0001", "CVE-9999-0006"), ids=("record", "pending"))
@pytest.mark.parametrize("language", ("zh", "zh-Hans", None, 'zh" onclick="bad'))
def test_html_tags_only_cnvd_title_and_description_with_recorded_language(
    tmp_path: Path, cve_id: str, language: str | None
) -> None:
    # Arrange
    directory = build_cnvd_report_session(tmp_path / "workspace", (cve_id,))
    set_recorded_cnvd_language(directory, language)

    # Act
    report = build_session_report(SessionChecker(directory).check_with_contents())
    document = render_html_report(report)

    # Assert
    attribute = "" if language is None else f' lang="{escape(language, quote=True)}"'
    assert f"<p{attribute}>{escape(CNVD_REPORT_TITLE)}</p>" in document
    assert f"<pre{attribute}><code>{escape(CNVD_REPORT_DESCRIPTION)}</code></pre>" in document
    assert document.count(" lang=") == (1 if language is None else 5)
    assert '<html lang="en">' in document
    assert ' onclick="bad' not in document


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
def test_lookup_without_cnvd_renders_exactly_as_plain_nvd_response(
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
        lookup.model_dump(
            exclude={"pending_cnvd", "cnvd_attribution", "cnvd_language", "not_found_statement"}
        )
    )

    # Act
    document = render(build_session_report(contents))
    plain_document = render(build_session_report(replace(contents, responses={1: plain})))

    # Assert
    assert document.encode() == plain_document.encode()
    assert "Recorded source facts" not in document
    assert "CNVD severity" not in document


def test_cli_higher_text_names_raw_grades_scorer_rule_and_provenance(tmp_path: Path) -> None:
    # Arrange
    directory = build_cnvd_report_session(tmp_path / "workspace", ("CVE-9999-0004",))
    lookup = CveLookupResponse.model_validate(read_document(directory, 1))

    # Act
    text = render_lookup_summary(lookup)

    # Assert
    assert (
        "◇ CNVD grades higher than nvd@nist.gov's CVSS 3.1 MEDIUM under cnvd_grade_vs_nvd_own_cvss3"
        in text
    )
    assert "CNVD CNVD-9999-00005: 高 · CNVD three-grade scheme" in text
    assert "assessed by nvd@nist.gov · primary" in text
    assert "circl-cnvd · CNVD-9999-00005 · urn:synthetic:cnvd:" in text
    assert "VulnWitness's mapping between two grading schemes" in text
    assert "disagree" not in text


def test_markdown_bytes_ignore_language_metadata_and_keep_original_source_text(
    cnvd_session: Path,
) -> None:
    # Arrange
    contents = SessionChecker(cnvd_session).check_with_contents()
    responses = dict(contents.responses)
    for sequence, answer in contents.responses.items():
        assert isinstance(answer, CveLookupResponse)
        responses[sequence] = answer.model_copy(update={"cnvd_language": None})

    # Act
    declared = render_markdown_report(build_session_report(contents))
    undeclared = render_markdown_report(
        build_session_report(replace(contents, responses=responses))
    )

    # Assert
    assert declared.encode() == undeclared.encode()
    assert "\n".join("    " + line for line in CNVD_REPORT_DESCRIPTION.splitlines()) in declared
    assert escape_markdown(CNVD_REPORT_TITLE) in declared
    assert "lang=" not in declared
