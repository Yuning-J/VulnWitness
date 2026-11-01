"""Report states and provenance over recorded packaged synthetic sessions."""

import json
from html import escape
from pathlib import Path

import pytest

from tests.support.clocks import SteppingClock
from tests.support.report_sessions import read_document, save_findings
from tests.support.triage import build_triage_workflow
from tests.support.triage_artifacts import InvalidFindingsArtifacts
from vulnwitness.adapters.session.check import SessionChecker
from vulnwitness.adapters.session.report_output import read_triage_scope
from vulnwitness.application.session_report import build_session_report
from vulnwitness.cli import main
from vulnwitness.domain.product_query import ProductQueryRequest
from vulnwitness.domain.triage import TriageLimits
from vulnwitness.interfaces.report_html import render_html_report
from vulnwitness.interfaces.report_markdown import render_markdown_report


@pytest.mark.parametrize("report_format", ("html", "md"))
@pytest.mark.parametrize(
    ("product", "limits", "clock", "selected", "exit_code", "wording"),
    (
        ("demo_gateway", TriageLimits(), None, (), 0, "Inventory complete"),
        ("demo_gateway", TriageLimits(max_pages=1), None, (), 3, "page cap"),
        (
            "demo_gateway",
            TriageLimits(time_limit=1),
            SteppingClock(seconds_per_read=1),
            (),
            3,
            "time limit",
        ),
        ("no matching synthetic product", TriageLimits(), None, (), 1, "Inventory complete"),
        (
            "demo_gateway",
            TriageLimits(lookups=0),
            None,
            (),
            0,
            "Selection is an order, not a risk ranking.",
        ),
        (
            "demo_gateway",
            TriageLimits(),
            None,
            ("CVE-9999-0002",),
            0,
            "selected by the user",
        ),
    ),
)
def test_report_shows_recorded_scope_and_check_marks(
    tmp_path: Path,
    product: str,
    limits: TriageLimits,
    clock: SteppingClock | None,
    selected: tuple[str, ...],
    exit_code: int,
    wording: str,
    report_format: str,
) -> None:
    # Arrange
    directory = tmp_path / "review"
    workflow = build_triage_workflow(directory, limits=limits, clock=clock)

    # Act
    summary, _, triage_exit = workflow.run(
        ProductQueryRequest(product=product, version="2.0", limit=1), selected
    )
    report = build_session_report(
        SessionChecker(directory).check_with_contents(), read_triage_scope(directory)
    )
    document = (
        render_html_report(report) if report_format == "html" else render_markdown_report(report)
    )

    # Assert
    assert triage_exit == exit_code
    assert wording in document
    assert "✓" in document
    assert "Free text is never checked." in document
    assert "Total matches" in document and "Read" in document and "CVE details" in document
    assert "recorded 2026-10-15 08:30 UTC" in document
    assert "Created at: 2026-10-15T08:30:00+00:00" in document
    if summary.stop_reason == "max_pages":
        unread = summary.inventory.total_available - summary.inventory.items_seen
        assert f"{unread} of {summary.inventory.total_available} not read" in document
        assert "Inventory incomplete" in document
    if summary.deep_dive.lookups_completed == 0:
        assert '<article class="card"' not in document
        assert "CVE details ·" not in document
    if summary.inventory.items_seen == 0:
        assert "Read inventory ·" not in document
    if report_format == "html":
        assert 'class="pill ok"' in document
        assert 'class="ok-mark">✓' in document
        assert 'class="tag ok">hit' not in document
    assert "Check JSON preview" not in document
    assert "Full check JSON" in document
    full_json = report.check.model_dump_json(indent=2)
    expected_json = escape(full_json)
    if report_format == "md":
        expected_json = "\n".join("    " + line for line in full_json.splitlines())
    assert expected_json in document


@pytest.mark.parametrize("scorer", ("nvd@nist.gov", "another-scorer"))
def test_description_is_escaped_and_retained_in_full_inside_details(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], scorer: str
) -> None:
    # Arrange
    directory = tmp_path / "review"
    workflow = build_triage_workflow(directory)
    summary, _, _ = workflow.run(ProductQueryRequest(product="demo_gateway"))
    sequence = summary.deep_dive.lookup_calls[0]
    lookup = read_document(directory, sequence)
    hostile = '<script>alert("description")</script> & ' + "synthetic description " * 60
    lookup["candidates"][0]["record"]["descriptions"][0]["value"] = hostile
    lookup["candidates"][0]["record"]["cvss"][0]["scorer"] = scorer
    (directory / f"responses/{sequence:04d}.json").write_text(json.dumps(lookup))

    # Act
    exit_code = main(["report", str(directory), "--format", "html"], environment={})
    document = capsys.readouterr().out

    # Assert
    assert exit_code == 0
    assert "NVD description · untrusted text" in document
    full_description = document.split("<summary>Full recorded NVD description")[1].split(
        "</details>"
    )[0]
    assert escape(hostile) in full_description
    assert "<script>" not in document
    scorer_label = "NVD" if scorer == "nvd@nist.gov" else scorer
    assert f"CVSS 3.1 · {scorer_label} · primary" in document


def test_lookup_details_retain_inheritance_scorer_and_original_paths(tmp_path: Path) -> None:
    # Arrange
    directory = tmp_path / "review"
    workflow = build_triage_workflow(directory)
    workflow.run(ProductQueryRequest(vendor="democorp", version="2.0"))

    # Act
    report = build_session_report(
        SessionChecker(directory).check_with_contents(), read_triage_scope(directory)
    )
    document = render_html_report(report)

    # Assert
    assert "Each original path" in document
    assert "capec_child_of" in document and "CAPEC-parent inheritance" in document
    assert "Terminal reason:" in document
    assert "CAPEC catalogue · version" in document
    assert "paths reaching ATT&amp;CK" in document and "distinct techniques" in document
    assert "paths omitted by the cap" in document
    assert "CVSS 3.1 · synthetic-scorer · primary" in document
    assert "synthetic-vendor-psirt · secondary" in document
    assert 'href="#CVE-9999-0002"' in document
    assert "Why selected: #" in document
    assert '<span class="tag neutral">hit</span>' in document
    assert '2.0 vs &lt; 2.0.1\n<small class="muted">Version 2.0 matches' in document
    assert '<span class="tag warn">unknown</span>' in document
    assert '<small class="muted">configuration and environment not evaluated</small>' in document
    assert '<h5 class="chip strong">CWE-20</h5>' in document
    assert "→ 18 CAPEC · 20 paths" in document
    assert '<span class="tag ok">20 reach ATT&amp;CK</span>' in document
    assert '<span class="chip">CAPEC-13 → T1574.006, T1574.007</span>' in document
    assert '<details class="inline"><summary>+14 more</summary>' in document
    assert '<details class="inline"><summary>Other severity metrics</summary>' in document
    assert '<details class="inline"><summary>Each original path</summary>' in document
    assert '<details class="inline"><summary>Full recorded NVD description' in document
    assert '<details class="appendix"><summary>Dataset identity</summary>' in document
    assert document.count("This association is derived from official catalogues.") == 1


def test_check_failure_takes_precedence_over_page_cap(tmp_path: Path) -> None:
    # Arrange
    directory = tmp_path / "review"
    workflow = build_triage_workflow(
        directory,
        limits=TriageLimits(max_pages=1),
        artifacts=InvalidFindingsArtifacts(directory),
    )

    # Act
    summary, check, exit_code = workflow.run(ProductQueryRequest(vendor="democorp", limit=1))

    # Assert
    assert exit_code == 2
    assert summary.stop_reason == "check_failed"
    assert not check.record.consistent


def test_requested_lookup_count_completes_without_a_final_deadline_check(tmp_path: Path) -> None:
    # Arrange
    directory = tmp_path / "review"
    workflow = build_triage_workflow(
        directory,
        limits=TriageLimits(time_limit=3, lookups=1),
        clock=SteppingClock(seconds_per_read=1),
    )

    # Act
    summary, _, exit_code = workflow.run(ProductQueryRequest(product="demo_gateway"))

    # Assert
    assert exit_code == 0
    assert summary.stop_reason == "complete"
    assert summary.deep_dive.lookups_completed == 1
    assert summary.remaining_steps == ()


def test_product_page_defaults_and_help_describe_exit_three(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    directory = tmp_path / "review"

    # Act
    exit_code = main(
        ["triage", "--product", "demo_gateway", "--session", str(directory)], environment={}
    )
    request = json.loads((directory / "calls/0002.json").read_text())["request"]
    with pytest.raises(SystemExit) as help_exit:
        main(["triage", "--help"], environment={})
    help_text = capsys.readouterr().out

    # Assert
    assert exit_code == help_exit.value.code == 0
    assert request["limit"] == ProductQueryRequest(product="demo_gateway").limit == 20
    assert "Exit codes:" in help_text and "non-zero for shells" in help_text


def test_original_path_details_include_cwe_parent_hops(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    directory = tmp_path / "review"
    main(["lookup", "CVE-9999-0006", "--session", str(directory)], environment={})
    save_findings(
        directory,
        {
            "findings": [],
            "selections": {"cve_ids": [], "product_queries": []},
            "open_questions": [],
        },
    )
    capsys.readouterr()

    # Act
    exit_code = main(["report", str(directory), "--format", "html"], environment={})
    document = capsys.readouterr().out

    # Assert
    assert exit_code == 0
    assert "cwe_child_of" in document
    assert "CWE-parent inheritance: CWE-119" in document
    assert "CWE catalogue · version 5.0" in document
    assert "No ATT&amp;CK mapping describes only the loaded catalogue snapshot" in document
    assert '<span class="tag warn">No ATT&amp;CK mapping in this snapshot</span>' in document
    assert '<span class="chip">CAPEC-100</span>' in document
    assert "→ no ATT&amp;CK mapping" not in document
