"""Reports present real recorded CLI sessions without retrieval or narrative verification."""

import json
import stat
from html import escape
from pathlib import Path

import pytest

from tests.support.report_sessions import (
    build_report_session,
    read_document,
    read_findings,
    read_recorded_files,
    save_findings,
)
from vulnwitness.cli import main
from vulnwitness.domain.weakness_associations import DERIVED_ASSOCIATION_NOTE


@pytest.fixture
def report_session(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Path:
    directory = tmp_path / "review"
    build_report_session(directory)
    capsys.readouterr()
    return directory


@pytest.mark.parametrize("report_format", ("md", "html"))
def test_both_formats_show_ordered_sections_and_recorded_limits(
    report_session: Path, capsys: pytest.CaptureFixture[str], report_format: str
) -> None:
    # Arrange
    sections = (
        "Overview",
        "Key facts and limits",
        "CVE details",
        "Read inventory",
        "Execution and checks",
        "Technical appendix",
    )

    # Act
    exit_code = main(["report", str(report_session), "--format", report_format], environment={})
    document = capsys.readouterr().out

    # Assert
    assert exit_code == 0
    previous_position = -1
    for section in sections:
        position = document.index(section)
        assert position > previous_position
        previous_position = position
    assert "Synthetic demonstration data" in document
    assert "Review demonstration product records" in document
    assert "Which deployed version needs review" in document
    assert "Affectedness" in document and "unknown" in document
    assert "NVD product field" in document
    assert "call 1 · evidence ev" in document
    assert "Free text is never checked" in document
    assert "Record consistency" in document
    assert document.count("This association is derived from official catalogues.") == 1
    assert (
        document.count(
            "Catalogue associations, not attack paths; “no ATT&amp;CK mapping” "
            "describes this snapshot only."
        )
        == 1
    )
    if report_format == "html":
        assert "<h3>Check layers</h3>" in document
        assert "<summary>Full check JSON</summary>" in document
        assert "&quot;count&quot;: 2" in document
        assert escape(DERIVED_ASSOCIATION_NOTE) in document
        assert "prefers-color-scheme: dark" in document and "@media print" in document
    else:
        assert '    "consistent": true,' in document
        assert '    "count": 2,' in document
        assert "## Execution and checks\n" in document


@pytest.mark.parametrize("report_format", ("md", "html"))
def test_contradicted_claim_is_visibly_flagged_and_exits_one(
    report_session: Path, capsys: pytest.CaptureFixture[str], report_format: str
) -> None:
    # Arrange
    findings = read_findings(report_session)
    findings["findings"][0]["claim"]["vendor"] = "wrong_vendor"
    save_findings(report_session, findings)

    # Act
    exit_code = main(["report", str(report_session), "--format", report_format], environment={})
    document = capsys.readouterr().out

    # Assert
    assert exit_code == 1
    assert "Structured claims failed" in document
    assert "✗" in document and "1 violations" in document
    assert "contradicted" in document
    if report_format == "html":
        assert 'class="pill bad"' in document
    assert "Recorded field differs from the claim." in document
    assert "Execution and checks" in document


@pytest.mark.parametrize("report_format", ("md", "html"))
def test_unverifiable_claim_is_flagged_and_failed_calls_are_listed(
    report_session: Path, capsys: pytest.CaptureFixture[str], report_format: str
) -> None:
    # Arrange
    main(
        [
            "product",
            "--vendor",
            "democorp",
            "--cursor",
            "invalid",
            "--session",
            str(report_session),
        ],
        environment={},
    )
    capsys.readouterr()
    findings = read_findings(report_session)
    findings["findings"][0]["claim"]["call"] = 5
    save_findings(report_session, findings)

    # Act
    exit_code = main(["report", str(report_session), "--format", report_format], environment={})
    document = capsys.readouterr().out

    # Assert
    assert exit_code == 1
    assert "WARNING" in document and "unverifiable" in document
    assert "Failed call 5" in document
    assert "invalid_cursor" in document or r"invalid\_cursor" in document


def test_html_escapes_hostile_finding_statement_and_source_uri(
    report_session: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    hostile = '<script>alert("report")</script><img src=x onerror=alert(1)> & unsafe'
    findings = read_findings(report_session)
    findings["findings"][4]["statement"] = hostile
    save_findings(report_session, findings)
    page = read_document(report_session, 1)
    page["evidence"][0]["source_uri"] = 'javascript:alert(1)" onmouseover="bad<value>'
    page["items"][0]["record"]["descriptions"][0]["value"] = hostile
    (report_session / "responses/0001.json").write_text(json.dumps(page))

    # Act
    exit_code = main(["report", str(report_session), "--format", "html"], environment={})
    document = capsys.readouterr().out

    # Assert
    assert exit_code == 0
    assert escape(hostile) in document and hostile not in document
    assert "<script>" not in document and "<img " not in document
    assert 'href="javascript:' not in document
    assert "onmouseover=&quot;bad&lt;value&gt;" in document


@pytest.mark.parametrize("report_format", ("md", "html"))
def test_repeated_rendering_is_byte_identical_and_preserves_recorded_files(
    report_session: Path, capsys: pytest.CaptureFixture[str], report_format: str
) -> None:
    # Arrange
    recorded_files = read_recorded_files(report_session)
    arguments = ["report", str(report_session), "--format", report_format]

    # Act
    first_exit = main(arguments, environment={})
    first = capsys.readouterr().out.encode()
    second_exit = main(arguments, environment={})
    second = capsys.readouterr().out.encode()

    # Assert
    assert first_exit == second_exit == 0
    assert first == second
    assert read_recorded_files(report_session) == recorded_files


def test_existing_output_is_preserved_without_force_and_replaced_privately_with_force(
    report_session: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    target = tmp_path / "share.html"
    target.write_text("Keep this file")
    arguments = ["report", str(report_session), "--format", "html", "--output", str(target)]

    # Act
    with pytest.raises(SystemExit) as refusal:
        main(arguments, environment={})
    preserved = target.read_text()
    exit_code = main([*arguments, "--force"], environment={})
    streams = capsys.readouterr()

    # Assert
    assert refusal.value.code == 2
    assert preserved == "Keep this file"
    assert "use --force" in streams.err
    assert exit_code == 0 and streams.out == ""
    assert target.read_text().startswith("<!doctype html>")
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


@pytest.mark.parametrize("report_format", ("md", "html"))
def test_explicit_report_output_inside_session_is_allowed_and_private(
    report_session: Path, capsys: pytest.CaptureFixture[str], report_format: str
) -> None:
    # Arrange
    target = report_session / f"report.{report_format}"

    # Act
    exit_code = main(
        ["report", str(report_session), "--format", report_format, "--output", str(target)],
        environment={},
    )

    # Assert
    assert exit_code == 0 and capsys.readouterr().out == ""
    assert "Synthetic demonstration data" in target.read_text()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


@pytest.mark.parametrize("relative_path", ("session.json", "findings.yaml", "calls/report.md"))
def test_output_that_could_modify_session_records_is_refused(
    report_session: Path, capsys: pytest.CaptureFixture[str], relative_path: str
) -> None:
    # Arrange
    target = report_session / relative_path

    # Act
    with pytest.raises(SystemExit) as refusal:
        main(["report", str(report_session), "--output", str(target), "--force"], environment={})

    # Assert
    assert refusal.value.code == 2
    assert "DIR/report.*" in capsys.readouterr().err


def test_broken_citation_renders_the_checker_failure_and_exits_one(
    report_session: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    findings = read_findings(report_session)
    findings["findings"][0]["citations"][0]["evidence_id"] = "ev:" + "0" * 24
    save_findings(report_session, findings)

    # Act
    exit_code = main(["report", str(report_session)], environment={})
    document = capsys.readouterr().out

    # Assert
    assert exit_code == 1
    assert "evidence anchor is absent from the cited response" in document
    assert "source URI unavailable" in document
    assert "Execution and checks" in document


def test_invalid_findings_render_a_record_violation_without_presenting_invalid_prose(
    report_session: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    (report_session / "findings.yaml").write_text("findings: invalid")

    # Act
    exit_code = main(["report", str(report_session)], environment={})
    document = capsys.readouterr().out

    # Assert
    assert exit_code == 1
    assert "findings are unreadable or invalid" in document
    assert "Execution and checks" in document


def test_unreadable_session_is_a_usage_error_without_a_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    directory = tmp_path / "missing"

    # Act
    with pytest.raises(SystemExit) as refusal:
        main(["report", str(directory)], environment={})

    # Assert
    assert refusal.value.code == 2
    streams = capsys.readouterr()
    assert streams.out == "" and "metadata is unreadable or invalid" in streams.err


def test_report_does_not_load_configured_services_or_store(
    report_session: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    environment = {
        "VULNWITNESS_STORE_ROOT": str(tmp_path / "unavailable-store"),
        "VULNWITNESS_PLANNER_ENABLED": "invalid",
    }

    # Act
    exit_code = main(["report", str(report_session)], environment=environment)

    # Assert
    assert exit_code == 0
    assert "Synthetic demonstration data" in capsys.readouterr().out


def test_invalid_triage_shape_is_labelled_unavailable_and_cannot_replace_findings(
    report_session: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    (report_session / "triage.json").write_text('{"inventory": {"items_seen": 3000}}')

    # Act
    exit_code = main(["report", str(report_session)], environment={})
    document = capsys.readouterr().out

    # Assert
    assert exit_code == 0
    assert "triage.json is unreadable or invalid" in document
    assert "Recorded workflow scope (not checked)" in document
    assert "Record consistency" in document


def test_manual_session_inventory_contains_all_recorded_product_pages(
    report_session: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    page = read_document(report_session, 1)

    # Act
    exit_code = main(["report", str(report_session), "--format", "html"], environment={})
    document = capsys.readouterr().out

    # Assert
    assert exit_code == 0
    assert '<div class="stat">' not in document
    inventory = document.split("Read inventory")[1].split("Execution and checks")[0]
    for vulnerability in page["items"]:
        assert vulnerability["record"]["cve_id"] in inventory


def test_unassessed_investigation_needs_remain_visible(
    report_session: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    main(
        [
            "investigate",
            "demo_gateway",
            "--scope",
            "implementation_only",
            "--session",
            str(report_session),
        ],
        environment={},
    )
    capsys.readouterr()

    # Act
    exit_code = main(["report", str(report_session), "--format", "html"], environment={})
    document = capsys.readouterr().out

    # Assert
    assert exit_code == 0
    assert "Need implementation_cves: (no subject) · matches_unassessed" in document


def test_malformed_optional_triage_metadata_does_not_prevent_session_reporting(
    report_session: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    (report_session / "triage.json").write_text('{"inventory": null, "inventory": 42}')

    # Act
    exit_code = main(["report", str(report_session)], environment={})
    document = capsys.readouterr().out

    # Assert
    assert exit_code == 0
    assert "triage.json is unreadable or invalid" in document


def test_symlink_destination_cannot_replace_session_metadata(
    report_session: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    target = tmp_path / "share.md"
    target.symlink_to(report_session / "session.json")
    metadata = (report_session / "session.json").read_bytes()

    # Act
    with pytest.raises(SystemExit) as refusal:
        main(["report", str(report_session), "--output", str(target), "--force"], environment={})

    # Assert
    assert refusal.value.code == 2
    assert (report_session / "session.json").read_bytes() == metadata
    assert capsys.readouterr().out == ""
