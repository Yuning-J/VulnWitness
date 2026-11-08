"""Priority presentation consumes checked synthetic artifacts in HTML and Markdown."""

import json
from html import escape
from pathlib import Path

import pytest

from tests.support.priority import (
    build_priority_report_session,
    build_priority_session,
    priority_arguments,
    write_priority_register,
)
from vulnwitness.adapters.session.check import SessionChecker
from vulnwitness.application.session_report import build_session_report
from vulnwitness.cli import main
from vulnwitness.domain.priority_decision import PriorityArtifact
from vulnwitness.domain.session_report import ReportSection
from vulnwitness.interfaces.report_html import render_html_report, render_html_section
from vulnwitness.interfaces.report_markdown import (
    escape_markdown,
    render_markdown_report,
    render_markdown_section,
)


@pytest.fixture(params=["html", "md"])
def priority_view(
    tmp_path: Path, request: pytest.FixtureRequest
) -> tuple[PriorityArtifact, ReportSection, str, str]:
    directory = build_priority_report_session(tmp_path / "sessions")
    contents = SessionChecker(directory).check_with_contents()
    artifact = contents.priority
    assert artifact is not None and contents.check.record.consistent
    report = build_session_report(contents)
    section = next(section for section in report.sections if section.title == "Priority decisions")
    format_name = str(request.param)
    rendered = (
        render_html_report(report) if format_name == "html" else render_markdown_report(report)
    )
    return artifact, section, rendered, format_name


def test_priority_header_shows_identities_dates_and_policy_limits(
    priority_view: tuple[PriorityArtifact, ReportSection, str, str],
) -> None:
    artifact, _, rendered, _ = priority_view

    assert "A recommendation is VulnWitness policy output, not a compliance conclusion." in rendered
    assert artifact.policy.content_sha256 in rendered and artifact.register_sha256 in rendered
    literal = rendered.replace("\\_", "_")
    assert "Policy: cn-auto-demo · format_version: 1" in literal
    assert "Reference date: 2026-10-12" in rendered
    assert "Used after-reference-date information: true" in rendered
    assert "not_listed_in_snapshot means not listed in that snapshot, not " in literal
    assert "not exploited" in literal


def test_priority_text_is_escaped_in_both_formats(
    priority_view: tuple[PriorityArtifact, ReportSection, str, str],
) -> None:
    _, section, _, format_name = priority_view

    priority_text = (
        render_html_section(section, 2)
        if format_name == "html"
        else render_markdown_section(section, 2)
    )

    assert "<script>" not in priority_text and "&lt;script&gt;" in priority_text
    assert "<img src=x>" not in priority_text and "&lt;img src=x&gt;" in priority_text


def test_priority_decisions_show_recommendations_reasons_and_separate_compliance(
    priority_view: tuple[PriorityArtifact, ReportSection, str, str],
) -> None:
    artifact, section, rendered, format_name = priority_view
    literal = rendered.replace("\\_", "_")

    recommendations = []
    for decision in artifact.decisions:
        recommendations.append(decision.recommendation)
    assert tuple(recommendations) == (
        "track",
        "act",
        "manual_triage_required",
        "attend",
        "manual_triage_required",
    )
    for decision, card in zip(artifact.decisions, section.sections, strict=True):
        assert f"Recommendation: {decision.recommendation}" in literal
        reason = (
            escape(decision.reason) if format_name == "html" else escape_markdown(decision.reason)
        )
        assert reason in rendered
        assert card.sections[0].title == f"Matched rule: {decision.matched_rule.id}"
        assert card.sections[-1].title == "Compliance status — separate from the recommendation"
        for status in decision.compliance:
            assert status.status in literal and status.regulation_id in literal
            for missing in status.missing_basis:
                assert missing in literal
    assert "CNVD high grade triggered this policy rule" in rendered


def test_priority_facts_keep_their_values_evidence_unknowns_and_notes(
    priority_view: tuple[PriorityArtifact, ReportSection, str, str],
) -> None:
    artifact, section, rendered, _ = priority_view
    literal = rendered.replace("\\_", "_")

    for decision, card in zip(artifact.decisions, section.sections, strict=True):
        for fact_name in ("applicability", "system_category", "kev", "high_grade"):
            fact = getattr(decision.facts, fact_name)
            row = next(row for row in card.sections[1].tables[0].rows if row[0] == fact_name)
            assert row == (fact_name, fact.value, ", ".join(fact.evidence_ids) or "none")
            for evidence_id in fact.evidence_ids:
                assert evidence_id in rendered
        assert card.sections[2].bullets == (decision.unknown_facts or ("None.",))
        for note in decision.notes:
            assert note in literal
    assert "no recorded exact lookup" in rendered


def test_priority_explains_matched_conditions_and_every_earlier_rule_failure(
    priority_view: tuple[PriorityArtifact, ReportSection, str, str],
) -> None:
    artifact, section, rendered, _ = priority_view
    literal = rendered.replace("\\_", "_")

    assert "What would change this" in rendered
    for decision, card in zip(artifact.decisions, section.sections, strict=True):
        for condition in decision.matched_rule.conditions:
            expected = f"{condition.fact} {condition.operator} ({', '.join(condition.values)})"
            assert expected in literal
        earlier_sections = card.sections[3].sections
        for unmatched, earlier in zip(
            decision.earlier_unmatched_rules, earlier_sections, strict=True
        ):
            assert earlier.title == unmatched.rule_id
            for condition, failure in zip(
                unmatched.failed_conditions, earlier.bullets, strict=True
            ):
                assert (
                    failure
                    == f"{condition.fact} {condition.operator} ({', '.join(condition.values)})"
                )


@pytest.mark.parametrize("format_name", ["html", "md"])
def test_repeated_priority_report_commands_produce_identical_bytes(
    tmp_path: Path, format_name: str
) -> None:
    directory = build_priority_report_session(tmp_path / "sessions")
    output = tmp_path / f"report.{format_name}"
    arguments = ["report", str(directory), "--format", format_name, "--output", str(output)]

    first_status = main(arguments, environment={})
    first_bytes = output.read_bytes()
    second_status = main([*arguments, "--force"], environment={})

    assert first_status == second_status == 0
    assert output.read_bytes() == first_bytes


@pytest.mark.parametrize(
    "invalid_kind", ["json", "schema", "dataset", "digest", "evidence", "symlink", "duplicate-key"]
)
def test_invalid_priority_is_a_visible_finding_and_never_rendered_as_decisions(
    tmp_path: Path, invalid_kind: str
) -> None:
    directory = build_priority_report_session(tmp_path / "sessions")
    path = directory / "priority.json"
    artifact = json.loads(path.read_bytes())
    if invalid_kind == "json":
        path.write_text("{broken")
    elif invalid_kind == "schema":
        artifact["decisions"][0]["recommendation"] = "compliant"
        path.write_text(json.dumps(artifact))
    elif invalid_kind == "dataset":
        artifact["dataset"]["store_manifest_sha256"] = "a" * 64
        path.write_text(json.dumps(artifact))
    elif invalid_kind == "digest":
        artifact["response_digests"][0]["response_sha256"] = "a" * 64
        path.write_text(json.dumps(artifact))
    elif invalid_kind == "evidence":
        artifact["decisions"][0]["facts"]["kev"]["evidence_ids"] = ["ev:000000000000000000000000"]
        path.write_text(json.dumps(artifact))
    elif invalid_kind == "symlink":
        other = tmp_path / "other.json"
        path.rename(other)
        path.symlink_to(other)
    else:
        path.write_text(
            path.read_text().replace(
                '"program_version":', '"program_version":"bad","program_version":'
            )
        )

    contents = SessionChecker(directory).check_with_contents()
    report = build_session_report(contents)

    assert contents.priority is None
    assert not report.check.record.consistent
    assert any(
        violation.location == "priority.json" for violation in report.check.record.violations
    )
    assert all(section.title != "Priority decisions" for section in report.sections)
    checks = next(
        section for section in report.sections if section.title == "Execution and checks"
    ).sections[1]
    assert any(
        paragraph.warning and "priority.json" in paragraph.text for paragraph in checks.paragraphs
    )
    for rendered in (render_html_report(report), render_markdown_report(report)):
        assert "priority.json" in rendered and "Priority decisions" not in rendered
    assert (
        main(
            [
                "report",
                str(directory),
                "--output",
                str(tmp_path / "invalid.html"),
                "--format",
                "html",
            ],
            environment={},
        )
        == 1
    )


@pytest.mark.parametrize("format_name", ["html", "md"])
def test_session_without_priority_renders_byte_identically_to_the_frozen_prior_report(
    tmp_path: Path, format_name: str
) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    report = build_session_report(SessionChecker(directory).check_with_contents())
    expected = Path(__file__).parents[1] / f"fixtures/priority/without-priority.{format_name}"

    rendered = (
        render_html_report(report) if format_name == "html" else render_markdown_report(report)
    )

    assert rendered.encode() == expected.read_bytes()


def test_force_regenerates_an_invalid_derived_priority_artifact(tmp_path: Path) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    assets = write_priority_register(tmp_path / "assets.yaml")
    (directory / "priority.json").write_text("invalid")

    status = main([*priority_arguments(directory, assets), "--force"], environment={})

    assert status == 0
    assert SessionChecker(directory).check_with_contents().priority is not None
