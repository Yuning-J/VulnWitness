"""Recorded demo investigations retain their evidence in every report view."""

from dataclasses import asdict
from html import escape
from pathlib import Path

import pytest

from tests.support.workspaces import build_test_workspace
from vulnwitness.domain.investigation import KnowledgeEvidenceSet
from vulnwitness.domain.nvd_version_note import NvdVersionUnknown
from vulnwitness.domain.weakness_associations import DERIVED_ASSOCIATION_NOTE
from vulnwitness.domain.workspace import InvestigationRequest, StartInvestigationRequest
from vulnwitness.interfaces.knowledge_tools import ToolAnswer
from vulnwitness.interfaces.report_html import render_html_report
from vulnwitness.interfaces.report_markdown import escape_markdown, render_markdown_report


@pytest.mark.parametrize(
    "scope,technique_count,status",
    (("mixed", 4, "partial"), ("implementation_only", 0, "no_match")),
)
def test_topic_only_reports_show_recorded_facts_and_sentences_for_empty_lists(
    tmp_path: Path, scope: str, technique_count: int, status: str
) -> None:
    # Arrange
    _, workspace = build_test_workspace(tmp_path / "workspace")
    started = workspace.start(StartInvestigationRequest(goal="Review GTP"))
    workspace.record(
        started.session_id, "investigate_telecom_topic", {"query": "GTP", "scope": scope}
    )
    request = InvestigationRequest(session_id=started.session_id)
    fact = (
        f"Call 1 investigation ({scope}): 0 implementation candidates, "
        f"{technique_count} FiGHT techniques, status {status}"
    )

    # Act
    model = workspace.report_model(request)
    html = render_html_report(model)
    markdown = render_markdown_report(model)
    repeated = workspace.report_model(request)

    # Assert
    assert model == repeated
    assert html == render_html_report(repeated)
    assert markdown == render_markdown_report(repeated)
    assert model.sections[1].sections[0].bullets == (fact,)
    limits = model.sections[1].sections[1].bullets
    assert "Affectedness is unknown for every CVE" in limits[0]
    assert DERIVED_ASSOCIATION_NOTE in limits
    assert any("Need " in limit for limit in limits)
    for section in model.sections:
        assert not section.title.startswith(("CVE details", "Read inventory"))
    investigation = next(section for section in model.sections if section.title == "Investigations")
    candidates = investigation.sections[0].sections[1]
    protocol = investigation.sections[0].sections[2]
    assert candidates.tables == ()
    assert candidates.paragraphs[0].text == "No implementation candidates were returned."
    if technique_count == 0:
        assert protocol.tables == ()
        assert protocol.paragraphs[-1].text == "No FiGHT techniques were returned."
    else:
        assert len(protocol.tables[0].rows) == technique_count
    assert escape(fact) in html
    assert escape_markdown(fact) in markdown
    for document in (html, markdown):
        assert "No implementation candidates were returned." in document
        assert "read entries match the NVD product field" not in document
        assert "CVE details returned" not in document
        assert "CVE details ·" not in document and "Read inventory ·" not in document
        if technique_count == 0:
            assert "No FiGHT techniques were returned." in document


@pytest.mark.parametrize("limit,context_bytes", ((1, 100000), (20, 100000), (20, 10000)))
def test_mixed_investigation_reports_preserve_returned_candidates_techniques_and_warnings(
    tmp_path: Path, limit: int, context_bytes: int
) -> None:
    # Arrange
    _, workspace = build_test_workspace(tmp_path / "workspace")
    started = workspace.start(StartInvestigationRequest(goal="Review 5G-AKA"))
    saved = workspace.record(
        started.session_id,
        "investigate_telecom_topic",
        {
            "query": "5G-AKA",
            "scope": "mixed",
            "budget": {"max_results_per_call": limit, "max_context_bytes": context_bytes},
        },
    )
    assert isinstance(saved, ToolAnswer)
    answer = KnowledgeEvidenceSet.model_validate_json(saved.json_text)
    assert answer.protocol_context and answer.implementation_candidates and answer.warnings
    candidate_id = answer.implementation_candidates[0].candidate.record.cve_id
    workspace.record(started.session_id, "lookup_cve", {"cve_id": candidate_id})
    request = InvestigationRequest(session_id=started.session_id)

    # Act
    model = workspace.report_model(request)
    html = render_html_report(model)
    markdown = render_markdown_report(model)
    model_text = str(asdict(model))
    repeated = workspace.report_model(request)

    # Assert
    assert model == repeated
    assert html == render_html_report(repeated)
    assert markdown == render_markdown_report(repeated)
    for technique in answer.protocol_context:
        for text in (
            technique.technique_id,
            technique.name,
            technique.status.value,
            *technique.tactic_names,
            *technique.matched_terms,
            *technique.evidence_ids,
        ):
            assert text in model_text
            assert escape(text) in html
            assert escape_markdown(text) in markdown
        for evidence_id in technique.evidence_ids:
            anchor = next(anchor for anchor in answer.evidence if anchor.evidence_id == evidence_id)
            assert escape(anchor.source_uri) in html
            assert escape_markdown(anchor.source_name) in markdown
    for candidate in answer.implementation_candidates:
        record = candidate.candidate.record
        assert record.cve_id in html and record.cve_id in markdown
        assert record.published is not None
        assert record.published.date().isoformat() in html
        steps = ", ".join(str(step) for step in candidate.found_by_steps)
        assert f"Steps {steps}" in html
    for warning in answer.warnings:
        assert warning.code.value in model_text and warning.code.value in html
        assert escape_markdown(warning.code.value) in markdown
        assert escape(warning.subject) in html
    for step in answer.trajectory.steps:
        for warning in step.topic_warnings:
            assert warning.code.value in html
            assert escape_markdown(warning.code.value) in markdown
            assert escape(warning.subject) in html
    if limit == 1:
        assert "protocol_context_truncated" in html
        assert "answer_truncated" in html
    if context_bytes == 10000:
        assert "evidence_prefix_omitted" in html
    assert f'href="#{candidate_id}"' in html
    assert f"[{candidate_id}](#{candidate_id})" in markdown
    assert "Protocol threat context, separate from implementation CVEs" in html
    assert "not evidence that a CVE was exploited" in html
    assert str(answer.status) in html and str(answer.stop_reason) in html


def test_investigation_reports_show_each_recorded_nvd_version_outcome(tmp_path: Path) -> None:
    # Arrange
    _, workspace = build_test_workspace(tmp_path / "workspace")
    started = workspace.start(StartInvestigationRequest(goal="Review version conditions"))
    saved = workspace.record(
        started.session_id,
        "investigate_telecom_topic",
        {
            "query": "Is democorp 2.0 affected by CVE-9999-0001, CVE-9999-0002 and CVE-9999-0003?",
            "scope": "implementation_only",
        },
    )
    assert isinstance(saved, ToolAnswer)
    answer = KnowledgeEvidenceSet.model_validate_json(saved.json_text)

    # Act
    model = workspace.report_model(InvestigationRequest(session_id=started.session_id))
    html = render_html_report(model)
    markdown = render_markdown_report(model)

    # Assert
    outcomes = set()
    for candidate in answer.implementation_candidates:
        assert candidate.nvd_version_notes
        for note in candidate.nvd_version_notes:
            outcomes.add(note.outcome)
            text = f"{note.mention}: {note.outcome} · {note.wording}"
            assert escape(text) in html
            assert escape_markdown(text) in markdown
    assert outcomes == {"hit", "no_hit", "unknown"}
    assert "configuration and environment" in html


def test_hostile_technique_and_candidate_text_stays_literal_in_both_reports(tmp_path: Path) -> None:
    # Arrange
    _, workspace = build_test_workspace(tmp_path / "workspace")
    started = workspace.start(StartInvestigationRequest(goal="Review recorded text"))
    workspace.record(
        started.session_id, "investigate_telecom_topic", {"query": "5G-AKA", "scope": "mixed"}
    )
    response_path = tmp_path / "workspace" / started.session_id / "responses" / "0001.json"
    answer = KnowledgeEvidenceSet.model_validate_json(response_path.read_bytes())
    hostile = '<img src=x onerror="alert(1)"> [click](https://attacker.invalid) | *text*'
    techniques = list(answer.protocol_context)
    techniques[0] = techniques[0].model_copy(update={"name": hostile})
    candidates = list(answer.implementation_candidates)
    candidate = candidates[0]
    # The report must render recorded source text safely even when record checks fail.
    candidates[0] = candidate.model_copy(
        update={
            "nvd_version_notes": (
                NvdVersionUnknown(
                    mention=hostile, wording=hostile, reason_code="no_matching_product"
                ),
            )
        }
    )
    answer = answer.model_copy(
        update={
            "protocol_context": tuple(techniques),
            "implementation_candidates": tuple(candidates),
        }
    )
    response_path.write_text(answer.model_dump_json())

    # Act
    model = workspace.report_model(InvestigationRequest(session_id=started.session_id))
    html = render_html_report(model)
    markdown = render_markdown_report(model)

    # Assert
    assert hostile not in html and hostile not in markdown
    assert escape(hostile) in html
    assert escape_markdown(hostile) in markdown
