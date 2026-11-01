"""Report sections for each recorded investigation, without reinterpreting evidence."""

from vulnwitness.application.investigation_presentation import (
    STATUS_SENTENCES,
    STOP_SENTENCES,
    format_found_by,
    format_need,
    format_severity,
    format_warning,
    has_candidate_labels,
)
from vulnwitness.domain.investigation import KnowledgeEvidenceSet
from vulnwitness.domain.session_report import (
    ReportLink,
    ReportParagraph,
    ReportSection,
    ReportTable,
)


def build_investigation_report(
    answer: KnowledgeEvidenceSet, sequence: int, card_ids: set[str]
) -> ReportSection:
    """Keep all returned candidates, techniques and answer/step warnings in recorded order."""
    candidates: list[tuple[str, ...]] = []
    links: list[ReportLink] = []
    for candidate in answer.implementation_candidates:
        record = candidate.candidate.record
        steps = ", ".join(str(index) for index in candidate.found_by_steps)
        notes: list[str] = []
        for note in candidate.nvd_version_notes or ():
            notes.append(f"{note.mention}: {note.outcome} · {note.wording}")
        candidates.append(
            (
                record.cve_id,
                "unknown" if record.published is None else record.published.date().isoformat(),
                format_severity(record),
                candidate.relevance_label.value if candidate.relevance_label else "unassessed",
                f"Steps {steps} · {format_found_by(candidate, answer)}",
                "; ".join(notes) or "not recorded",
            )
        )
        if record.cve_id in card_ids:
            links.append(ReportLink(record.cve_id, f"#{record.cve_id}"))
    anchors = {}
    for evidence_anchor in answer.evidence:
        anchors[evidence_anchor.evidence_id] = evidence_anchor
    techniques: list[tuple[str, ...]] = []
    for technique in answer.protocol_context:
        sources: list[str] = []
        for evidence_id in technique.evidence_ids:
            anchor = anchors.get(evidence_id)
            source = (
                "source unavailable"
                if anchor is None
                else f"{anchor.source_name} · {anchor.source_uri} · {anchor.locator}"
            )
            sources.append(f"{evidence_id} · {source}")
        techniques.append(
            (
                technique.technique_id,
                technique.name,
                ", ".join(technique.tactic_names),
                technique.status.value,
                ", ".join(technique.matched_terms) or "none recorded",
                "; ".join(sources),
            )
        )
    warnings: list[str] = []
    for warning in answer.warnings:
        warnings.append(format_warning(warning))
    for step in answer.trajectory.steps:
        for topic_warning in step.topic_warnings:
            warnings.append(f"Step {step.step_index}: {format_warning(topic_warning)}")
        for search_warning in step.search_warnings:
            warnings.append(f"Step {step.step_index}: {format_warning(search_warning)}")
    needs: list[str] = []
    for need in answer.coverage.needs:
        needs.append(format_need(need, has_candidate_labels(answer)))
    return ReportSection(
        f"Call {sequence} · {answer.request.query}",
        sections=(
            ReportSection(
                "Status and needs",
                paragraphs=(
                    ReportParagraph(f"Scope: {answer.applied_scope}"),
                    ReportParagraph(f"Status: {answer.status} · {STATUS_SENTENCES[answer.status]}"),
                    ReportParagraph(
                        f"Stop reason: {answer.stop_reason} · {STOP_SENTENCES[answer.stop_reason]}"
                    ),
                ),
                bullets=tuple(needs),
            ),
            ReportSection(
                "Implementation candidates",
                paragraphs=()
                if candidates
                else (ReportParagraph("No implementation candidates were returned."),),
                tables=(
                    ReportTable(
                        (
                            "CVE",
                            "Published",
                            "Severity",
                            "Relevance",
                            "Found by",
                            "NVD version note",
                        ),
                        tuple(candidates),
                        tuple(links),
                    ),
                )
                if candidates
                else (),
            ),
            ReportSection(
                "Protocol context (FiGHT)",
                paragraphs=(
                    ReportParagraph(
                        "Protocol threat context, separate from implementation CVEs. "
                        "A FiGHT technique is not evidence that a CVE was exploited."
                    ),
                )
                + (() if techniques else (ReportParagraph("No FiGHT techniques were returned."),)),
                tables=(
                    ReportTable(
                        (
                            "Technique",
                            "Name",
                            "Tactics",
                            "Status",
                            "Matched terms",
                            "Evidence / source",
                        ),
                        tuple(techniques),
                    ),
                )
                if techniques
                else (),
            ),
            ReportSection("Warnings", bullets=tuple(warnings) or ("None recorded.",)),
        ),
    )
