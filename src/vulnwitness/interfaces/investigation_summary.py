"""Deterministic, plain-text views of an investigation's existing evidence."""

from itertools import zip_longest
from textwrap import wrap

from vulnwitness.application.investigation_presentation import (
    STATUS_SENTENCES,
    STOP_SENTENCES,
    format_found_by,
    format_need,
    format_severity,
    format_warning,
    has_candidate_labels,
)
from vulnwitness.domain.cve import CveRecord
from vulnwitness.domain.investigation import (
    EvidenceNeedKind,
    KnowledgeEvidenceSet,
    NeedOutcome,
)
from vulnwitness.domain.relevance import RelevanceLabel

TABLE_WIDTHS = (4, 14, 17, 14, 10, 16, 13)


def format_paragraph(text: str) -> str:
    return "\n".join(wrap(text, width=100, subsequent_indent="  "))


def format_products(record: CveRecord) -> str:
    product_names: list[str] = []
    for product in record.affected:
        product_name = f"{product.vendor}/{product.product}"
        if product_name not in product_names:
            product_names.append(product_name)
    if not product_names:
        return "unknown"
    product_text = ", ".join(product_names[:2])
    if len(product_names) > 2:
        product_text += f" +{len(product_names) - 2}"
    return product_text


def format_table_row(cells: tuple[str, ...]) -> str:
    wrapped_cells: list[list[str]] = []
    for cell, width in zip(cells, TABLE_WIDTHS, strict=True):
        wrapped_cells.append(wrap(cell, width=width))
    lines: list[str] = []
    for fragments in zip_longest(*wrapped_cells, fillvalue=""):
        padded_cells: list[str] = []
        for fragment, width in zip(fragments, TABLE_WIDTHS, strict=True):
            padded_cells.append(fragment.ljust(width))
        lines.append("  ".join(padded_cells).rstrip())
    return "\n".join(lines)


def format_candidates(evidence_set: KnowledgeEvidenceSet) -> str:
    lines = ["CVE candidates:"]
    if not evidence_set.implementation_candidates:
        lines.append("None returned.")
        return "\n".join(lines)
    lines.append(
        format_table_row(
            ("Rank", "CVE ID", "Severity", "KEV", "Published", "Vendor/product", "Found by")
        )
    )
    previous_label: RelevanceLabel | None = None
    has_labels = has_candidate_labels(evidence_set)
    for candidate in evidence_set.implementation_candidates[:20]:
        if has_labels and (candidate.rank == 1 or candidate.relevance_label != previous_label):
            label = candidate.relevance_label
            heading = "Unassessed" if label is None else label.value.replace("_", " ").capitalize()
            lines.append(heading + ":")
            previous_label = label
        record = candidate.candidate.record
        kev = "no" if record.kev is None else f"yes {record.kev.date_added.isoformat()}"
        published = "unknown" if record.published is None else record.published.date().isoformat()
        lines.append(
            format_table_row(
                (
                    str(candidate.rank),
                    record.cve_id,
                    format_severity(record),
                    kev,
                    published,
                    format_products(record),
                    format_found_by(candidate, evidence_set),
                )
            )
        )
        for note in candidate.nvd_version_notes or ():
            outcome = note.outcome.replace("_", " ")
            reason = f" [{note.reason_code}]" if note.outcome == "unknown" else ""
            lines.append(format_paragraph(f"  NVD ({note.mention}): {outcome}{reason}."))
    lines.append(
        format_paragraph(
            "Weakness associations (derived catalogue context): "
            "use vulnwitness lookup <CVE-ID> for full paths, sources and omitted counts."
        )
    )
    if evidence_set.interpretation.affectedness_mentions:
        lines.append(
            format_paragraph(
                "NVD CPE version condition hits: the full configuration and environment "
                "conditions were not evaluated."
            )
        )
    if len(evidence_set.implementation_candidates) > 20:
        lines.append(
            f"+{len(evidence_set.implementation_candidates) - 20} more CVEs in --format json."
        )
    for warning in evidence_set.warnings:
        if warning.code in {"answer_truncated", "result_limit_reached"}:
            lines.append(format_paragraph(format_warning(warning)))
    return "\n".join(lines)


def format_unknowns(evidence_set: KnowledgeEvidenceSet) -> str:
    lines = ["Could not be judged:"]
    affectedness_subjects: list[str | None] = []
    for need in evidence_set.coverage.needs:
        if need.outcome is NeedOutcome.FOUND:
            continue
        description = format_need(need, has_candidate_labels(evidence_set))
        if need.kind is EvidenceNeedKind.AFFECTEDNESS:
            description += " Version affectedness was not assessed."
            affectedness_subjects.append(need.subject)
        lines.append(format_paragraph(description))
    for applicability in evidence_set.product_applicability:
        if applicability.product not in affectedness_subjects:
            lines.append(
                format_paragraph(f"{applicability.product}: version affectedness was not assessed.")
            )
    if len(lines) == 1:
        lines.append("None recorded.")
    return "\n".join(lines)


def render_investigation_summary(evidence_set: KnowledgeEvidenceSet) -> str:
    """Return a summary using only the set's fields, with lines at most 100 columns wide."""
    sections = [
        format_paragraph(f"Investigation: {evidence_set.request.query}"),
        f"Scope: {evidence_set.applied_scope}",
        format_paragraph(f"Status: {STATUS_SENTENCES[evidence_set.status]}"),
        format_paragraph(f"Stop reason: {STOP_SENTENCES[evidence_set.stop_reason]}"),
        "",
        "Needs:",
    ]
    for need in evidence_set.coverage.needs:
        sections.append(format_paragraph(format_need(need, has_candidate_labels(evidence_set))))
    if has_candidate_labels(evidence_set):
        sections.extend(
            (
                "",
                format_paragraph(
                    "The model assessed the candidates' relevance; the system has not "
                    "confirmed that the evidence need is met."
                ),
            )
        )
    sections.extend(("", format_candidates(evidence_set)))
    if evidence_set.protocol_context:
        sections.extend(("", "Protocol context:"))
        for technique in evidence_set.protocol_context[:10]:
            sections.append(format_paragraph(f"{technique.technique_id}: {technique.name}"))
        if len(evidence_set.protocol_context) > 10:
            sections.append(f"+{len(evidence_set.protocol_context) - 10} more")
    sections.extend(("", format_unknowns(evidence_set), "", "Warnings:"))
    for warning in evidence_set.warnings:
        sections.append(format_paragraph(format_warning(warning)))
    if not evidence_set.warnings:
        sections.append("None recorded.")
    evidence_location = (
        "Full evidence set: --format json; one source record: vulnwitness evidence <evidence_id>."
    )
    sections.extend(("", "Where the evidence is:", format_paragraph(evidence_location)))
    if evidence_set.evidence:
        sections.append(f"Example: vulnwitness evidence {evidence_set.evidence[0].evidence_id}")
    return "\n".join(sections)
