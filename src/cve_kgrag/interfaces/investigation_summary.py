"""Deterministic, plain-text views of an investigation's existing evidence."""

from itertools import zip_longest
from textwrap import wrap

from cve_kgrag.domain.cve import CveRecord, CvssMetric
from cve_kgrag.domain.investigation import (
    EvidenceNeed,
    EvidenceNeedKind,
    InvestigationCandidate,
    InvestigationWarning,
    KnowledgeEvidenceSet,
    NeedOutcome,
)
from cve_kgrag.domain.relevance import RelevanceLabel

STATUS_SENTENCES = {
    "ok": "Every evidence need was met; that does not show the list is complete.",
    "no_match": "No matches were returned.",
    "partial": "The investigation returned a partial answer.",
    "incomplete_index": "The search index was incomplete.",
    "source_unavailable": "A required source was unavailable.",
    "backend_error": "An evidence source or validation check failed.",
    "policy_blocked": "The investigation policy blocked the request.",
}
STOP_SENTENCES = {
    "sufficient": "Each need was met through an exact lookup or the reviewed topic.",
    "no_evidence": "The investigation stopped without finding evidence.",
    "budget_exhausted": "The investigation reached a budget limit.",
    "source_unavailable": "A required source could not serve the investigation.",
    "policy_blocked": "The request could not proceed under the investigation policy.",
    "invalid_evidence": "The evidence failed validation.",
    "needs_unmet": "Matches were found but not every need was met.",
}
NEED_LABELS = {
    "named_cve": "Named CVE",
    "implementation_cves": "Implementation CVEs",
    "protocol_context": "Protocol context",
    "affectedness": "Affectedness",
}
NEED_OUTCOMES = {
    "matches_unassessed": "matches found; their relevance was not assessed",
    "not_found": "the lookup or search did not meet this need",
    "source_unavailable": "the required source was unavailable",
    "unsupported": "no tool could serve this need for the interpreted query",
    "not_evaluated": "this need was not evaluated",
}
TOOL_LABELS = {
    "cve_exact_lookup": "exact lookup",
    "topic_context": "topic card",
    "cve_search": "word match",
}
WARNING_SENTENCES = {
    "excluded_term": "The query contains a term excluded from topic resolution.",
    "topic_not_resolved": "The query did not resolve to a reviewed topic.",
    "topic_pending_review": "The topic card used for retrieval is pending review.",
    "no_searchable_terms": "The query contained no searchable terms.",
    "applicability_unknown": "Version affectedness was not assessed.",
    "model_plan_rejected": "The proposed plan was rejected by the investigation policy.",
    "evidence_discarded": "A step's evidence was discarded because of a budget limit.",
    "unrelated_candidates_dropped": "Candidates unrelated to the topic were omitted.",
    "answer_truncated": "The evidence set omits additional CVEs or techniques because of a limit.",
    "result_limit_reached": "A search reached its result limit; more CVE matches may exist.",
    "term_not_indexed": "A search term was absent from the searched index.",
}
TABLE_WIDTHS = (4, 14, 17, 14, 10, 16, 13)
SEVERITY_ORDER = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def format_paragraph(text: str) -> str:
    return "\n".join(wrap(text, width=100, subsequent_indent="  "))


def format_need(need: EvidenceNeed, has_relevance_labels: bool = False) -> str:
    label = NEED_LABELS[need.kind]
    if need.subject is not None:
        label += f" ({need.subject})"
    if need.outcome is NeedOutcome.FOUND:
        if need.kind is EvidenceNeedKind.NAMED_CVE:
            outcome = "found through an exact lookup"
        else:
            outcome = "found through the reviewed topic"
    elif need.outcome is NeedOutcome.MATCHES_UNASSESSED and has_relevance_labels:
        outcome = "matches found; the system has not confirmed that this need is met"
    else:
        outcome = NEED_OUTCOMES[need.outcome]
    return f"{label}: {outcome}."


def rank_cvss_metric(metric: CvssMetric) -> tuple[bool, int, float]:
    """Prefer primary scorers, then the highest supplied severity and base score."""
    severity_rank = -1
    if metric.base_severity is not None:
        severity_rank = SEVERITY_ORDER.index(metric.base_severity)
    return metric.scorer_type == "primary", severity_rank, metric.base_score


def format_severity(record: CveRecord) -> str:
    if not record.cvss:
        return "unknown"
    metric = max(record.cvss, key=rank_cvss_metric)
    severity = metric.base_severity or "unknown"
    return f"{severity} {metric.base_score:.1f} v{metric.version}"


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


def format_found_by(candidate: InvestigationCandidate, evidence_set: KnowledgeEvidenceSet) -> str:
    tool_labels: list[str] = []
    for step in evidence_set.trajectory.steps:
        if step.step_index in candidate.found_by_steps:
            label = TOOL_LABELS[step.call.tool]
            if label not in tool_labels:
                tool_labels.append(label)
    return ", ".join(tool_labels)


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


def format_warning(warning: InvestigationWarning) -> str:
    sentence = WARNING_SENTENCES.get(warning.code)
    if sentence is None:
        return str(warning.code)
    return f"[{warning.code}] {sentence} Subject: {warning.subject}"


def has_candidate_labels(evidence_set: KnowledgeEvidenceSet) -> bool:
    return any(
        round_record.relevance_assessment is not None and round_record.relevance_assessment.labels
        for round_record in evidence_set.trajectory.rounds
    )


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
        "Full evidence set: --format json; one source record: cve-kgrag evidence <evidence_id>."
    )
    sections.extend(("", "Where the evidence is:", format_paragraph(evidence_location)))
    if evidence_set.evidence:
        sections.append(f"Example: cve-kgrag evidence {evidence_set.evidence[0].evidence_id}")
    return "\n".join(sections)
