"""CNVD source panels and descriptive counts from recorded lookup comparisons."""

from collections.abc import Sequence

from vulnwitness.application.cnvd_presentation import describe_cnvd_comparison
from vulnwitness.domain.cve_lookup import ComparedCnvdEntry, CveLookupResponse, PendingCnvdLookup
from vulnwitness.domain.session_record import SessionDatasetIdentity
from vulnwitness.domain.session_report import ReportBadge, ReportParagraph, ReportSection
from vulnwitness.domain.source_comparison import SourceComparison


def explain_not_compared(comparison: SourceComparison) -> str:
    """Describe the recorded missing input without rerunning the severity rule."""
    if comparison.not_compared_reason == "no_nvd_record":
        return "NVD's snapshot has no servable record."
    if comparison.not_compared_reason == "no_nvd_cvss3_metric":
        return "NVD's own CVSS v3.1 or v3.0 metric is not recorded."
    return "NVD's own CVSS v3 severity is missing or NONE."


def build_cnvd_entries(
    entries: Sequence[ComparedCnvdEntry], sequence: int, language: str | None
) -> ReportSection:
    """Keep each recorded source statement separate, ordered by CNVD ID."""
    sections: list[ReportSection] = []
    for entry in sorted(entries, key=lambda entry: entry.cnvd_id):
        comparison = entry.source_comparison
        nvd_severity = comparison.nvd_raw_severity
        nvd_value = "not recorded"
        if nvd_severity is not None:
            nvd_value = (
                f"{nvd_severity.base_severity or 'not recorded'} "
                f"· CVSS {nvd_severity.cvss_version} · assessed by {nvd_severity.scorer} "
                f"· {nvd_severity.scorer_type or 'type not recorded'} · channel: NVD"
            )
        paragraphs = [
            ReportParagraph(entry.title, language=language),
            ReportParagraph(
                f"CNVD severity: {comparison.cnvd_raw_severity} "
                "· CNVD three-grade scheme (高 / 中 / 低) · assessed by CNVD"
            ),
            ReportParagraph(f"NVD state: {comparison.nvd_state}"),
            ReportParagraph(f"NVD severity used for comparison: {nvd_value}"),
            ReportParagraph(f"Rule: {comparison.rule}"),
            ReportParagraph(comparison.statement),
            ReportParagraph(f"Evidence: {entry.evidence_id} · call {sequence}"),
        ]
        badges: tuple[ReportBadge, ...] = ()
        comparison_text = describe_cnvd_comparison(comparison)
        if comparison.grade_relative == "higher":
            badges = (ReportBadge(comparison_text),)
        else:
            paragraphs.append(ReportParagraph(comparison_text))
        if comparison.grade_relative == "not_compared":
            paragraphs.append(ReportParagraph(explain_not_compared(comparison)))
        sections.append(
            ReportSection(
                entry.cnvd_id,
                paragraphs=tuple(paragraphs),
                badges=badges,
                sections=(
                    ReportSection(
                        "Full recorded CNVD description · untrusted text",
                        verbatim=entry.description,
                        verbatim_language=language,
                        folded=True,
                        layout="inline",
                    ),
                ),
            )
        )
    return ReportSection("CNVD · untrusted source text", sections=tuple(sections))


def build_pending_cnvd_card(
    cve_id: str, entries: Sequence[PendingCnvdLookup], sequence: int, language: str | None
) -> ReportSection:
    """A pending-only lookup is a CVE card with an explicit NVD absence panel."""
    states: list[str] = []
    for entry in sorted(entries, key=lambda entry: entry.cnvd_id):
        state = entry.source_comparison.nvd_state
        if state not in states:
            states.append(state)
    return ReportSection(
        cve_id,
        paragraphs=(ReportParagraph(f"Recorded lookup · call {sequence}"),),
        sections=(
            ReportSection(
                "Recorded source facts",
                sections=(
                    ReportSection(
                        "NVD",
                        paragraphs=(
                            ReportParagraph("NVD's snapshot has no servable record."),
                            ReportParagraph(f"NVD state: {', '.join(states)}"),
                            ReportParagraph(
                                "Affectedness: unknown; "
                                "configuration and environment not evaluated."
                            ),
                        ),
                    ),
                    build_cnvd_entries(entries, sequence, language),
                ),
                layout="columns",
            ),
        ),
        layout="card",
        anchor=cve_id,
    )


def build_cnvd_facts(
    lookups: Sequence[CveLookupResponse], dataset: SessionDatasetIdentity
) -> tuple[str, ...]:
    """Count distinct CNVD-listed CVEs from recordings, within the pinned session dataset."""
    listed: set[str] = set()
    compared: set[str] = set()
    higher: set[str] = set()
    record_gaps: set[str] = set()
    records: set[str] = set()
    score_gaps: set[str] = set()
    awaiting: set[str] = set()
    deferred: set[str] = set()
    for lookup in lookups:
        entries: list[tuple[str, ComparedCnvdEntry]] = []
        for candidate in lookup.candidates:
            for entry in candidate.record.cnvd:
                entries.append((candidate.record.cve_id, entry))
        for pending in lookup.pending_cnvd:
            entries.append((pending.cve_id, pending))
        for cve_id, entry in entries:
            listed.add(cve_id)
            comparison = entry.source_comparison
            if comparison.grade_relative != "not_compared":
                compared.add(cve_id)
            if comparison.grade_relative == "higher":
                higher.add(cve_id)
            if comparison.not_compared_reason == "no_nvd_record":
                record_gaps.add(cve_id)
            else:
                records.add(cve_id)
            if comparison.not_compared_reason == "no_nvd_cvss3_metric":
                score_gaps.add(cve_id)
            if comparison.nvd_state == "awaiting_analysis":
                awaiting.add(cve_id)
            if comparison.nvd_state == "deferred":
                deferred.add(cve_id)
    if not listed:
        return ()
    identity = (
        f"store {dataset.store_name}"
        if dataset.store_name
        else f"dataset {dataset.served.kind.value}"
    )
    identity += f" (corpus {dataset.corpus_content_sha256})"
    record_denominator = f"{len(records)} distinct CNVD-listed CVEs with a servable NVD record"
    return (
        f"CNVD counts below cover recorded lookups from {identity}.",
        f"CNVD grades higher under cnvd_grade_vs_nvd_own_cvss3: {len(higher)} of "
        f"{len(compared)} distinct CVEs compared.",
        f"NVD record gaps: {len(record_gaps)} of {len(listed)} distinct CNVD-listed CVEs "
        "have no servable record in the snapshot.",
        f"NVD score gaps: {len(score_gaps)} of {record_denominator} "
        "have no NVD-owned CVSS v3.1 or v3.0 metric for comparison.",
        f"NVD status awaiting_analysis: {len(awaiting)} of {record_denominator}.",
        f"NVD status deferred: {len(deferred)} of {record_denominator}.",
        "These counts describe recorded lookups only; they are not a ranking and change no "
        "triage order, selection or checker verdict. NVD status is independent of score gaps; "
        "awaiting_analysis or deferred does not mean no score.",
    )
