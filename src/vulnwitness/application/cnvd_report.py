"""CNVD source panels and descriptive counts from recorded lookup comparisons."""

from collections.abc import Sequence

from vulnwitness.domain.cve_lookup import ComparedCnvdEntry, CveLookupResponse, PendingCnvdLookup
from vulnwitness.domain.session_report import ReportBadge, ReportParagraph, ReportSection
from vulnwitness.domain.source_comparison import SourceComparison


def explain_not_compared(comparison: SourceComparison) -> str:
    """Describe the missing comparison input without rerunning the severity rule."""
    if comparison.nvd_state in {"not_in_nvd_snapshot", "rejected_by_nvd", "excluded_by_import"}:
        return "NVD's snapshot has no servable record."
    if comparison.nvd_raw_severity is None:
        return "NVD's own CVSS v3.1 or v3.0 metric is not recorded."
    return "NVD's own CVSS v3 severity is missing or NONE."


def build_cnvd_entries(entries: Sequence[ComparedCnvdEntry], sequence: int) -> ReportSection:
    """Keep each recorded source statement separate, ordered by CNVD ID."""
    sections: list[ReportSection] = []
    for entry in sorted(entries, key=lambda entry: entry.cnvd_id):
        comparison = entry.source_comparison
        nvd_severity = comparison.nvd_raw_severity
        nvd_value = (
            "not recorded"
            if nvd_severity is None
            else f"{nvd_severity.base_severity or 'not recorded'} "
            f"· NVD's own CVSS {nvd_severity.cvss_version}"
        )
        paragraphs = [
            ReportParagraph(entry.title),
            ReportParagraph(f"CNVD severity: {comparison.cnvd_raw_severity}"),
            ReportParagraph(f"NVD state: {comparison.nvd_state}"),
            ReportParagraph(f"NVD severity used for comparison: {nvd_value}"),
            ReportParagraph(f"Rule: {comparison.rule}"),
            ReportParagraph(comparison.statement),
            ReportParagraph(f"Evidence: {entry.evidence_id} · call {sequence}"),
        ]
        if comparison.grade_relative == "not_compared":
            paragraphs.append(ReportParagraph(explain_not_compared(comparison)))
        sections.append(
            ReportSection(
                entry.cnvd_id,
                paragraphs=tuple(paragraphs),
                badges=(ReportBadge(comparison.grade_relative),),
                sections=(
                    ReportSection(
                        "Full recorded CNVD description · untrusted text",
                        verbatim=entry.description,
                        folded=True,
                        layout="inline",
                    ),
                ),
            )
        )
    return ReportSection("CNVD · untrusted source text", sections=tuple(sections))


def build_pending_cnvd_card(
    cve_id: str, entries: Sequence[PendingCnvdLookup], sequence: int
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
                    build_cnvd_entries(entries, sequence),
                ),
                layout="columns",
            ),
        ),
        layout="card",
        anchor=cve_id,
    )


def build_cnvd_facts(lookups: Sequence[CveLookupResponse]) -> tuple[str, ...]:
    """Count distinct CVEs across recorded calls; these counts establish no ranking."""
    listed: set[str] = set()
    disagreements: set[str] = set()
    unanalysed: set[str] = set()
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
            if comparison.grade_relative in {"higher", "lower"}:
                disagreements.add(cve_id)
            if comparison.nvd_state in {
                "awaiting_analysis",
                "deferred",
                "not_in_nvd_snapshot",
                "rejected_by_nvd",
                "excluded_by_import",
            }:
                unanalysed.add(cve_id)
    if not listed:
        return ()
    disagreement_noun = "CVE" if len(disagreements) == 1 else "CVEs"
    unanalysed_noun = "CVE" if len(unanalysed) == 1 else "CVEs"
    return (
        f"CNVD severity disagrees with NVD for {len(disagreements)} {disagreement_noun} under "
        "cnvd_grade_vs_nvd_own_cvss3 (VulnWitness's comparison).",
        f"CNVD lists {len(unanalysed)} {unanalysed_noun} whose NVD state is "
        "awaiting_analysis or deferred, "
        "or whose NVD snapshot has no servable record. Counts describe recorded lookups "
        "only; they are not a ranking.",
    )
