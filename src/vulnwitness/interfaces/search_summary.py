"""Ranked search matches and channel outcomes without relevance assertions."""

from vulnwitness.application.investigation_presentation import format_severity
from vulnwitness.domain.search import SearchResponse
from vulnwitness.interfaces.investigation_summary import format_paragraph
from vulnwitness.interfaces.record_summary import format_published, summarize_description


def render_search_summary(search: SearchResponse) -> str:
    """Keep each description on one table line and preserve supplied rank order."""
    lines = [
        format_paragraph(f"Search: {search.query}"),
        f"Status: {search.status}",
        "Ranks are word matches, not an assessment of relevance, severity or exploitability.",
        "Exact-ID, semantic or graph channels may also contribute when executed.",
        "",
        f"{'Rank':<4}  {'CVE ID':<14}  {'Published':<10}  {'Severity':<18}  Description",
    ]
    for candidate in search.candidates:
        record = candidate.record
        lines.append(
            f"{candidate.rank:<4}  {record.cve_id:<14}  {format_published(record):<10}  "
            f"{format_severity(record):<18}  {summarize_description(record, width=100)}"
        )
    if not search.candidates:
        lines.append("None returned.")
    lines.extend(("", "Channel outcomes:"))
    for outcome in search.channel_outcomes:
        detail = "" if outcome.detail is None else f"; {outcome.detail}"
        lines.append(format_paragraph(f"{outcome.channel}: {outcome.status}{detail}"))
    lines.extend(("", "Warnings:"))
    for warning in search.warnings:
        lines.append(format_paragraph(f"[{warning.code}] Subject: {warning.subject}"))
    if not search.warnings:
        lines.append("None recorded.")
    return "\n".join(lines)
