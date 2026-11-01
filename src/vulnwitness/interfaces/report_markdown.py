"""GitHub-flavoured Markdown rendering of a format-independent session report."""

import html
import re

from vulnwitness.domain.session_report import ReportSection, ReportTable, SessionReport


def escape_markdown(text: str) -> str:
    """Keep untrusted prose literal, including HTML, links and table delimiters."""
    characters: list[str] = []
    for character in html.escape(" ".join(text.split()), quote=False):
        if character in "\\`*_[]|~#":
            characters.append("\\")
        characters.append(character)
    literal = "".join(characters)
    if literal.startswith(("-", "+", "=")):
        literal = "\\" + literal
    return re.sub(r"^([0-9]+)([.)])(?= )", r"\1\\\2", literal)


def render_markdown_table(table: ReportTable) -> str:
    lines = [
        "| " + " | ".join(escape_markdown(cell) for cell in table.headings) + " |",
        "| " + " | ".join("---" for _ in table.headings) + " |",
    ]
    links: dict[str, str] = {}
    for link in table.links:
        links[link.text] = link.target
    for row in table.rows:
        cells: list[str] = []
        for cell in row:
            literal = escape_markdown(cell)
            if cell in links:
                literal = f"[{literal}]({links[cell]})"
            cells.append(literal)
        lines.append("| " + " | ".join(cells) + " |")
    if not table.rows:
        lines.extend(("", "None recorded."))
    return "\n".join(lines)


def render_markdown_section(section: ReportSection, level: int) -> str:
    lines = ["#" * min(level, 6) + " " + escape_markdown(section.title), ""]
    if section.folded:
        lines.extend(("<details>", f"<summary>{html.escape(section.title)}</summary>", ""))
    if section.anchor:
        lines.extend((f'<a id="{html.escape(section.anchor, quote=True)}"></a>', ""))
    if section.heading_note:
        lines.extend((escape_markdown(section.heading_note), ""))
    for stat in section.stats:
        lines.extend(
            (
                f"**{escape_markdown(stat.label)}:** {escape_markdown(stat.value)} "
                f"· {escape_markdown(stat.note)}",
                "",
            )
        )
    for badge in section.badges:
        mark = {"ok": "✓", "bad": "✗", "warn": "!", "neutral": ""}[badge.tone]
        lines.extend((f"{mark} {escape_markdown(badge.text)}", ""))
    for chip in section.chips:
        lines.extend((escape_markdown(chip), ""))
    for link in section.links:
        lines.extend((f"[{escape_markdown(link.text)}]({link.target})", ""))
    for paragraph in section.paragraphs:
        text = escape_markdown(paragraph.text)
        lines.extend((f"**{text}**" if paragraph.warning else text, ""))
    for bullet in section.bullets:
        lines.append("- " + escape_markdown(bullet))
    if section.bullets:
        lines.append("")
    if section.verbatim is not None:
        # An indented block cannot be closed by a hostile backtick fence in recorded text.
        for line in section.verbatim.splitlines():
            lines.append("    " + line)
        lines.append("")
    for table in section.tables:
        lines.extend((render_markdown_table(table), ""))
    if section.facts:
        rows: list[tuple[str, ...]] = []
        for fact in section.facts:
            value = fact.value
            if fact.badge is not None:
                value = f"{fact.badge.text} {value}".rstrip()
            if fact.detail:
                value += f" · {fact.detail}"
            rows.append((fact.label, value))
        lines.extend(
            (render_markdown_table(ReportTable(("Fact", "Recorded value"), tuple(rows))), "")
        )
    for subsection in section.sections:
        lines.append(render_markdown_section(subsection, level + 1))
    if section.folded:
        lines.extend(("</details>", ""))
    return "\n".join(lines)


def render_markdown_report(report: SessionReport) -> str:
    lines = ["# " + escape_markdown(report.title), ""]
    if report.synthetic:
        lines.extend(("> **Synthetic demonstration data**", ""))
    for section in report.sections:
        lines.append(render_markdown_section(section, 2))
    return "\n".join(lines).rstrip() + "\n"
