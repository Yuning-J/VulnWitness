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
    for row in table.rows:
        lines.append("| " + " | ".join(escape_markdown(cell) for cell in row) + " |")
    if not table.rows:
        lines.extend(("", "None recorded."))
    return "\n".join(lines)


def render_markdown_section(section: ReportSection, level: int) -> str:
    lines = ["#" * min(level, 6) + " " + escape_markdown(section.title), ""]
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
    for subsection in section.sections:
        lines.append(render_markdown_section(subsection, level + 1))
    return "\n".join(lines)


def render_markdown_report(report: SessionReport) -> str:
    lines = ["# " + escape_markdown(report.title), ""]
    if report.synthetic:
        lines.extend(("> **Synthetic demonstration data**", ""))
    for section in report.sections:
        lines.append(render_markdown_section(section, 2))
    return "\n".join(lines).rstrip() + "\n"
