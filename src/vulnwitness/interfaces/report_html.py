"""Self-contained HTML rendering; every recorded value is escaped as text."""

from html import escape
from importlib.resources import files
from string import Template

from vulnwitness.domain.session_report import ReportSection, ReportTable, SessionReport


def render_html_table(table: ReportTable) -> str:
    fragments = ['<div class="table-scroll"><table><thead><tr>']
    for heading in table.headings:
        fragments.append(f'<th scope="col">{escape(heading)}</th>')
    fragments.append("</tr></thead><tbody>")
    for row in table.rows:
        fragments.append("<tr>")
        for cell in row:
            fragments.append(f"<td>{escape(cell)}</td>")
        fragments.append("</tr>")
    fragments.append("</tbody></table></div>")
    if not table.rows:
        fragments.append("<p>None recorded.</p>")
    return "\n".join(fragments)


def render_html_section(section: ReportSection, level: int) -> str:
    level = min(level, 6)
    fragments = [f"<section><h{level}>{escape(section.title)}</h{level}>"]
    for paragraph in section.paragraphs:
        attributes = ' class="warning"' if paragraph.warning else ""
        fragments.append(f"<p{attributes}>{escape(paragraph.text)}</p>")
    if section.bullets:
        fragments.append("<ul>")
        for bullet in section.bullets:
            fragments.append(f"<li>{escape(bullet)}</li>")
        fragments.append("</ul>")
    if section.verbatim is not None:
        fragments.append(f"<pre><code>{escape(section.verbatim)}</code></pre>")
    for table in section.tables:
        fragments.append(render_html_table(table))
    for subsection in section.sections:
        fragments.append(render_html_section(subsection, level + 1))
    fragments.append("</section>")
    return "\n".join(fragments)


def render_html_report(report: SessionReport) -> str:
    template = Template(
        files("vulnwitness.interfaces").joinpath("report_template.html").read_text()
    )
    fragments: list[str] = []
    for section in report.sections:
        fragments.append(render_html_section(section, 2))
    banner = '<p class="banner">Synthetic demonstration data</p>' if report.synthetic else ""
    return template.substitute(title=escape(report.title), banner=banner, body="\n".join(fragments))
