"""Self-contained HTML rendering; every recorded value is escaped as text."""

from html import escape
from importlib.resources import files
from string import Template

from vulnwitness.domain.session_report import ReportSection, ReportTable, SessionReport


def render_html_table(table: ReportTable) -> str:
    fragments = ['<div class="table-wrap"><table><thead><tr>']
    for heading in table.headings:
        fragments.append(f'<th scope="col">{escape(heading)}</th>')
    fragments.append("</tr></thead><tbody>")
    links: dict[str, str] = {}
    for link in table.links:
        links[link.text] = link.target
    for row in table.rows:
        fragments.append("<tr>")
        for cell in row:
            text = escape(cell)
            if cell in links:
                text = (
                    f'<a href="{escape(links[cell], quote=True)}" '
                    f'rel="noreferrer noopener">{text}</a>'
                )
            mark = (
                ' class="ok-mark"'
                if cell == "✓"
                else ' class="bad-mark"'
                if cell.startswith("✗")
                else ""
            )
            fragments.append(f"<td{mark}>{text}</td>")
        fragments.append("</tr>")
    fragments.append("</tbody></table></div>")
    if not table.rows:
        fragments.append("<p>None recorded.</p>")
    return "\n".join(fragments)


def render_html_section(section: ReportSection, level: int) -> str:
    level = min(level, 6)
    tag = "details" if section.folded else "article" if section.layout == "card" else "section"
    attributes = (
        f' class="{section.layout or "appendix"}"' if section.layout or section.folded else ""
    )
    if section.anchor:
        attributes += f' id="{escape(section.anchor, quote=True)}"'
    heading = (
        f"<summary>{escape(section.title)}</summary>"
        if section.folded
        else f"<h{level}>{escape(section.title)}</h{level}>"
    )
    if section.layout == "facts":
        heading = ""
    elif section.layout == "paths":
        heading = (
            f'<div class="path-head"><h{level} class="chip strong">{escape(section.title)}'
            f'</h{level}><span class="muted">{escape(section.heading_note)}</span>'
        )
    fragments = [f"<{tag}{attributes}>{heading}"]
    if section.stats:
        for paragraph in section.paragraphs:
            fragments.append(f'<p class="meta">{escape(paragraph.text)}</p>')
        fragments.append('<div class="stats">')
    for stat in section.stats:
        fragments.append(
            f'<div class="stat"><div class="stat-value">{escape(stat.value)}</div><div '
            f'class="stat-label">{escape(stat.label)}</div>'
            f'<div class="stat-note">{escape(stat.note)}</div></div>'
        )
    if section.stats:
        fragments.append("</div>")
    if section.layout == "card":
        fragments[0] = f'<{tag}{attributes}><header class="card-head">{heading}'
    for badge in section.badges:
        badge_class = f"{'tag' if section.layout == 'paths' else 'pill'} {badge.tone}"
        if badge.severity is not None:
            badge_class = f"sev sev-{badge.severity.lower()}"
        fragments.append(f'<span class="{badge_class}">{escape(badge.text)}</span>')
    if section.layout == "card":
        fragments.append("</header>")
    if section.layout == "paths":
        fragments.append('</div><div class="chips">')
    if section.layout != "facts":
        for chip in section.chips:
            fragments.append(f'<span class="chip">{escape(chip)}</span>')
    for link in section.links:
        fragments.append(
            f'<a href="{escape(link.target, quote=True)}" '
            f'rel="noreferrer noopener">{escape(link.text)}</a>'
        )
    for paragraph in () if section.stats else section.paragraphs:
        attributes = ' class="warning"' if paragraph.warning else ""
        fragments.append(f"<p{attributes}>{escape(paragraph.text)}</p>")
    if section.bullets:
        fragments.append("<ul>")
        for bullet in section.bullets:
            fragments.append(f"<li>{escape(bullet)}</li>")
        fragments.append("</ul>")
    if section.verbatim is not None:
        fragments.append(f"<pre><code>{escape(section.verbatim)}</code></pre>")
    if section.facts:
        fragments.append('<dl class="facts-grid">')
        for fact in section.facts:
            fragments.append(f"<div><dt>{escape(fact.label)}</dt><dd>")
            if fact.badge is not None:
                fragments.append(
                    f'<span class="tag {fact.badge.tone}">{escape(fact.badge.text)}</span>'
                )
            fragments.append(escape(fact.value))
            if fact.detail:
                fragments.append(f'<small class="muted">{escape(fact.detail)}</small>')
            fragments.append("</dd></div>")
        fragments.append("<div><dt>Weaknesses</dt><dd>")
        for chip in section.chips:
            fragments.append(f'<span class="chip">{escape(chip)}</span>')
        if not section.chips:
            fragments.append("none recorded")
        fragments.append("</dd></div></dl>")
    for table in section.tables:
        fragments.append(render_html_table(table))
    if section.layout == "columns":
        fragments.append('<div class="two">')
    for subsection in section.sections:
        fragments.append(render_html_section(subsection, level + 1))
    if section.layout == "columns":
        fragments.append("</div>")
    if section.layout == "paths":
        fragments.append("</div>")
    fragments.append(f"</{tag}>")
    return "\n".join(fragments)


def render_html_report(report: SessionReport) -> str:
    template = Template(
        files("vulnwitness.interfaces").joinpath("report_template.html").read_text()
    )
    fragments: list[str] = []
    for section in report.sections:
        fragments.append(render_html_section(section, 2))
    if report.input_digest is not None:
        fragments.append("<p>Report input digest: " + escape(report.input_digest) + "</p>")
    banner = '<p class="banner">Synthetic demonstration data</p>' if report.synthetic else ""
    return template.substitute(title=escape(report.title), banner=banner, body="\n".join(fragments))
