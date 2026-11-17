"""Report cards show mirrored KEV detail, SSVC, tags and source-stated versions with their
authors, and only when a record carries them."""

from datetime import date

from tests.support.builders import build_cve_record
from vulnwitness.application.session_report import build_mirrored_section
from vulnwitness.domain.cve import (
    CveRecord,
    CveTag,
    KevEntry,
    SourceAffected,
    SourceAffectedProduct,
    SourceAffectedVersion,
    SourceVersionChange,
    SsvcAssessment,
    SsvcDecisionPoints,
)
from vulnwitness.interfaces.lookup_summary import render_mirrored_lines
from vulnwitness.interfaces.report_html import render_html_section
from vulnwitness.interfaces.report_markdown import render_markdown_section


def build_format4_record() -> CveRecord:
    return build_cve_record(
        kev=KevEntry(
            date_added=date(2026, 10, 1),
            required_action="Apply mitigations.",
            forensic_triage="yes",
        ),
        ssvc=(
            SsvcAssessment(
                source="134c704f-9b21-4f2e-91b3-4a467353bcc0",
                role="CISA Coordinator",
                version="2.0.3",
                decision_points=SsvcDecisionPoints(
                    exploitation="poc", automatable="yes", technical_impact="total"
                ),
            ),
        ),
        cve_tags=(CveTag(source="cna@democorp.example", tags=("disputed",)),),
        source_affected=(
            SourceAffected(
                source="cna@democorp.example",
                products=(
                    SourceAffectedProduct(
                        vendor="Democorp",
                        product="Gateway",
                        default_status="unaffected",
                        versions=(
                            SourceAffectedVersion(
                                version="2.0",
                                status="affected",
                                less_than="2.7.3",
                                version_type="semver",
                                changes=(SourceVersionChange(at="2.7.1", status="unaffected"),),
                                omitted_changes=2,
                            ),
                        ),
                        omitted_versions=3,
                    ),
                ),
                omitted_products=2,
            ),
        ),
    )


def test_record_without_mirrored_data_adds_no_section() -> None:
    assert build_mirrored_section(build_cve_record()) is None


def test_mirrored_section_names_each_author_and_keeps_affectedness_unknown() -> None:
    section = build_mirrored_section(build_format4_record())

    assert section is not None
    markdown = render_markdown_section(section, 3)
    html = render_html_section(section, 3)
    for rendered in (markdown, html):
        assert "forensic triage: yes" in rendered
        assert "exploitation poc" in rendered
        assert "CISA Coordinator" in rendered
        assert "disputed" in rendered
        assert "affected 2.0 to &lt; 2.7.3 (semver)" in rendered or (
            "affected 2.0 to < 2.7.3 (semver)" in rendered
        )
        assert "3 more not stored" in rendered
        assert "2 more products not stored" in rendered
        assert "affectedness stays unknown" in rendered


def test_report_and_lookup_show_status_changes_and_omitted_changes() -> None:
    record = build_format4_record()

    section = build_mirrored_section(record)
    assert section is not None
    markdown = render_markdown_section(section, 3)
    html = render_html_section(section, 3)
    lookup = "\n".join(render_mirrored_lines(record, 1000))

    for rendered in (markdown, html, lookup):
        assert "at 2.7.1 → unaffected" in rendered
        assert "2 more status changes not stored" in rendered
        assert "cna@democorp.example" in rendered
        assert "exploitation poc · automatable yes · technical impact total" in rendered
