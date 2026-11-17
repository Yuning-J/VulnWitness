"""Reports and investigation summaries prefer modern CVSS metrics over CVSS 2.0."""

from collections.abc import Callable
from pathlib import Path

import pytest

from tests.support.builders import build_cve_record, build_cvss_metric
from tests.support.priority import build_priority_session
from vulnwitness.adapters.session.check import SessionChecker
from vulnwitness.application.investigation_presentation import format_severity
from vulnwitness.application.session_report import build_session_report
from vulnwitness.domain.session_report import SessionReport
from vulnwitness.interfaces.report_html import render_html_report
from vulnwitness.interfaces.report_markdown import render_markdown_report


@pytest.mark.parametrize("version", ["3.0", "3.1", "4.0"])
@pytest.mark.parametrize("scorer_type", ["primary", "secondary"])
@pytest.mark.parametrize("render", [render_html_report, render_markdown_report], ids=["html", "md"])
def test_modern_medium_metric_is_displayed_above_primary_v2_high_metric(
    tmp_path: Path,
    version: str,
    scorer_type: str,
    render: Callable[[SessionReport], str],
) -> None:
    metrics = (
        build_cvss_metric(version="2.0", base_severity="HIGH", base_score=10.0),
        build_cvss_metric(
            version=version,
            scorer="cna@democorp.example",
            scorer_type=scorer_type,
        ),
    )
    directory = build_priority_session(
        tmp_path / "workspace", record_overrides={"cvss": metrics, "cnvd": ()}
    )
    record = build_cve_record(cvss=metrics)

    document = render(build_session_report(SessionChecker(directory).check_with_contents()))
    summary = format_severity(record)

    assert summary == f"MEDIUM 5.3 v{version}"
    preferred_label = f"Medium 5.3 · CVSS {version} · cna@democorp.example · {scorer_type}"
    assert document.index(preferred_label) < document.index("Other severity metrics")
