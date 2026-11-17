"""ADR 0025: operator-supplied EPSS files become the exploit_probability fact."""

import gzip
from pathlib import Path

import pytest

from tests.support.priority import (
    build_priority_session,
    priority_arguments,
    write_priority_register,
)
from vulnwitness.adapters.epss_files import EpssFileError, read_epss_directory
from vulnwitness.application.priority_report import build_priority_report
from vulnwitness.cli import main
from vulnwitness.domain.priority_decision import PriorityArtifact
from vulnwitness.interfaces.report_markdown import render_markdown_section

CVE_ID = "CVE-9999-0001"


def write_epss(directory: Path, score_date: str, epss: float, compress: bool = True) -> Path:
    directory.mkdir(exist_ok=True)
    text = (
        f"#model_version:v2025.03.14,score_date:{score_date}T00:00:00+0000\n"
        "cve,epss,percentile\n"
        f"CVE-9999-0002,0.9,0.99\n{CVE_ID},{epss},0.75\n"
    )
    if compress:
        path = directory / f"epss_scores-{score_date}.csv.gz"
        path.write_bytes(gzip.compress(text.encode("ascii")))
    else:
        path = directory / f"epss_scores-{score_date}.csv"
        path.write_text(text)
    return path


def prioritise(tmp_path: Path, policy: str, epss_dir: Path) -> tuple[int, Path]:
    directory = build_priority_session(tmp_path / "sessions")
    assets = write_priority_register(tmp_path / "assets.yaml")
    arguments = priority_arguments(directory, assets)
    arguments[arguments.index("cn-auto-demo")] = policy
    arguments += ["--epss-dir", str(epss_dir)]
    return main(arguments, environment={}), directory / "priority.json"


def test_a_high_score_attends_and_the_files_are_recorded(tmp_path: Path) -> None:
    epss_dir = tmp_path / "epss"
    write_epss(epss_dir, "2026-10-09", 0.02, compress=False)
    write_epss(epss_dir, "2026-11-08", 0.4)
    write_epss(epss_dir, "2026-11-09", 0.99)

    status, output = prioritise(tmp_path, "exploitation-demo", epss_dir)

    assert status == 0
    artifact = PriorityArtifact.model_validate_json(output.read_bytes())
    fact = artifact.decisions[0].facts.exploit_probability
    assert fact.value == "at_or_above_threshold"
    assert (fact.epss, fact.percentile, fact.threshold) == (0.4, 0.75, 0.1)
    assert fact.lev is not None and fact.lev.covered_days == 31
    assert [s.score_date.isoformat() for s in artifact.epss_snapshots] == [
        "2026-10-09",
        "2026-11-08",
    ]
    assert artifact.decisions[0].matched_rule.id == "rule-7b"
    assert not artifact.used_after_reference_date_information
    rendered = render_markdown_section(build_priority_report(artifact), 2)
    assert "LEV lower bound" in rendered
    assert "not exploited" in rendered


def test_a_low_score_is_below_threshold_not_absent(tmp_path: Path) -> None:
    epss_dir = tmp_path / "epss"
    write_epss(epss_dir, "2026-11-08", 0.001)

    status, output = prioritise(tmp_path, "exploitation-demo", epss_dir)

    assert status == 0
    decision = PriorityArtifact.model_validate_json(output.read_bytes()).decisions[0]
    assert decision.facts.exploit_probability.value == "below_threshold"
    assert "exploit_probability" not in decision.unknown_facts


def test_a_policy_without_a_threshold_refuses_epss(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    epss_dir = tmp_path / "epss"
    write_epss(epss_dir, "2026-11-08", 0.4)

    status, output = prioritise(tmp_path, "cn-auto-demo", epss_dir)

    assert status == 1
    assert "exploit_probability_threshold" in capsys.readouterr().err
    assert not output.exists()


def test_malformed_or_duplicate_files_are_refused(tmp_path: Path) -> None:
    epss_dir = tmp_path / "epss"
    write_epss(epss_dir, "2026-11-08", 0.4)
    write_epss(epss_dir, "2026-11-08", 0.4, compress=False)
    with pytest.raises(EpssFileError, match="two EPSS files"):
        read_epss_directory(epss_dir, {CVE_ID})

    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "epss.csv").write_text("cve,epss,percentile\nCVE-9999-0001,0.1,0.2\n")
    with pytest.raises(EpssFileError, match="header"):
        read_epss_directory(bad, {CVE_ID})

    row = tmp_path / "row"
    write_epss(row, "2026-11-08", 0.4, compress=False)
    path = row / "epss_scores-2026-11-08.csv"
    path.write_text(path.read_text().replace("0.4,", "high,"))
    with pytest.raises(EpssFileError, match="line 4"):
        read_epss_directory(row, {CVE_ID})
