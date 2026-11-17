"""ADR 0025: operator-supplied EPSS files become the exploit_probability fact."""

import gzip
import json
import os
from pathlib import Path

import pytest

from tests.support.priority import (
    build_priority_session,
    priority_arguments,
    write_priority_register,
)
from vulnwitness.adapters.epss_files import EpssFileError, read_epss_directory
from vulnwitness.adapters.session.check import SessionChecker
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
    score_dates = []
    for snapshot in artifact.epss_snapshots:
        score_dates.append(snapshot.score_date.isoformat())
    assert score_dates == ["2026-10-09", "2026-11-08"]
    assert artifact.decisions[0].matched_rule.id == "rule-7b"
    assert not artifact.used_after_reference_date_information
    rendered = render_markdown_section(build_priority_report(artifact), 2)
    assert "LEV over the supplied files" in rendered
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


def test_corrupt_gzip_returns_a_named_cli_error_without_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    epss_dir = tmp_path / "epss"
    path = write_epss(epss_dir, "2026-11-08", 0.4)
    compressed = bytearray(path.read_bytes())
    for index in range(12, len(compressed) - 8):
        compressed[index] ^= 0xFF
    path.write_bytes(compressed)

    status, output = prioritise(tmp_path, "exploitation-demo", epss_dir)

    assert status == 1
    assert not output.exists()
    error = capsys.readouterr().err
    assert path.name in error and "readable" in error
    assert "Traceback" not in error


def test_high_epss_without_recorded_kev_or_exploitation_requires_manual_triage(
    tmp_path: Path,
) -> None:
    epss_dir = tmp_path / "epss"
    write_epss(epss_dir, "2026-11-08", 0.4)
    directory = build_priority_session(tmp_path / "sessions", cve_ids=())
    assets = write_priority_register(tmp_path / "assets.yaml")
    arguments = priority_arguments(directory, assets)
    arguments[arguments.index("cn-auto-demo")] = "exploitation-demo"

    status = main([*arguments, "--epss-dir", str(epss_dir)], environment={})

    assert status == 0
    artifact = PriorityArtifact.model_validate_json((directory / "priority.json").read_bytes())
    decision = artifact.decisions[0]
    assert decision.facts.exploit_probability.value == "at_or_above_threshold"
    assert decision.facts.kev.value == decision.facts.exploitation.value == "unknown"
    assert decision.matched_rule.id == "rule-8"
    assert decision.recommendation == "manual_triage_required"


@pytest.mark.parametrize("entry_kind", ["directory", "symlink", "fifo"])
def test_non_regular_csv_entries_are_skipped(tmp_path: Path, entry_kind: str) -> None:
    epss_dir = tmp_path / "epss"
    regular = write_epss(epss_dir, "2026-11-08", 0.4)
    ignored = epss_dir / "old.csv"
    if entry_kind == "directory":
        ignored.mkdir()
    elif entry_kind == "symlink":
        ignored.symlink_to(regular)
    else:
        os.mkfifo(ignored)

    status, output = prioritise(tmp_path, "exploitation-demo", epss_dir)

    assert status == 0
    artifact = PriorityArtifact.model_validate_json(output.read_bytes())
    assert len(artifact.epss_snapshots) == 1
    assert artifact.epss_snapshots[0].file_name == regular.name


def test_future_duplicate_dates_and_unreadable_rows_are_ignored_after_the_header(
    tmp_path: Path,
) -> None:
    epss_dir = tmp_path / "epss"
    write_epss(epss_dir, "2026-11-08", 0.4)
    future = write_epss(epss_dir, "2026-11-09", 0.8, compress=False)
    future.write_bytes(b"#model_version:v1,score_date:2026-11-09\n\xffinvalid rows")
    compressed = write_epss(epss_dir, "2026-11-09", 0.9)
    compressed.write_bytes(compressed.read_bytes()[:-8] + b"badtrail")

    status, output = prioritise(tmp_path, "exploitation-demo", epss_dir)

    assert status == 0
    artifact = PriorityArtifact.model_validate_json(output.read_bytes())
    assert len(artifact.epss_snapshots) == 1
    assert artifact.epss_snapshots[0].score_date.isoformat() == "2026-11-08"
    assert artifact.decisions[0].facts.exploit_probability.epss == 0.4


@pytest.mark.parametrize("inconsistency", ["no-snapshots", "policy-threshold"])
def test_session_check_rejects_probability_inconsistent_with_snapshots_or_policy(
    tmp_path: Path, inconsistency: str
) -> None:
    epss_dir = tmp_path / "epss"
    write_epss(epss_dir, "2026-11-08", 0.4)
    status, output = prioritise(tmp_path, "exploitation-demo", epss_dir)
    assert status == 0
    assert SessionChecker(output.parent).check().record.consistent
    artifact = json.loads(output.read_bytes())
    if inconsistency == "no-snapshots":
        artifact["epss_snapshots"] = []
    else:
        artifact["decisions"][0]["facts"]["exploit_probability"]["threshold"] = 0.2
    output.write_text(json.dumps(artifact))

    contents = SessionChecker(output.parent).check_with_contents()

    assert contents.priority is None
    assert not contents.check.record.consistent
    assert any(
        violation.location == "priority.json" for violation in contents.check.record.violations
    )
