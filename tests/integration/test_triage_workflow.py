"""Product triage outcomes over the packaged synthetic fixture, without code patches."""

import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from tests.support.clocks import SteppingClock
from tests.support.session_files import assert_check_layers_hold
from tests.support.triage import (
    FailingLookup,
    build_triage_workflow,
    read_triage_tree,
)
from tests.support.triage_artifacts import InvalidFindingsArtifacts
from vulnwitness.adapters.session.check import SessionChecker
from vulnwitness.application.search import SearchService
from vulnwitness.cli import main
from vulnwitness.domain.product_query import ProductQueryRequest
from vulnwitness.domain.session_record import SessionCall, SessionFindings
from vulnwitness.domain.triage import TriageLimits, TriageSummary
from vulnwitness.interfaces.cli_triage import render_triage_summary
from vulnwitness.schema_snapshots import render_schema


def read_findings(directory: Path) -> SessionFindings:
    return SessionFindings.model_validate(
        yaml.safe_load((directory / "findings.yaml").read_bytes())
    )


def test_complete_run_records_verified_claims_for_every_inventoried_cve(tmp_path: Path) -> None:
    # Arrange
    directory = tmp_path / "review"
    workflow = build_triage_workflow(directory)

    # Act
    summary, check, exit_code = workflow.run(ProductQueryRequest(vendor="democorp", limit=1))

    # Assert
    assert exit_code == 0 and summary.stop_reason == "complete"
    assert summary.inventory.pages_read == 3
    assert summary.inventory.items_seen == summary.inventory.total_available == 3
    assert summary.inventory.complete
    assert summary.deep_dive.lookups_completed == 3
    assert summary.remaining_steps == ()
    assert_check_layers_hold(check)
    assert len(check.claims.checks) > 3
    findings = read_findings(directory)
    matched_ids: set[str] = set()
    for finding in findings.findings:
        assert finding.author == "workflow" and finding.status == "unconfirmed"
        assert finding.kind not in {"analyst_note", "model_judgement"}
        assert finding.claim is not None
        if finding.claim.kind == "product_field_match":
            matched_ids.add(finding.claim.cve_id)
    assert matched_ids == set(summary.inventory.cve_ids)
    for sequence, command in enumerate(
        ("capabilities", "product", "product", "product", "lookup", "lookup", "lookup"), start=1
    ):
        call = SessionCall.model_validate_json(
            (directory / f"calls/{sequence:04d}.json").read_bytes()
        )
        assert call.command == command and call.outcome == "ok"
    document = json.loads((directory / "triage.json").read_bytes())
    assert document == summary.model_dump(mode="json")
    Draft202012Validator(json.loads(render_schema(TriageSummary, "serialization"))).validate(
        document
    )
    for path in directory.rglob("*"):
        assert path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)


@pytest.mark.parametrize(
    "version,expected_ids",
    [
        (None, ("CVE-9999-0007", "CVE-9999-0002")),
        ("2.0", ("CVE-9999-0001", "CVE-9999-0007")),
    ],
)
def test_selection_uses_the_stated_order_across_all_pages(
    tmp_path: Path, version: str | None, expected_ids: tuple[str, ...]
) -> None:
    # Arrange
    workflow = build_triage_workflow(tmp_path / "review", limits=TriageLimits(lookups=2))

    # Act
    summary, check, exit_code = workflow.run(
        ProductQueryRequest(vendor="democorp", version=version, limit=1)
    )

    # Assert
    assert exit_code == 0
    assert summary.deep_dive.selected_ids == summary.deep_dive.looked_up_ids == expected_ids
    assert summary.deep_dive.selection_mode == "first N by the stated order"
    assert "lookups" in summary.caps_hit
    assert_check_layers_hold(check)


def test_user_chosen_ids_override_order_and_keep_requested_order(tmp_path: Path) -> None:
    # Arrange
    workflow = build_triage_workflow(tmp_path / "review")
    selected = ("CVE-9999-0001", "CVE-9999-0007")

    # Act
    summary, check, exit_code = workflow.run(ProductQueryRequest(vendor="democorp"), selected)

    # Assert
    assert exit_code == 0
    assert summary.deep_dive.selection_mode == "user-chosen IDs"
    assert summary.deep_dive.selected_ids == summary.deep_dive.looked_up_ids == selected
    assert_check_layers_hold(check)


def test_versioned_run_records_verified_version_notes_for_every_inventory_item(
    tmp_path: Path,
) -> None:
    # Arrange
    directory = tmp_path / "review"
    workflow = build_triage_workflow(directory)

    # Act
    summary, check, exit_code = workflow.run(ProductQueryRequest(vendor="democorp", version="2.0"))

    # Assert
    assert exit_code == 0
    version_ids: set[str] = set()
    for finding in read_findings(directory).findings:
        if finding.claim is not None and finding.claim.kind == "version_note":
            assert finding.claim.version == "2.0"
            assert finding.claim.applicability == "unknown"
            version_ids.add(finding.claim.cve_id)
    assert version_ids == set(summary.inventory.cve_ids)
    assert_check_layers_hold(check)


def test_page_cap_reports_unfinished_inventory_and_completed_deep_dive(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    directory = tmp_path / "review"
    arguments = ["triage", "--vendor", "democorp", "--limit", "1", "--max-pages", "1"]

    # Act
    exit_code = main([*arguments, "--session", str(directory)], environment={})

    # Assert
    text = capsys.readouterr().out
    summary = TriageSummary.model_validate_json((directory / "triage.json").read_bytes())
    assert exit_code == 2 and summary.stop_reason == "max_pages"
    assert summary.inventory.pages_read == summary.inventory.items_seen == 1
    assert summary.inventory.total_available == 3 and not summary.inventory.complete
    assert summary.deep_dive.lookups_completed == 1
    assert summary.remaining_steps == ("product: continue inventory traversal",)
    assert "traversal unfinished" in text and "Deep dive: 1 looked up:" in text
    assert "first N by the stated order" in text
    assert "max_pages" in text and "Remaining planned steps:" in text
    assert_check_layers_hold(SessionChecker(directory).check())


def test_call_limit_preflight_refuses_without_creating_any_session_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    directory = tmp_path / "review"

    # Act
    exit_code = main(
        [
            "triage",
            "--vendor",
            "democorp",
            "--session",
            str(directory),
            "--session-call-limit",
            "25",
        ],
        environment={},
    )

    # Assert
    assert exit_code == 2 and not directory.exists()
    streams = capsys.readouterr()
    assert streams.out == ""
    assert "planned call count 26 exceeds remaining session call limit 25" in streams.err


def test_nonempty_session_is_refused_without_modifying_existing_bytes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    directory = tmp_path / "review"
    directory.mkdir()
    (directory / "keep.txt").write_text("keep this file")

    # Act
    exit_code = main(
        ["triage", "--vendor", "democorp", "--session", str(directory)], environment={}
    )

    # Assert
    assert exit_code == 2
    assert "empty or new session directory" in capsys.readouterr().err
    assert read_triage_tree(directory) == {"keep.txt": b"keep this file"}


def test_midrun_failure_keeps_completed_calls_and_findings_and_lists_pending_lookups(
    tmp_path: Path, search_service: SearchService
) -> None:
    # Arrange
    directory = tmp_path / "review"
    failing_service = FailingLookup(search_service.lookup)
    workflow = build_triage_workflow(directory, lookup=failing_service.lookup)

    # Act
    summary, check, exit_code = workflow.run(ProductQueryRequest(vendor="democorp"))

    # Assert
    assert exit_code == 2 and summary.stop_reason == "call_failed"
    assert summary.inventory.complete and summary.deep_dive.lookups_completed == 1
    assert summary.deep_dive.looked_up_ids == ("CVE-9999-0007",)
    assert summary.remaining_steps == ("lookup: CVE-9999-0002", "lookup: CVE-9999-0001")
    assert len(failing_service.calls) == 2
    failed_call = SessionCall.model_validate_json((directory / "calls/0004.json").read_bytes())
    assert failed_call.outcome == summary.failure_code == "internal_error"
    assert failed_call.request == {"cve_id": "CVE-9999-0002"}
    assert check.record.calls_checked == 4
    assert any(
        finding.kind == "catalogue_association" for finding in read_findings(directory).findings
    )
    assert_check_layers_hold(check)


def test_time_limit_stops_after_recorded_capabilities_and_lists_unstarted_steps(
    tmp_path: Path,
) -> None:
    # Arrange
    directory = tmp_path / "review"
    workflow = build_triage_workflow(
        directory, limits=TriageLimits(time_limit=1), clock=SteppingClock(seconds_per_read=1)
    )

    # Act
    summary, check, exit_code = workflow.run(ProductQueryRequest(vendor="democorp"))

    # Assert
    assert exit_code == 2 and summary.stop_reason == "time_limit"
    assert summary.caps_hit == ("time_limit",)
    assert summary.inventory.pages_read == summary.deep_dive.lookups_completed == 0
    assert summary.inventory.total_available is None and not summary.inventory.complete
    assert summary.remaining_steps == (
        "product: continue inventory traversal",
        "select: validate user IDs or take first N by the stated order",
        "lookup: up to 5 selected CVEs",
    )
    assert check.record.calls_checked == 1
    assert "Time limit reached" in render_triage_summary(summary, check)
    assert_check_layers_hold(check)


def test_fixed_clocks_produce_identical_session_bytes_except_the_directory_name(
    tmp_path: Path,
) -> None:
    # Arrange
    first_directory = tmp_path / "first"
    second_directory = tmp_path / "second"
    first_workflow = build_triage_workflow(first_directory)
    second_workflow = build_triage_workflow(second_directory)
    request = ProductQueryRequest(vendor="democorp", version="2.0", limit=1)

    # Act
    first_summary, first_check, first_exit = first_workflow.run(request)
    second_summary, second_check, second_exit = second_workflow.run(request)

    # Assert
    assert first_exit == second_exit == 0
    assert first_summary == second_summary and first_check == second_check
    first_files = read_triage_tree(first_directory)
    second_files = read_triage_tree(second_directory)
    first_metadata = json.loads(first_files.pop("session.json"))
    second_metadata = json.loads(second_files.pop("session.json"))
    assert first_metadata.pop("name") == "first"
    assert second_metadata.pop("name") == "second"
    assert first_metadata == second_metadata
    assert first_files == second_files


def test_json_stdout_matches_saved_triage_artifact(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    directory = tmp_path / "review"

    # Act
    exit_code = main(
        ["triage", "--product", "demo_gateway", "--session", str(directory), "--format", "json"],
        environment={},
    )

    # Assert
    assert exit_code == 0
    assert capsys.readouterr().out.encode() == (directory / "triage.json").read_bytes()


def test_no_product_match_has_empty_verified_findings_and_exits_one(tmp_path: Path) -> None:
    # Arrange
    workflow = build_triage_workflow(tmp_path / "review")

    # Act
    summary, check, exit_code = workflow.run(
        ProductQueryRequest(product="nonexistent fixture product")
    )

    # Assert
    assert exit_code == 1 and summary.stop_reason == "no_match"
    assert summary.inventory.complete and summary.inventory.total_available == 0
    assert summary.deep_dive.looked_up_ids == ()
    assert_check_layers_hold(check)


def test_override_outside_inventory_is_refused_without_lookup_calls(tmp_path: Path) -> None:
    # Arrange
    workflow = build_triage_workflow(tmp_path / "review")

    # Act
    summary, check, exit_code = workflow.run(
        ProductQueryRequest(vendor="democorp"), ("CVE-9999-9999",)
    )

    # Assert
    assert exit_code == 2 and summary.stop_reason == "invalid_selection"
    assert summary.deep_dive.lookups_completed == 0
    assert check.record.calls_checked == 2
    assert_check_layers_hold(check)


def test_time_limit_between_lookups_keeps_finished_deep_dive_and_remaining_ids(
    tmp_path: Path,
) -> None:
    # Arrange
    workflow = build_triage_workflow(
        tmp_path / "review",
        limits=TriageLimits(time_limit=3),
        clock=SteppingClock(seconds_per_read=1),
    )

    # Act
    summary, check, exit_code = workflow.run(ProductQueryRequest(vendor="democorp"))

    # Assert
    assert exit_code == 2 and summary.stop_reason == "time_limit"
    assert summary.inventory.complete
    assert summary.deep_dive.looked_up_ids == ("CVE-9999-0007",)
    assert summary.remaining_steps == ("lookup: CVE-9999-0002", "lookup: CVE-9999-0001")
    assert_check_layers_hold(check)


def test_cli_repeatable_selection_overrides_order_and_reserves_only_requested_calls(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    directory = tmp_path / "review"

    # Act
    exit_code = main(
        [
            "triage",
            "--vendor",
            "democorp",
            "--session",
            str(directory),
            "--max-pages",
            "1",
            "--session-call-limit",
            "4",
            "--select",
            "CVE-9999-0001",
            "--select",
            "CVE-9999-0002",
            "--format",
            "json",
        ],
        environment={},
    )

    # Assert
    summary = TriageSummary.model_validate_json(capsys.readouterr().out)
    assert exit_code == 0 and summary.planned_call_count == 4
    assert summary.deep_dive.looked_up_ids == ("CVE-9999-0001", "CVE-9999-0002")
    assert summary.deep_dive.selection_mode == "user-chosen IDs"


@pytest.mark.parametrize(
    "options",
    [
        ["--max-pages", "0"],
        ["--lookups", "11"],
        ["--lookups", "-1"],
        ["--time-limit", "0"],
        ["--time-limit", "nan"],
        ["--limit", "21"],
        ["--select", "CVE-9999-0001", "--select", "CVE-9999-0001"],
        ["--lookups", "0", "--select", "CVE-9999-0001"],
    ],
)
def test_invalid_caps_or_selection_are_refused_before_recording(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], options: list[str]
) -> None:
    # Arrange
    directory = tmp_path / "review"

    # Act
    exit_code = main(
        ["triage", "--vendor", "democorp", "--session", str(directory), *options], environment={}
    )

    # Assert
    assert exit_code == 2 and not directory.exists()
    assert capsys.readouterr().out == ""


def test_description_inventory_records_verified_mentions_without_product_claims(
    tmp_path: Path,
) -> None:
    # Arrange
    directory = tmp_path / "review"
    workflow = build_triage_workflow(directory, limits=TriageLimits(lookups=0))

    # Act
    summary, check, exit_code = workflow.run(ProductQueryRequest(product="unnamed component"))

    # Assert
    assert exit_code == 0 and summary.inventory.items_seen == 1
    findings = read_findings(directory)
    assert any(finding.kind == "description_mention" for finding in findings.findings)
    assert not any(finding.kind == "product_field_match" for finding in findings.findings)
    assert_check_layers_hold(check)


def test_lookup_without_a_claimable_source_field_stops_without_inventing_a_finding(
    tmp_path: Path,
) -> None:
    # Arrange
    directory = tmp_path / "review"
    workflow = build_triage_workflow(directory)

    # Act
    summary, check, exit_code = workflow.run(ProductQueryRequest(product="unnamed component"))

    # Assert
    assert exit_code == 2 and summary.stop_reason == "lookup_claim_unavailable"
    assert summary.deep_dive.lookups_completed == 1
    assert summary.remaining_steps[0] == "findings: lookup call 3 returned no claimable fields"
    assert len(read_findings(directory).findings) == 1
    assert_check_layers_hold(check)


def test_failed_session_check_prevents_a_successful_workflow_exit(tmp_path: Path) -> None:
    # Arrange
    directory = tmp_path / "review"
    workflow = build_triage_workflow(directory, artifacts=InvalidFindingsArtifacts(directory))

    # Act
    summary, check, exit_code = workflow.run(ProductQueryRequest(vendor="democorp"))

    # Assert
    assert exit_code == 2 and summary.stop_reason == "check_failed"
    assert not check.record.consistent
    assert "Session check: failed" in render_triage_summary(summary, check)
    assert summary.remaining_steps == ("session check: resolve reported violations",)
