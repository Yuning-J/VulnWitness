"""Priority decisions use frozen recorded facts, with no deployment reads or new calls."""

import json
import stat
from importlib.metadata import version
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.support.builders import build_cvss_metric
from tests.support.priority import (
    build_priority_session,
    priority_arguments,
    write_priority_register,
)
from tests.support.report_sessions import read_recorded_files
from tests.support.triage import build_triage_workflow
from vulnwitness.cli import main
from vulnwitness.domain.cve import KevEntry
from vulnwitness.domain.hashing import sha256_hex
from vulnwitness.domain.priority_decision import PriorityArtifact
from vulnwitness.domain.product_query import ProductQueryRequest


@pytest.mark.parametrize(
    "overrides,record_capabilities,category,expected_rule,expected_grade,expected_kev",
    [
        (
            {"cvss": (), "cnvd": ()},
            True,
            "external_connection",
            "rule-8",
            "none_available",
            "not_listed_in_snapshot",
        ),
        ({}, False, "external_connection", "rule-7", "absent", "unknown"),
        (
            {"kev": KevEntry(date_added="2026-01-01")},
            False,
            "unknown",
            "rule-4",
            "absent",
            "listed",
        ),
        (
            {
                "cvss": (
                    build_cvss_metric(
                        base_severity="CRITICAL", base_score=9.8, scorer="cna@example.org"
                    ),
                ),
                "cnvd": (),
            },
            True,
            "external_connection",
            "rule-8",
            "none_available",
            "not_listed_in_snapshot",
        ),
    ],
    ids=["both-grades-missing", "no-capabilities", "listed-unknown-category", "cna-only"],
)
def test_recorded_facts_select_the_policy_rule(
    tmp_path: Path,
    overrides: dict[str, Any],
    record_capabilities: bool,
    category: str,
    expected_rule: str,
    expected_grade: str,
    expected_kev: str,
) -> None:
    directory = build_priority_session(
        tmp_path / "sessions", record_capabilities=record_capabilities, record_overrides=overrides
    )
    assets = write_priority_register(tmp_path / "assets.yaml", category=category)

    assert main(priority_arguments(directory, assets), environment={}) == 0
    artifact = PriorityArtifact.model_validate_json((directory / "priority.json").read_bytes())
    decision = artifact.decisions[0]

    assert decision.matched_rule.id == expected_rule
    assert decision.facts.high_grade.value == expected_grade
    assert decision.facts.kev.value == expected_kev
    assert decision.compliance[0].status == "basis_insufficient"


@pytest.mark.parametrize("cve_id", ["CVE-9999-0002", "CVE-9999-0008"])
def test_cnvd_high_grade_escalates_even_without_nvd_or_kev_basis(
    tmp_path: Path, cve_id: str
) -> None:
    directory = build_priority_session(tmp_path / "sessions", (cve_id,))
    assets = write_priority_register(tmp_path / "assets.yaml", (cve_id,))

    assert main(priority_arguments(directory, assets), environment={}) == 0
    artifact = PriorityArtifact.model_validate_json((directory / "priority.json").read_bytes())
    decision = artifact.decisions[0]

    assert decision.recommendation == "attend"
    assert "the CNVD high grade triggered this policy rule" in decision.reason
    assert decision.facts.high_grade.triggering_authorities == ("CNVD",)
    assert decision.facts.high_grade.evidence_ids
    if cve_id == "CVE-9999-0008":
        assert decision.facts.high_grade.cnvd_links_to_review == ()
        assert decision.facts.kev.value == "unknown"
        assert "kev" in decision.unknown_facts
        assert len(artifact.response_digests) == 1


@pytest.mark.parametrize("as_of,expected_flag", [("2026-10-12", True), ("2026-10-13", False)])
def test_used_evidence_dates_set_the_reference_date_flag(
    tmp_path: Path, as_of: str, expected_flag: bool
) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    assets = write_priority_register(tmp_path / "assets.yaml")

    assert main(priority_arguments(directory, assets, as_of), environment={}) == 0
    artifact = PriorityArtifact.model_validate_json((directory / "priority.json").read_bytes())

    assert artifact.used_after_reference_date_information is expected_flag
    assert str(artifact.decisions[0].facts.kev.snapshot_retrieved_at) == "2026-10-13"


def test_force_repeated_runs_are_byte_identical_and_leave_the_call_log_unchanged(
    tmp_path: Path,
) -> None:
    directory = build_priority_session(tmp_path / "sessions", ("CVE-9999-0002", "CVE-9999-0001"))
    assets = write_priority_register(tmp_path / "assets.yaml", ("CVE-9999-0002", "CVE-9999-0001"))
    recorded_files = read_recorded_files(directory)
    arguments = priority_arguments(directory, assets)

    assert main(arguments, environment={}) == 0
    first_bytes = (directory / "priority.json").read_bytes()
    assert main([*arguments, "--force"], environment={}) == 0
    second_bytes = (directory / "priority.json").read_bytes()
    artifact = PriorityArtifact.model_validate_json(second_bytes)

    assert first_bytes == second_bytes
    assert read_recorded_files(directory) == recorded_files
    assert stat.S_IMODE((directory / "priority.json").stat().st_mode) == 0o600
    assert artifact.program_version == version("vulnwitness")
    cve_ids = []
    for decision in artifact.decisions:
        cve_ids.append(decision.cve_id)
    assert cve_ids == ["CVE-9999-0001", "CVE-9999-0002"]
    for digest in artifact.response_digests:
        call = json.loads((directory / f"calls/{digest.call:04d}.json").read_bytes())
        assert digest.response_sha256 == call["response_sha256"]


def test_existing_priority_file_is_refused_and_preserved(tmp_path: Path) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    assets = write_priority_register(tmp_path / "assets.yaml")
    target = directory / "priority.json"
    target.write_bytes(b"existing")

    assert main(priority_arguments(directory, assets), environment={}) == 1
    assert target.read_bytes() == b"existing"


@pytest.mark.parametrize("sequence", [1, 2], ids=["capabilities", "lookup"])
def test_tampered_used_response_refuses_priority_publication(tmp_path: Path, sequence: int) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    assets = write_priority_register(tmp_path / "assets.yaml")
    response = directory / f"responses/{sequence:04d}.json"
    response.write_bytes(response.read_bytes() + b" ")

    assert main(priority_arguments(directory, assets), environment={}) == 1
    assert not (directory / "priority.json").exists()


def test_missing_exact_lookup_has_unknown_facts_and_an_explicit_note(tmp_path: Path) -> None:
    directory = build_priority_session(tmp_path / "sessions", ("CVE-9999-0001",))
    assets = write_priority_register(tmp_path / "assets.yaml", ("CVE-9999-0002",))

    assert main(priority_arguments(directory, assets), environment={}) == 0
    artifact = PriorityArtifact.model_validate_json((directory / "priority.json").read_bytes())
    decision = artifact.decisions[0]

    assert decision.facts.kev.value == "unknown"
    assert decision.facts.high_grade.value == "none_available"
    assert "no recorded exact lookup" in decision.notes[0]
    assert artifact.response_digests == ()


def test_cli_summary_succeeds_without_loading_invalid_deployment_settings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = build_priority_session(tmp_path / "sessions", ("CVE-9999-0002",))
    assets = write_priority_register(tmp_path / "assets.yaml", ("CVE-9999-0002",))

    assert (
        main(
            priority_arguments(directory, assets), environment={"VULNWITNESS_STORE_ROOT": "/absent"}
        )
        == 0
    )

    assert capsys.readouterr().out == (
        "gateway CVE-9999-0002: attend; compliance: "
        "gb-44495-vulnerability-clause=basis_insufficient; "
        "rule: rule-6\n"
    )


@pytest.mark.parametrize("invalid_input", ["policy", "date", "register", "duplicate-yaml"])
def test_invalid_explicit_inputs_are_usage_errors(tmp_path: Path, invalid_input: str) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    assets = write_priority_register(tmp_path / "assets.yaml")
    arguments = priority_arguments(directory, assets)
    if invalid_input == "policy":
        arguments[arguments.index("cn-auto-demo")] = "../unknown"
    elif invalid_input == "date":
        arguments[-1] = "2026-02-30"
    elif invalid_input == "register":
        register = yaml.safe_load(assets.read_text())
        register["assessments"][0]["asset"] = "undeclared"
        assets.write_text(yaml.safe_dump(register))
    else:
        assets.write_text(assets.read_text() + "format_version: 1\n")

    with pytest.raises(SystemExit) as refused:
        main(arguments, environment={})

    assert refused.value.code == 2
    assert not (directory / "priority.json").exists()


def test_no_imported_snapshot_never_implies_a_negative_kev_listing(tmp_path: Path) -> None:
    directory = build_priority_session(tmp_path / "sessions", kev_imported=False)
    assets = write_priority_register(tmp_path / "assets.yaml")

    assert main(priority_arguments(directory, assets), environment={}) == 0
    artifact = PriorityArtifact.model_validate_json((directory / "priority.json").read_bytes())

    assert artifact.decisions[0].facts.kev.value == "unknown"
    assert artifact.decisions[0].facts.kev.snapshot_retrieved_at is None


def test_force_refuses_a_symlink_priority_destination(tmp_path: Path) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    assets = write_priority_register(tmp_path / "assets.yaml")
    other_file = tmp_path / "other.json"
    other_file.write_bytes(b"keep")
    (directory / "priority.json").symlink_to(other_file)

    assert main([*priority_arguments(directory, assets), "--force"], environment={}) == 1
    assert other_file.read_bytes() == b"keep"


def test_unavailable_grades_still_disclose_the_used_records_later_retrieval_date(
    tmp_path: Path,
) -> None:
    directory = build_priority_session(
        tmp_path / "sessions", record_capabilities=False, record_overrides={"cvss": (), "cnvd": ()}
    )
    assets = write_priority_register(tmp_path / "assets.yaml")

    assert main(priority_arguments(directory, assets, "2026-10-12"), environment={}) == 0
    artifact = PriorityArtifact.model_validate_json((directory / "priority.json").read_bytes())

    assert artifact.decisions[0].facts.high_grade.value == "none_available"
    assert artifact.used_after_reference_date_information is True


def test_kev_listing_cites_only_the_listing_anchor_and_preserves_unknown_category(
    tmp_path: Path,
) -> None:
    directory = build_priority_session(
        tmp_path / "sessions", record_overrides={"kev": KevEntry(date_added="2026-01-01")}
    )
    assets = write_priority_register(tmp_path / "assets.yaml", category="unknown")

    assert main(priority_arguments(directory, assets), environment={}) == 0
    artifact = PriorityArtifact.model_validate_json((directory / "priority.json").read_bytes())
    decision = artifact.decisions[0]
    lookup = json.loads((directory / "responses/0002.json").read_bytes())
    anchors = {}
    for anchor in lookup["evidence"]:
        anchors[anchor["evidence_id"]] = anchor

    assert decision.matched_rule.id == "rule-4"
    assert decision.unknown_facts == ("system_category",)
    assert len(decision.facts.kev.evidence_ids) == 1
    assert anchors[decision.facts.kev.evidence_ids[0]]["authoritative_record_id"] == decision.cve_id
    assert len(artifact.response_digests) == 1


def test_cli_recordings_without_stored_byte_digests_can_be_prioritised(tmp_path: Path) -> None:
    directory = tmp_path / "cli-session"
    workflow = build_triage_workflow(directory)
    _, _, status = workflow.run(ProductQueryRequest(vendor="democorp", limit=1))
    assert status == 0
    assets = write_priority_register(tmp_path / "assets.yaml", ("CVE-9999-0002",))
    recorded_files = read_recorded_files(directory)

    assert main(priority_arguments(directory, assets), environment={}) == 0
    artifact = PriorityArtifact.model_validate_json((directory / "priority.json").read_bytes())

    assert artifact.decisions[0].facts.kev.value == "unknown"
    assert len(artifact.response_digests) == 2
    for digest in artifact.response_digests:
        call = json.loads((directory / f"calls/{digest.call:04d}.json").read_bytes())
        assert call["response_sha256"] is None
        response_bytes = (directory / f"responses/{digest.call:04d}.json").read_bytes()
        assert digest.response_sha256 == sha256_hex(response_bytes)
    assert read_recorded_files(directory) == recorded_files


@pytest.mark.parametrize(
    "title,nvd_high,kev_listed,grade,expected_rule,review",
    (
        ("PHP 漏洞", False, False, "high", "rule-6", True),
        ("DemoCorp Platform 漏洞", False, False, "high", "rule-6", False),
        ("PHP 漏洞", True, False, "high", "rule-6", True),
        ("PHP 漏洞", False, True, "high", "rule-3", False),
        ("PHP 漏洞", False, False, "low", "rule-9", False),
    ),
    ids=("cnvd-no-overlap", "vendor-overlap", "nvd-also-high", "kev-rule", "low-grade"),
)
def test_recorded_name_checks_add_review_reasons_without_changing_outcomes(
    tmp_path: Path,
    title: str,
    nvd_high: bool,
    kev_listed: bool,
    grade: str,
    expected_rule: str,
    review: bool,
) -> None:
    overrides = {
        "cvss": (build_cvss_metric(base_severity="HIGH", base_score=8.1),) if nvd_high else (),
        "kev": KevEntry(date_added="2026-01-01") if kev_listed else None,
    }
    directory = build_priority_session(
        tmp_path / "sessions",
        record_overrides=overrides,
        cnvd_overrides={"title": title, "severity": grade},
    )
    assets = write_priority_register(tmp_path / "assets.yaml")
    recorded_files = read_recorded_files(directory)

    assert main(priority_arguments(directory, assets), environment={}) == 0
    first = (directory / "priority.json").read_bytes()
    artifact = PriorityArtifact.model_validate_json(first)
    decision = artifact.decisions[0]
    links = decision.facts.high_grade.cnvd_links_to_review

    assert decision.matched_rule.id == expected_rule
    assert decision.recommendation == (
        "act" if kev_listed else "attend" if grade == "high" else "track"
    )
    assert ("review the link." in decision.reason) == review
    if title.startswith("PHP") and grade == "high":
        cnvd_ids = []
        for link in links:
            cnvd_ids.append(link.cnvd_id)
        assert cnvd_ids == ["CNVD-9999-00001", "CNVD-9999-00002"]
        assert all(link.cnvd_name == "PHP" for link in links)
    else:
        assert links == ()
    if review:
        for link in links:
            assert (
                f"{link.cnvd_id}'s product name (PHP) does not overlap "
                "NVD's CPE names; review the link." in decision.reason
            )
    if nvd_high:
        assert decision.facts.high_grade.triggering_authorities == ("NVD", "CNVD")
    assert main([*priority_arguments(directory, assets), "--force"], environment={}) == 0
    assert (directory / "priority.json").read_bytes() == first
    assert read_recorded_files(directory) == recorded_files
