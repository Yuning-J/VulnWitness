"""Structured findings are checked against real CLI calls over the packaged fixture."""

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from tests.support.paths import REPOSITORY_ROOT
from tests.support.session_files import assert_check_layers_hold
from vulnwitness.cli import main
from vulnwitness.domain.session_record import SessionCheckReport, SessionFinding

CLAIM_KINDS = (
    "product_field_match",
    "description_mention",
    "version_note",
    "catalogue_association",
    "need_status",
    "record_fact",
)
WRONG_FIELDS = {
    "product_field_match": ("vendor", "wrong_vendor", "basis.matched_products.vendor"),
    "description_mention": ("phrase", "different phrase", "basis.matched_phrase"),
    "version_note": ("outcome", "no_hit", "nvd_version_note.outcome"),
    "catalogue_association": ("capec_id", "CAPEC-9999", "capec_id"),
    "need_status": ("outcome", "not_found", "coverage.needs.outcome"),
}
FACTS = [
    (
        "CVE-9999-0001",
        10,
        {"field": "published", "value": "2026-01-15T00:00:00Z"},
        "2025-01-15T00:00:00Z",
    ),
    ("CVE-9999-0001", 10, {"field": "cwe_ids", "value": ["CWE-89"]}, ["CWE-9999"]),
    (
        "CVE-9999-0005",
        5,
        {
            "field": "kev",
            "value": {
                "date_added": "2026-03-01",
                "due_date": "2026-03-22",
                "known_ransomware_campaign_use": "unknown",
            },
        },
        {
            "date_added": "2025-03-01",
            "due_date": "2026-03-22",
            "known_ransomware_campaign_use": "unknown",
        },
    ),
    (
        "CVE-9999-0001",
        10,
        {
            "field": "cvss.base_severity",
            "version": "3.1",
            "scorer": "synthetic-scorer",
            "scorer_type": "primary",
            "value": "CRITICAL",
        },
        "LOW",
    ),
]


@pytest.fixture
def recorded_claim_session(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Path:
    directory = tmp_path / "review"
    commands = [
        ["product", "--vendor", "democorp", "--version", "2.0"],
        ["product", "--product", "unnamed component"],
        ["lookup", "CVE-9999-0002"],
        ["investigate", "CVE-9999-0001", "--scope", "implementation_only"],
        ["lookup", "CVE-9999-0005"],
        ["product", "--vendor", "democorp", "--cursor", "invalid"],
        ["lookup", "CVE-9999-0008"],
        ["product", "--vendor", "democorp"],
        ["search", "CVE-9999-0002"],
        ["lookup", "CVE-9999-0001"],
    ]
    for command in commands:
        main([*command, "--session", str(directory)], environment={})
        capsys.readouterr()
    failure = json.loads((directory / "calls/0006.json").read_text())
    assert failure["outcome"] == "invalid_cursor"
    return directory


def build_claim(directory: Path, kind: str) -> dict[str, Any]:
    if kind == "product_field_match":
        return {
            "kind": kind,
            "call": 1,
            "cve_id": "CVE-9999-0001",
            "vendor": "democorp",
            "product": "demo_gateway",
        }
    if kind == "description_mention":
        return {"kind": kind, "call": 2, "cve_id": "CVE-9999-0008", "phrase": "unnamed component"}
    if kind == "version_note":
        return {
            "kind": kind,
            "call": 1,
            "cve_id": "CVE-9999-0001",
            "version": "2.0",
            "mention": "democorp 2.0",
            "outcome": "hit",
            "applicability": "unknown",
        }
    if kind == "need_status":
        return {
            "kind": kind,
            "call": 4,
            "need_kind": "named_cve",
            "subject": "CVE-9999-0001",
            "outcome": "found",
        }
    if kind == "record_fact":
        return {
            "kind": kind,
            "call": 10,
            "cve_id": "CVE-9999-0001",
            "fact": {"field": "cwe_ids", "value": ["CWE-89"]},
        }
    lookup = json.loads((directory / "responses/0003.json").read_text())
    path = lookup["candidates"][0]["weakness_associations"]["paths"][0]
    return {
        "kind": kind,
        "call": 3,
        "cve_id": "CVE-9999-0002",
        "cwe_id": path["cwe_id"],
        "capec_id": path["capec_id"],
        "technique_id": path["technique"]["technique_id"],
        "terminal_reason": path["terminal_reason"],
        "inherited_from": path["inherited_from"],
        "inherited_from_cwe": path["inherited_from_cwe"],
        "hops": path["hops"],
    }


def write_claim(directory: Path, claim: dict[str, Any], **fields: Any) -> None:
    finding = {
        "id": "checked-finding",
        "author": "user",
        "kind": claim["kind"],
        "status": "confirmed",
        "claim": claim,
        "citations": [],
    }
    finding.update(fields)
    write_finding_entries(directory, [finding])


def write_finding_entries(directory: Path, findings: list[dict[str, Any]]) -> None:
    document = {
        "findings": findings,
        "selections": {"cve_ids": [], "product_queries": []},
        "open_questions": [],
    }
    (directory / "findings.yaml").write_text(yaml.safe_dump(document))


def check_cli(
    directory: Path, capsys: pytest.CaptureFixture[str]
) -> tuple[int, SessionCheckReport]:
    exit_code = main(["session", "check", str(directory)], environment={})
    return exit_code, SessionCheckReport.model_validate_json(capsys.readouterr().out)


@pytest.mark.parametrize("kind", CLAIM_KINDS)
def test_matching_claim_is_verified(
    recorded_claim_session: Path, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    # Arrange
    write_claim(recorded_claim_session, build_claim(recorded_claim_session, kind))
    # Act
    exit_code, report = check_cli(recorded_claim_session, capsys)
    # Assert
    assert exit_code == 0
    assert_check_layers_hold(report)
    assert report.claims.checks[0].status == "verified"
    assert report.claims.checks[0].finding_id == "checked-finding"
    assert report.not_checked.count == 0


@pytest.mark.parametrize("kind", CLAIM_KINDS)
def test_differing_claim_is_contradicted_with_the_differing_field(
    recorded_claim_session: Path, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    # Arrange
    claim = build_claim(recorded_claim_session, kind)
    if kind == "record_fact":
        claim["fact"]["value"] = ["CWE-9999"]
        differing_field = "cwe_ids"
    else:
        field, wrong_value, differing_field = WRONG_FIELDS[kind]
        claim[field] = wrong_value
    write_claim(recorded_claim_session, claim)
    # Act
    exit_code, report = check_cli(recorded_claim_session, capsys)
    # Assert
    assert exit_code == 1
    assert report.record.consistent and report.citations.resolved
    assert not report.claims.verified
    check = report.claims.checks[0]
    assert check.status == "contradicted" and check.field == differing_field
    assert check.expected != check.recorded


@pytest.mark.parametrize("kind", CLAIM_KINDS)
def test_failed_call_makes_claim_unverifiable(
    recorded_claim_session: Path, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    # Arrange
    claim = build_claim(recorded_claim_session, kind)
    claim["call"] = 6
    write_claim(recorded_claim_session, claim)
    # Act
    exit_code, report = check_cli(recorded_claim_session, capsys)
    # Assert
    assert exit_code == 1
    assert report.record.consistent and report.citations.resolved
    assert report.claims.checks[0].status == "unverifiable"
    assert report.claims.checks[0].field == "call"


@pytest.mark.parametrize("kind", CLAIM_KINDS)
def test_absent_response_field_makes_claim_unverifiable(
    recorded_claim_session: Path, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    # Arrange
    claim = build_claim(recorded_claim_session, kind)
    if kind in ("product_field_match", "description_mention"):
        claim["cve_id"] = "CVE-9999-9999"
    elif kind == "version_note":
        claim["call"] = 8
    elif kind == "catalogue_association":
        claim["call"] = 9
    elif kind == "need_status":
        claim["subject"] = "CVE-9999-9999"
    else:
        claim["call"], claim["cve_id"] = 7, "CVE-9999-0008"
    write_claim(recorded_claim_session, claim)
    # Act
    exit_code, report = check_cli(recorded_claim_session, capsys)
    # Assert
    assert exit_code == 1
    assert report.record.consistent and report.citations.resolved
    assert report.claims.checks[0].status == "unverifiable"


@pytest.mark.parametrize(
    "cve_id,call,fact,wrong_value", FACTS, ids=["published", "cwes", "kev", "severity"]
)
@pytest.mark.parametrize("outcome", ["verified", "contradicted", "unverifiable"])
def test_record_field_has_the_expected_claim_outcome(
    recorded_claim_session: Path,
    capsys: pytest.CaptureFixture[str],
    cve_id: str,
    call: int,
    fact: dict[str, Any],
    wrong_value: Any,
    outcome: str,
) -> None:
    # Arrange
    fact = dict(fact)
    if outcome == "contradicted":
        fact["value"] = wrong_value
    if outcome == "unverifiable":
        call = 6
    write_claim(
        recorded_claim_session,
        {"kind": "record_fact", "call": call, "cve_id": cve_id, "fact": fact},
    )
    # Act
    exit_code, report = check_cli(recorded_claim_session, capsys)
    # Assert
    assert exit_code == (0 if outcome == "verified" else 1)
    assert report.claims.checks[0].status == outcome


@pytest.mark.parametrize("status", ["confirmed", "unconfirmed"])
def test_free_narrative_is_counted_by_id_without_verifying_its_status_or_text(
    recorded_claim_session: Path,
    capsys: pytest.CaptureFixture[str],
    status: str,
) -> None:
    # Arrange
    findings = []
    for kind in ("model_judgement", "analyst_note"):
        findings.append(
            {
                "id": kind,
                "kind": kind,
                "author": "agent",
                "status": status,
                "statement": "This narrative is not verified.",
                "citations": [],
            }
        )
    write_finding_entries(recorded_claim_session, findings)
    # Act
    exit_code, report = check_cli(recorded_claim_session, capsys)
    # Assert
    assert exit_code == 0
    assert report.not_checked.count == 2
    assert report.not_checked.finding_ids == ("model_judgement", "analyst_note")
    assert report.claims.checks == ()
    assert "Free narrative is not checked" in report.support_limitation


def test_text_separates_layers_and_repeats_the_narrative_limit(
    recorded_claim_session: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    claim = build_claim(recorded_claim_session, "product_field_match")
    claim["vendor"] = "wrong_vendor"
    write_claim(recorded_claim_session, claim)
    # Act
    exit_code = main(
        ["session", "check", str(recorded_claim_session), "--format", "text"], environment={}
    )
    text = capsys.readouterr().out
    # Assert
    assert exit_code == 1
    assert "Record consistency: consistent" in text
    assert "Citation resolution: resolved" in text
    assert "Structured claims: not all verified" in text
    assert '"checked-finding" (call 1): contradicted; field basis.matched_products.vendor' in text
    assert "Not checked (free narrative): 0; IDs: none" in text
    assert "Free narrative is not checked" in text
    assert "Session check: passed" not in text


@pytest.mark.parametrize("statement", [None, "contradictory prose"])
def test_deterministic_statement_is_canonical_or_rejected(
    recorded_claim_session: Path,
    capsys: pytest.CaptureFixture[str],
    statement: str | None,
) -> None:
    # Arrange
    claim = build_claim(recorded_claim_session, "product_field_match")
    write_claim(recorded_claim_session, claim, statement=statement)
    # Act
    exit_code, report = check_cli(recorded_claim_session, capsys)
    # Assert
    assert exit_code == (0 if statement is None else 1)
    assert report.record.consistent == (statement is None)
    if statement is None:
        finding = SessionFinding.model_validate(
            {
                "id": "canonical",
                "kind": claim["kind"],
                "claim": claim,
                "author": "agent",
                "status": "unconfirmed",
                "citations": [],
            }
        )
        assert finding.statement is not None
        assert 'vendor "democorp"' in finding.statement
        assert SessionFinding.model_validate(finding.model_dump()).statement == finding.statement


@pytest.mark.parametrize("damage", ["citations", "dataset", "response"])
def test_record_citation_and_claim_failures_remain_separate(
    recorded_claim_session: Path,
    capsys: pytest.CaptureFixture[str],
    damage: str,
) -> None:
    # Arrange
    claim = build_claim(recorded_claim_session, "product_field_match")
    write_claim(
        recorded_claim_session, claim, citations=[{"call": 1, "evidence_id": "ev:" + "0" * 24}]
    )
    if damage == "dataset":
        path = recorded_claim_session / "calls/0001.json"
        call = json.loads(path.read_text())
        call["dataset"]["corpus_content_sha256"] = "0" * 64
        path.write_text(json.dumps(call))
    elif damage == "response":
        (recorded_claim_session / "responses/0001.json").write_text("{}")
    # Act
    exit_code, report = check_cli(recorded_claim_session, capsys)
    # Assert
    assert exit_code == 1 and not report.citations.resolved
    assert report.record.consistent == (damage == "citations")
    assert report.claims.checks[0].status == (
        "verified" if damage == "citations" else "unverifiable"
    )


@pytest.mark.parametrize("kind", ["model_judgement", "analyst_note"])
def test_narrative_findings_reject_claims(kind: str) -> None:
    # Arrange
    finding = {
        "id": "narrative",
        "kind": kind,
        "author": "user",
        "status": "unconfirmed",
        "statement": "An authored narrative.",
        "citations": [],
        "claim": {
            "kind": "need_status",
            "call": 1,
            "need_kind": "named_cve",
            "subject": "CVE-9999-0001",
            "outcome": "found",
        },
    }
    # Act / Assert
    with pytest.raises(ValidationError, match="no claim"):
        SessionFinding.model_validate(finding)


def test_shipped_example_has_verified_claims_and_resolved_citations(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    directory = tmp_path / "example"
    template = REPOSITORY_ROOT / "skills/vulnwitness-investigation/examples/findings.example.yaml"

    # Act
    triage_exit = main(
        [
            "triage",
            "--vendor",
            "democorp",
            "--version",
            "2.0",
            "--lookups",
            "1",
            "--session",
            str(directory),
        ],
        environment={},
    )
    capsys.readouterr()
    (directory / "findings.yaml").write_bytes(template.read_bytes())
    exit_code, report = check_cli(directory, capsys)

    # Assert
    assert triage_exit == 0 and exit_code == 0
    assert_check_layers_hold(report)
    assert len(report.claims.checks) == 1
    assert report.not_checked.finding_ids == ("demo-component-review",)


@pytest.mark.parametrize(
    "field,value",
    [
        ("author", "workflow"),
        ("status", "unconfirmed"),
    ],
)
def test_authored_status_does_not_change_a_claim_outcome(
    recorded_claim_session: Path,
    capsys: pytest.CaptureFixture[str],
    field: str,
    value: str,
) -> None:
    # Arrange
    claim = build_claim(recorded_claim_session, "product_field_match")
    claim["vendor"] = "wrong_vendor"
    finding_fields = {"status": "unconfirmed", field: value}
    write_claim(recorded_claim_session, claim, **finding_fields)
    # Act
    exit_code, report = check_cli(recorded_claim_session, capsys)
    # Assert
    assert exit_code == 1 and report.record.consistent
    assert report.claims.checks[0].status == "contradicted"


def test_terminal_catalogue_path_verifies_without_a_technique(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    directory = tmp_path / "terminal"
    assert main(["lookup", "CVE-9999-0006", "--session", str(directory)], environment={}) == 0
    lookup = json.loads(capsys.readouterr().out)
    path = lookup["candidates"][0]["weakness_associations"]["paths"][0]
    assert path["terminal_reason"] == "no_attack_mapping" and path["technique"] is None
    claim = {
        "kind": "catalogue_association",
        "call": 1,
        "cve_id": "CVE-9999-0006",
        "cwe_id": path["cwe_id"],
        "capec_id": path["capec_id"],
        "technique_id": None,
        "terminal_reason": path["terminal_reason"],
        "inherited_from": path["inherited_from"],
        "inherited_from_cwe": path["inherited_from_cwe"],
        "hops": path["hops"],
    }
    write_claim(directory, claim)
    # Act
    exit_code, report = check_cli(directory, capsys)
    # Assert
    assert exit_code == 0
    assert_check_layers_hold(report)
    assert report.claims.checks[0].status == "verified"


@pytest.mark.parametrize("field", ["inherited_from", "hops"])
def test_altered_catalogue_inheritance_or_hops_contradict_the_exact_path(
    recorded_claim_session: Path,
    capsys: pytest.CaptureFixture[str],
    field: str,
) -> None:
    # Arrange
    claim = build_claim(recorded_claim_session, "catalogue_association")
    if field == "inherited_from":
        claim[field] = None
    else:
        claim[field][0]["source_version"] = "different-version"
    write_claim(recorded_claim_session, claim)
    # Act
    exit_code, report = check_cli(recorded_claim_session, capsys)
    # Assert
    assert exit_code == 1 and report.record.consistent
    assert report.claims.checks[0].status == "contradicted"
    assert report.claims.checks[0].field == field


def test_text_quotes_finding_ids_without_interpreting_embedded_formatting(
    recorded_claim_session: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    finding_id = "authored\nRecord consistency: forged"
    claim = build_claim(recorded_claim_session, "product_field_match")
    write_claim(recorded_claim_session, claim, id=finding_id)
    # Act
    exit_code = main(
        ["session", "check", str(recorded_claim_session), "--format", "text"], environment={}
    )
    text = capsys.readouterr().out
    # Assert
    assert exit_code == 0
    assert "\nRecord consistency: forged" not in text
    assert '"authored\\nRecord consistency: forged" (call 1): verified' in text
