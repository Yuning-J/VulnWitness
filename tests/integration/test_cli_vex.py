"""``vulnwitness vex`` writes an OpenVEX document from the register, quoting priority."""

import json
from pathlib import Path

import pytest
import yaml

from tests.support.priority import (
    build_priority_session,
    priority_arguments,
    write_priority_register,
)
from vulnwitness.adapters.session.check import SessionChecker
from vulnwitness.cli import main


def vex_arguments(assets: Path, output: Path, directory: Path | None = None) -> list[str]:
    arguments = [
        "vex",
        "--assets",
        str(assets),
        "--author",
        "Example PSIRT",
        "--as-of",
        "2026-11-16",
        "--output",
        str(output),
    ]
    if directory is not None:
        arguments.extend(["--session", str(directory)])
    return arguments


def test_vex_quotes_the_recorded_recommendation(tmp_path: Path) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    assets = write_priority_register(tmp_path / "assets.yaml")
    assert main(priority_arguments(directory, assets), environment={}) == 0
    output = tmp_path / "out.vex.json"

    exit_code = main(
        [
            "vex",
            "--assets",
            str(assets),
            "--author",
            "Example PSIRT",
            "--as-of",
            "2026-11-16",
            "--session",
            str(directory),
            "--output",
            str(output),
        ],
        environment={},
    )

    document = json.loads(output.read_text())
    assert exit_code == 0
    (statement,) = document["statements"]
    assert statement["status"] == "affected"
    assert statement["action_statement"].startswith("VulnWitness policy cn-auto-demo recommends")
    assert (output.stat().st_mode & 0o777) == 0o600


def test_vex_refuses_to_overwrite_without_force(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assets = write_priority_register(tmp_path / "assets.yaml")
    output = tmp_path / "out.vex.json"
    output.write_text("{}")
    arguments = [
        "vex",
        "--assets",
        str(assets),
        "--author",
        "Example PSIRT",
        "--as-of",
        "2026-11-16",
        "--output",
        str(output),
    ]

    assert main(arguments, environment={}) == 1
    assert "use --force" in capsys.readouterr().err
    assert main([*arguments, "--force"], environment={}) == 0
    assert json.loads(output.read_text())["statements"][0]["status"] == "affected"


def test_vex_refuses_priority_from_a_different_asset_register(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    assets = write_priority_register(tmp_path / "assets.yaml", applicability="not_affected")
    assert main(priority_arguments(directory, assets), {}) == 0
    write_priority_register(assets, applicability="affected", category="other")
    output = tmp_path / "out.json"

    assert main(vex_arguments(assets, output, directory), {}) == 1

    assert "different asset register" in capsys.readouterr().err
    assert not output.exists()


@pytest.mark.parametrize("failed_layer", ["record", "citations", "claims"])
def test_vex_refuses_a_session_that_fails_any_check_layer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], failed_layer: str
) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    assets = write_priority_register(tmp_path / "assets.yaml")
    assert main(priority_arguments(directory, assets), {}) == 0
    if failed_layer == "record":
        (directory / "responses/0099.json").write_text("{}")
    else:
        finding: dict[str, object] = {
            "id": "bad-finding",
            "kind": "analyst_note",
            "author": "user",
            "status": "unconfirmed",
            "citations": [],
        }
        if failed_layer == "citations":
            finding["statement"] = "An unresolved citation."
            finding["citations"] = [{"call": 99, "evidence_id": "ev:" + "a" * 24}]
        else:
            finding["kind"] = "record_fact"
            finding["claim"] = {
                "kind": "record_fact",
                "call": 2,
                "cve_id": "CVE-9999-0001",
                "fact": {"field": "cwe_ids", "value": ["CWE-999999"]},
            }
        (directory / "findings.yaml").write_text(
            yaml.safe_dump(
                {
                    "findings": [finding],
                    "selections": {"cve_ids": [], "product_queries": []},
                    "open_questions": [],
                }
            )
        )
    output = tmp_path / "out.json"
    report = SessionChecker(directory).check()
    assert not getattr(report, failed_layer).model_dump()[
        {"record": "consistent", "citations": "resolved", "claims": "verified"}[failed_layer]
    ]

    assert main(vex_arguments(assets, output, directory), {}) == 1

    assert "session check did not pass" in capsys.readouterr().err
    assert not output.exists()


def test_vex_refuses_an_assessment_dated_after_the_document(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assets = write_priority_register(tmp_path / "assets.yaml")
    register = yaml.safe_load(assets.read_text())
    register["assessments"][0]["assessed_at"] = "2026-11-17"
    assets.write_text(yaml.safe_dump(register))
    output = tmp_path / "out.json"

    assert main(vex_arguments(assets, output), {}) == 1

    assert "dated after --as-of" in capsys.readouterr().err
    assert not output.exists()


@pytest.mark.parametrize("applicability", ["unknown", "affected"])
def test_vex_preserves_analyst_justification_in_status_notes(
    tmp_path: Path, applicability: str
) -> None:
    assets = write_priority_register(tmp_path / "assets.yaml", applicability=applicability)
    register = yaml.safe_load(assets.read_text())
    register["assessments"][0]["justification"] = "Deployment review needs a vendor response."
    assets.write_text(yaml.safe_dump(register))
    output = tmp_path / "out.json"

    assert main(vex_arguments(assets, output), {}) == 0

    statement = json.loads(output.read_text())["statements"][0]
    assert statement["status_notes"] == "Deployment review needs a vendor response."


def test_vex_describes_a_dated_unknown_assessment_as_unknown(tmp_path: Path) -> None:
    assets = write_priority_register(tmp_path / "assets.yaml", applicability="unknown")
    register = yaml.safe_load(assets.read_text())
    register["assessments"][0].pop("justification")
    assets.write_text(yaml.safe_dump(register))
    output = tmp_path / "out.json"

    assert main(vex_arguments(assets, output), {}) == 0

    statement = json.loads(output.read_text())["statements"][0]
    assert statement["status_notes"] == "Applicability remains unknown."
