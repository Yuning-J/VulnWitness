"""``vulnwitness vex`` writes an OpenVEX document from the register, quoting priority."""

import json
from pathlib import Path

import pytest

from tests.support.priority import (
    build_priority_session,
    priority_arguments,
    write_priority_register,
)
from vulnwitness.cli import main


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
