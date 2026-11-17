"""A sealed session's recorded files can be verified with the sealing key."""

import json
from pathlib import Path

import pytest

from tests.support.priority import (
    build_priority_session,
    priority_arguments,
    write_priority_register,
)
from vulnwitness.adapters.session.seal import (
    SealError,
    read_key,
    seal_session,
    verify_session_seal,
)
from vulnwitness.cli import main


@pytest.fixture
def key_file(tmp_path: Path) -> Path:
    path = tmp_path / "seal.key"
    path.write_bytes(b"k" * 32)
    return path


def test_untouched_session_verifies_and_editable_files_stay_unsealed(
    tmp_path: Path, key_file: Path
) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    key = read_key(key_file, directory)
    seal = seal_session(directory, key, force=False)
    (directory / "findings.yaml").write_text("edited after sealing\n")

    verification = verify_session_seal(directory, key)

    assert verification.valid
    files = seal.files
    assert "session.json" in files
    assert any(name.startswith("responses/") for name in files)
    assert "findings.yaml" not in files


def test_a_rewritten_response_is_named(tmp_path: Path, key_file: Path) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    key = read_key(key_file, directory)
    seal_session(directory, key, force=False)
    response = sorted((directory / "responses").iterdir())[0]
    document = json.loads(response.read_bytes())
    document["tampered"] = True
    response.write_text(json.dumps(document))
    (directory / "responses" / "9999.json").write_text("{}")

    verification = verify_session_seal(directory, key)

    assert not verification.valid
    assert verification.changed == (f"responses/{response.name}",)
    assert verification.added == ("responses/9999.json",)


def test_wrong_short_or_inside_keys_are_refused(tmp_path: Path, key_file: Path) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    seal_session(directory, read_key(key_file, directory), force=False)
    other = tmp_path / "other.key"
    other.write_bytes(b"o" * 32)
    short = tmp_path / "short.key"
    short.write_bytes(b"s" * 8)
    inside = directory / "inside.key"
    inside.write_bytes(b"i" * 32)

    with pytest.raises(SealError, match="not the one"):
        verify_session_seal(directory, read_key(other, directory))
    with pytest.raises(SealError, match="32 to"):
        read_key(short, directory)
    with pytest.raises(SealError, match="inside the session"):
        read_key(inside, directory)


def test_cli_seal_and_verify(tmp_path: Path, key_file: Path) -> None:
    directory = build_priority_session(tmp_path / "sessions")

    assert main(["session", "seal", str(directory), "--key-file", str(key_file)], {}) == 0
    assert main(["session", "verify-seal", str(directory), "--key-file", str(key_file)], {}) == 0
    assert main(["session", "check", str(directory)], {}) == 0
    (directory / "session.json").write_text((directory / "session.json").read_text() + " ")
    assert main(["session", "verify-seal", str(directory), "--key-file", str(key_file)], {}) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("mac", "é" * 64),
        ("mac", "g" * 64),
        ("mac", "a" * 63),
        ("files", {"session.json": "é" * 64}),
        ("algorithm", "other"),
        ("format_version", 2),
        ("key_id", "é" * 16),
        ("unexpected", "field"),
    ],
)
def test_verify_seal_rejects_invalid_contract_fields_without_traceback(
    tmp_path: Path, key_file: Path, capsys: pytest.CaptureFixture[str], field: str, value: object
) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    seal_session(directory, read_key(key_file, directory), force=False)
    seal_path = directory / "seal.json"
    seal = json.loads(seal_path.read_text())
    seal[field] = value
    seal_path.write_text(json.dumps(seal))

    exit_code = main(["session", "verify-seal", str(directory), "--key-file", str(key_file)], {})

    assert exit_code == 1
    stderr = capsys.readouterr().err
    assert "seal.json is missing, unreadable or invalid" in stderr
    assert "Traceback" not in stderr


def test_verify_seal_rejects_deep_json_without_traceback(
    tmp_path: Path, key_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    (directory / "seal.json").write_text("[" * 200000 + "]" * 200000)

    exit_code = main(["session", "verify-seal", str(directory), "--key-file", str(key_file)], {})

    assert exit_code == 1
    stderr = capsys.readouterr().err
    assert "seal.json is missing, unreadable or invalid" in stderr
    assert "Traceback" not in stderr


@pytest.mark.parametrize("mutation", ["edit", "regenerate", "add", "remove"])
def test_verify_seal_detects_priority_changes(
    tmp_path: Path, key_file: Path, capsys: pytest.CaptureFixture[str], mutation: str
) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    assets = write_priority_register(tmp_path / "assets.yaml")
    if mutation != "add":
        assert main(priority_arguments(directory, assets), {}) == 0
    key = read_key(key_file, directory)
    seal_session(directory, key, force=False)
    assert verify_session_seal(directory, key).valid
    if mutation == "remove":
        (directory / "priority.json").unlink()
    elif mutation == "edit":
        priority_path = directory / "priority.json"
        priority_path.write_bytes(priority_path.read_bytes() + b" ")
    else:
        assert main([*priority_arguments(directory, assets, "2026-11-09"), "--force"], {}) == 0

    exit_code = main(["session", "verify-seal", str(directory), "--key-file", str(key_file)], {})

    assert exit_code == 1
    label = {"edit": "changed", "regenerate": "changed", "add": "added", "remove": "removed"}
    assert f"{label[mutation]}: priority.json" in capsys.readouterr().out


def test_seal_and_verify_ignore_unrelated_invalid_settings(tmp_path: Path, key_file: Path) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    environment = {"VULNWITNESS_PLANNER_ENABLED": "invalid"}

    assert main(["session", "seal", str(directory), "--key-file", str(key_file)], environment) == 0
    assert (
        main(["session", "verify-seal", str(directory), "--key-file", str(key_file)], environment)
        == 0
    )


def test_seal_refuses_non_regular_entries(
    tmp_path: Path, key_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    (directory / "responses/extra").mkdir()

    assert main(["session", "seal", str(directory), "--key-file", str(key_file)], {}) == 1

    assert "session seal failed" in capsys.readouterr().err
    assert not (directory / "seal.json").exists()
