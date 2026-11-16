"""A sealed session's recorded files can be verified with the sealing key."""

import json
from pathlib import Path

import pytest

from tests.support.priority import build_priority_session
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
    files = seal["files"]
    assert isinstance(files, dict)
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
