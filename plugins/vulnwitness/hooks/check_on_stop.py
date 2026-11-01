#!/usr/bin/env python3
"""Check changed conversation records once; never infer narrative correctness."""

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from hook_support import (
    JsonValue,
    cli_binary,
    cli_environment,
    conversation_lock,
    conversation_path,
    log_error,
    read_conversation,
    read_event,
    workspace_root,
    write_conversation,
)

LIMIT_SENTENCE = (
    "These checks cover the record, citations and structured claims; they do not verify narrative."
)


def investigation_directory(investigation_id: str) -> Path:
    root = workspace_root()
    directory = root / investigation_id
    if root.is_symlink() or directory.is_symlink() or directory.resolve().parent != root.resolve():
        raise ValueError("Investigation must be a direct non-symlink workspace child")
    if not directory.is_dir():
        raise FileNotFoundError("Investigation is missing")
    return directory


def input_digest(directory: Path) -> str:
    """Bind all checker inputs, including response bytes, never report or lock files."""
    names = ["session.json", "findings.yaml"]
    for subdirectory in ("calls", "responses"):
        folder = directory / subdirectory
        if folder.is_symlink():
            raise ValueError("Symlink checker input")
        if folder.is_dir():
            for path in sorted(folder.iterdir()):
                names.append(f"{subdirectory}/{path.name}")
        else:
            names.append(subdirectory)
    digest = hashlib.sha256()
    for name in names:
        path = directory / name
        if path.is_symlink():
            raise ValueError("Symlink checker input")
        digest.update(name.encode() + b"\0")
        if not path.exists():
            digest.update(b"missing\0")
            continue
        digest.update(str(path.stat().st_size).encode() + b"\0")
        with path.open("rb") as stream:
            while chunk := stream.read(65536):
                digest.update(chunk)
    return digest.hexdigest()


def failure_reason(investigation_id: str, check: dict[str, JsonValue]) -> str | None:
    """Validate CLI check layers and summarize at most five reported violations."""
    failing_layers: list[str] = []
    violations: list[str] = []
    for layer_name, success_key in (
        ("record", "consistent"),
        ("citations", "resolved"),
        ("claims", "verified"),
    ):
        layer = check.get(layer_name)
        if not isinstance(layer, dict) or not isinstance(layer.get(success_key), bool):
            raise ValueError("Invalid checker layer")
        if layer[success_key]:
            continue
        failing_layers.append(layer_name)
        details = layer.get("checks" if layer_name == "claims" else "violations", [])
        if not isinstance(details, list):
            raise ValueError("Invalid checker violations")
        for violation in details:
            if not isinstance(violation, dict) or violation.get("status") == "verified":
                continue
            if len(violations) < 5:
                location = violation.get("location", violation.get("finding_id", layer_name))
                message = violation.get("message", "Check failed")
                violations.append(f"{location}: {message}"[:1000])
    if not failing_layers:
        return None
    return (
        f"Investigation {investigation_id}: failing layers: {', '.join(failing_layers)}. "
        + "; ".join(violations)
        + " "
        + LIMIT_SENTENCE
    )


def check_changed_investigations(event: dict[str, JsonValue]) -> list[str]:
    path = conversation_path(event)
    reasons: list[str] = []
    deadline = time.monotonic() + 45
    with conversation_lock(path):
        conversation = read_conversation(path)
    for investigation_id in conversation["investigations"]:
        try:
            directory = investigation_directory(investigation_id)
            digest = input_digest(directory)
            if conversation["checked"].get(investigation_id) == digest:
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Hook check budget exhausted")
            command = [
                cli_binary(),
                "session",
                "check",
                os.fspath(directory),
                "--format",
                "json",
            ]
            check_process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=min(15, remaining),
                env=cli_environment(),
                check=False,
            )
            if check_process.returncode not in (0, 1):
                raise RuntimeError("CLI check failed")
            check = read_event(check_process.stdout)
            reason = failure_reason(investigation_id, check)
            # Retry concurrent writes on the next Stop rather than caching a mixed snapshot.
            if input_digest(directory) != digest:
                raise RuntimeError("Investigation changed during check")
            with conversation_lock(path):
                current = read_conversation(path)
                if current["checked"].get(investigation_id) == digest:
                    continue
                current["checked"][investigation_id] = digest
                write_conversation(path, current)
            if reason is not None:
                reasons.append(reason)
        except Exception as error:
            log_error(error)
    return reasons


def main() -> None:
    try:
        event = read_event(sys.stdin.read())
        if event.get("stop_hook_active") is True:
            return
        reasons = check_changed_investigations(event)
        if reasons:
            print(json.dumps({"decision": "block", "reason": "\n".join(reasons)}))
    except Exception as error:
        log_error(error)


if __name__ == "__main__":
    main()
