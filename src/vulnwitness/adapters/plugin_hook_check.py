"""Bounded CLI process boundary for the record-only session checker."""

import json
import os
import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path

from pydantic import JsonValue


def check_investigation(
    directory: Path, timeout: float, *, environment: Mapping[str, str]
) -> dict[str, JsonValue]:
    """Check saved records through the operator's CLI without loading a store."""
    binary = environment.get("VULNWITNESS_BIN") or "vulnwitness"
    executable = shutil.which(binary, path=environment.get("PATH"))
    if executable is None:
        raise FileNotFoundError("VulnWitness CLI not found")
    check_process = subprocess.run(
        [executable, "session", "check", os.fspath(directory), "--format", "json"],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=environment,
        check=False,
    )
    if check_process.returncode not in (0, 1):
        raise RuntimeError("CLI check failed")
    check: JsonValue = json.loads(check_process.stdout)
    if not isinstance(check, dict):
        raise ValueError("Expected checker object")
    return check
