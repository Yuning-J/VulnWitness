"""CLI composition for advisory Claude Code hooks over private plugin state."""

import time
from collections.abc import Mapping
from functools import partial
from pathlib import Path
from typing import TextIO

from vulnwitness.adapters.plugin_hook_check import check_investigation
from vulnwitness.adapters.plugin_hook_state import LocalPluginHookState
from vulnwitness.interfaces.hook_cli import run_hook


def run_plugin_hook(
    command: str, stdin: TextIO, stdout: TextIO, environment: Mapping[str, str]
) -> int:
    plugin_data = environment.get("CLAUDE_PLUGIN_DATA")
    workspace = Path(
        environment.get("VULNWITNESS_WORKSPACE") or Path.home() / ".vulnwitness/workspace"
    )
    state = LocalPluginHookState(
        Path(plugin_data) if plugin_data is not None else None,
        workspace,
        time.monotonic,
        time.sleep,
    )
    return run_hook(
        command,
        stdin,
        stdout,
        state,
        partial(check_investigation, environment=environment),
        time.monotonic,
    )
