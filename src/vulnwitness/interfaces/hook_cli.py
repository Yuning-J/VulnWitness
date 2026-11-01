"""Claude Code JSON ingress, investigation extraction and fail-open hook commands."""

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from pydantic import JsonValue

from vulnwitness.domain.workspace import INVESTIGATION_ID_PATTERN
from vulnwitness.ports.plugin_hooks import PluginHookState

TOOL_PREFIX = "mcp__plugin_vulnwitness_vulnwitness__"
LIMIT_SENTENCE = (
    "These checks cover the record, citations and structured claims; they do not verify narrative."
)


def read_event(text: str) -> dict[str, JsonValue]:
    event: JsonValue = json.loads(text)
    if not isinstance(event, dict):
        raise ValueError("Expected hook object")
    return event


# Tools whose answers list other investigations; recording them would pull unrelated
# investigations of a shared workspace into this conversation's stop checks.
LISTING_TOOLS = frozenset({TOOL_PREFIX + "list_investigations"})


def unwrap_tool_answers(tool_response: JsonValue) -> list[dict[str, JsonValue]]:
    """The tool's top-level answer objects. Claude Code passes the MCP result as a JSON
    string of the structured content; dict, structuredContent and text-content envelopes
    are unwrapped too. Nested objects inside an answer are never returned."""
    answers: list[dict[str, JsonValue]] = []
    pending: list[JsonValue] = [tool_response]
    while pending:
        content = pending.pop()
        if isinstance(content, str):
            try:
                pending.append(json.loads(content))
            except ValueError:
                continue
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    pending.append(item.get("text"))
        elif isinstance(content, dict):
            if isinstance(content.get("structuredContent"), dict):
                pending.append(content["structuredContent"])
            elif isinstance(content.get("content"), list):
                pending.append(content["content"])
            else:
                answers.append(content)
    return answers


def extract_investigations(tool_response: JsonValue) -> list[str]:
    """Investigation IDs named by the answer's own top-level ``session_id``."""
    investigations: list[str] = []
    for answer in unwrap_tool_answers(tool_response):
        investigation_id = answer.get("session_id")
        if (
            isinstance(investigation_id, str)
            and re.fullmatch(INVESTIGATION_ID_PATTERN, investigation_id)
            and investigation_id not in investigations
        ):
            investigations.append(investigation_id)
    return investigations


def conversation_path(event: dict[str, JsonValue], state: PluginHookState) -> Path:
    session_id = event.get("session_id")
    if not isinstance(session_id, str):
        raise ValueError("Expected hook session_id")
    return state.conversation_path(session_id)


def record_investigation(event: dict[str, JsonValue], state: PluginHookState) -> None:
    tool_name = event.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name.startswith(TOOL_PREFIX):
        return
    if tool_name in LISTING_TOOLS:
        return
    investigations = extract_investigations(event.get("tool_response"))
    if not investigations:
        return
    path = conversation_path(event, state)
    with state.conversation_lock(path):
        conversation = state.read_conversation(path)
        for investigation_id in investigations:
            if investigation_id not in conversation["investigations"]:
                conversation["investigations"].append(investigation_id)
        state.write_conversation(path, conversation)


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


def check_changed_investigations(
    event: dict[str, JsonValue],
    state: PluginHookState,
    checker: Callable[[Path, float], dict[str, JsonValue]],
    monotonic: Callable[[], float],
) -> list[str]:
    path = conversation_path(event, state)
    reasons: list[str] = []
    deadline = monotonic() + 45
    with state.conversation_lock(path):
        conversation = state.read_conversation(path)
    for investigation_id in conversation["investigations"]:
        try:
            directory = state.investigation_directory(investigation_id)
            digest = state.input_digest(directory)
            if conversation["checked"].get(investigation_id) == digest:
                continue
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError("Hook check budget exhausted")
            check = checker(directory, min(15, remaining))
            reason = failure_reason(investigation_id, check)
            # Retry concurrent writes on the next Stop rather than caching a mixed snapshot.
            if state.input_digest(directory) != digest:
                raise RuntimeError("Investigation changed during check")
            with state.conversation_lock(path):
                current = state.read_conversation(path)
                if current["checked"].get(investigation_id) == digest:
                    continue
                current["checked"][investigation_id] = digest
                state.write_conversation(path, current)
            if reason is not None:
                reasons.append(reason)
        except Exception as error:
            state.log_error(error)
    return reasons


def run_hook(
    command: str,
    stdin: TextIO,
    stdout: TextIO,
    state: PluginHookState,
    checker: Callable[[Path, float], dict[str, JsonValue]],
    monotonic: Callable[[], float],
) -> int:
    """Run an advisory hook; malformed events and operational failures never block."""
    try:
        event = read_event(stdin.read())
        if command == "record-investigation":
            record_investigation(event, state)
        elif event.get("stop_hook_active") is not True:
            reasons = check_changed_investigations(event, state, checker, monotonic)
            if reasons:
                stdout.write(json.dumps({"decision": "block", "reason": "\n".join(reasons)}) + "\n")
    except Exception as error:
        state.log_error(error)
    return 0
