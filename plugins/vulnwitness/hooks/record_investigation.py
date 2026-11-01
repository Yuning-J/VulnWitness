#!/usr/bin/env python3
"""Collect returned investigation IDs without relying on Claude's internal transcript."""

import json
import sys

from hook_support import (
    INVESTIGATION_PATTERN,
    TOOL_PREFIX,
    JsonValue,
    conversation_lock,
    conversation_path,
    log_error,
    read_conversation,
    read_event,
    write_conversation,
)


def extract_investigations(tool_response: JsonValue) -> list[str]:
    """Walk JSON envelopes, structuredContent and MCP text blocks for session_id keys."""
    investigations: list[str] = []
    pending = [tool_response]
    while pending:
        content = pending.pop()
        if isinstance(content, str):
            try:
                pending.append(json.loads(content))
            except ValueError:
                continue
        elif isinstance(content, list):
            pending.extend(content)
        elif isinstance(content, dict):
            investigation_id = content.get("session_id")
            if (
                isinstance(investigation_id, str)
                and INVESTIGATION_PATTERN.fullmatch(investigation_id)
                and investigation_id not in investigations
            ):
                investigations.append(investigation_id)
            pending.extend(content.values())
    return investigations


def main() -> None:
    try:
        event = read_event(sys.stdin.read())
        tool_name = event.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name.startswith(TOOL_PREFIX):
            return
        investigations = extract_investigations(event.get("tool_response"))
        if not investigations:
            return
        path = conversation_path(event)
        with conversation_lock(path):
            conversation = read_conversation(path)
            for investigation_id in investigations:
                if investigation_id not in conversation["investigations"]:
                    conversation["investigations"].append(investigation_id)
            write_conversation(path, conversation)
    except Exception as error:
        log_error(error)


if __name__ == "__main__":
    main()
