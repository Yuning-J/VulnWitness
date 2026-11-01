"""Record normalized MCP requests and the exact structured-content serialization."""

import json
import logging
from collections.abc import Callable
from functools import partial
from typing import Literal

from pydantic import JsonValue, ValidationError

from cve_kgrag.domain.session_record import SessionRecordingError
from cve_kgrag.domain.tool_contracts import ToolFailure, ToolFailureCode
from cve_kgrag.interfaces.knowledge_toolbox import KnowledgeToolbox
from cve_kgrag.interfaces.knowledge_tools import (
    KNOWLEDGE_TOOL_SPECS,
    KnowledgeToolName,
    ToolAnswer,
    build_tool_failure,
)
from cve_kgrag.ports.session_recording import SessionRecording


def encode_tool_answer(
    answer: ToolAnswer | ToolFailure,
) -> tuple[bytes, Literal["ok"] | ToolFailureCode, str]:
    if isinstance(answer, ToolFailure):
        return answer.model_dump_json().encode("utf-8"), answer.code, "ToolFailure"
    return answer.json_text.encode("utf-8"), "ok", "SessionResponse"


def invoke_tool(
    toolbox: KnowledgeToolbox | None,
    name: str,
    arguments: dict[str, object] | None,
) -> ToolAnswer | ToolFailure:
    if toolbox is None:
        return build_tool_failure(ToolFailureCode.DATA_LOADING)
    try:
        tool_name = KnowledgeToolName(name)
    except ValueError:
        return build_tool_failure(ToolFailureCode.INVALID_ARGUMENTS)
    try:
        return toolbox.call(tool_name, arguments)
    except Exception:
        logging.getLogger(__name__).error("session tool failed outside toolbox", exc_info=True)
        return build_tool_failure(ToolFailureCode.INTERNAL_ERROR)


def record_tool_call(
    recorder: SessionRecording,
    toolbox: KnowledgeToolbox | None,
    name: str,
    arguments: dict[str, object] | None,
) -> ToolAnswer | ToolFailure:
    request: dict[str, JsonValue] | None = None
    response_schema = "SessionResponse"
    for spec in KNOWLEDGE_TOOL_SPECS:
        if spec.name.value != name:
            continue
        response_schema = spec.response_model.__name__
        try:
            request = spec.request_model.model_validate_json(
                json.dumps(arguments or {}, allow_nan=False)
            ).model_dump(mode="json")
        except (ValidationError, ValueError, TypeError):
            request = None
        break
    operation: Callable[[], ToolAnswer | ToolFailure] = partial(
        invoke_tool, toolbox, name, arguments
    )
    encoder: Callable[
        [ToolAnswer | ToolFailure], tuple[bytes, Literal["ok"] | ToolFailureCode, str]
    ] = partial(encode_named_tool_answer, response_schema)
    try:
        return recorder.run(
            "mcp",
            name,
            request,
            operation,
            encoder,
        )
    except SessionRecordingError as error:
        return build_tool_failure(error.code)


def encode_named_tool_answer(
    response_schema: str,
    answer: ToolAnswer | ToolFailure,
) -> tuple[bytes, Literal["ok"] | ToolFailureCode, str]:
    content, outcome, schema = encode_tool_answer(answer)
    if outcome == "ok":
        schema = response_schema
    return content, outcome, schema
