"""REST routes that are each one knowledge-tool call (ADR 0007, decisions 8 and 9).

A route reads the tool's arguments from the request (the JSON body, the path's last
segment, or none), hands them to ``KnowledgeToolbox.call`` on a worker thread and
answers the tool's JSON with 200, or its ``ToolFailure`` with the status its code has
over REST. The route itself only answers ``invalid_arguments`` for a body that is not a
JSON object or an evidence-ID segment that is not ASCII; the toolbox parses everything
else with the tool's request contract, so no answer repeats what the request sent.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass

import anyio.to_thread
from starlette.types import Receive, Scope, Send

from cve_kgrag.domain.tool_contracts import ToolFailure, ToolFailureCode
from cve_kgrag.interfaces.http.guard import read_path_segment, read_route_body, send_json
from cve_kgrag.interfaces.knowledge_toolbox import KnowledgeToolbox
from cve_kgrag.interfaces.knowledge_tools import KnowledgeToolName, build_tool_failure

# Each failure's status over REST (ADR 0007, decision 8). MCP answers a failure with the
# tool's error result instead.
TOOL_FAILURE_STATUSES: dict[ToolFailureCode, int] = {
    ToolFailureCode.SESSION_CALL_LIMIT: 429,
    ToolFailureCode.SESSION_DATASET_MISMATCH: 409,
    ToolFailureCode.SESSION_RECORDING_FAILED: 500,
    ToolFailureCode.INVALID_ARGUMENTS: 422,
    ToolFailureCode.INVALID_CURSOR: 422,
    ToolFailureCode.ARGUMENTS_TOO_LARGE: 413,
    ToolFailureCode.UNKNOWN_EVIDENCE_ID: 404,
    ToolFailureCode.SERVER_BUSY: 503,
    ToolFailureCode.DATA_LOADING: 503,
    ToolFailureCode.TIMED_OUT: 504,
    ToolFailureCode.RESPONSE_TOO_LARGE: 500,
    ToolFailureCode.INTEGRITY_CHECK_FAILED: 500,
    ToolFailureCode.INTERNAL_ERROR: 500,
    ToolFailureCode.FILTER_UNSUPPORTED: 422,
}

ToolArguments = dict[str, object]
# Reads a tool's arguments from the request's scope and body, or ``None`` when the
# request carries none the tool could parse.
ArgumentReader = Callable[[Scope, bytes], ToolArguments | None]


def read_no_arguments(scope: Scope, body: bytes) -> ToolArguments | None:
    return {}


def read_body_arguments(scope: Scope, body: bytes) -> ToolArguments | None:
    """The body as a JSON object, or ``None`` when it is not one."""
    try:
        arguments = json.loads(body)
    except (ValueError, RecursionError):
        return None
    if not isinstance(arguments, dict):
        return None
    return arguments


def read_evidence_id_argument(scope: Scope, body: bytes) -> ToolArguments | None:
    """The path's last segment as the ``evidence_id``, exactly as the request line wrote
    it; the tool's contract decides whether it is one."""
    path_segment = read_path_segment(scope)
    if not path_segment.isascii():
        return None
    return {"evidence_id": path_segment.decode("ascii")}


async def send_tool_failure(send: Send, tool_failure: ToolFailure) -> None:
    await send_json(
        send, TOOL_FAILURE_STATUSES[tool_failure.code], tool_failure.model_dump_json().encode()
    )


@dataclass(frozen=True)
class ToolRoute:
    """One tool over REST: ``read_arguments`` reads its arguments, ``toolbox`` answers.
    Arguments that cannot be read are the tool's ``invalid_arguments``."""

    toolbox: KnowledgeToolbox
    tool_name: KnowledgeToolName
    read_arguments: ArgumentReader

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        arguments = self.read_arguments(scope, await read_route_body(receive))
        if arguments is None:
            await send_tool_failure(send, build_tool_failure(ToolFailureCode.INVALID_ARGUMENTS))
            return
        # The toolbox bounds the call itself, so a request cancelled at its deadline leaves
        # the thread to finish within the tool's own limit.
        tool_outcome = await anyio.to_thread.run_sync(
            self.toolbox.call, self.tool_name, arguments, abandon_on_cancel=True
        )
        if isinstance(tool_outcome, ToolFailure):
            await send_tool_failure(send, tool_outcome)
            return
        await send_json(send, 200, tool_outcome.json_text.encode())
