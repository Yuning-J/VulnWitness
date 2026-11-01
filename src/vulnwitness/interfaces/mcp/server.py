"""The knowledge tools as an MCP server: the SDK's low-level ``Server`` with only the tool
handlers registered, so it advertises tools and nothing else (ADR 0003 §6).

Each tool's listed input and output schema is the committed contract snapshot. A call is
handed to ``KnowledgeToolbox.call`` on a worker thread, so the event loop never blocks;
every failure is answered as a ``ToolFailure`` with a fixed message, never exception text.
A JSON-RPC error raised while handling a request keeps its code and fixed message and
carries no ``data``, where the SDK would repeat the method name a client sent.
"""

import json
import logging
from collections.abc import Sequence
from typing import Any

import anyio.to_thread
from mcp.server import Server, ServerRequestContext
from mcp.server.context import CallNext, HandlerResult
from mcp.shared.exceptions import MCPError
from mcp.types import (
    INVALID_PARAMS,
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
    ToolAnnotations,
)
from pydantic import ValidationError

from vulnwitness.distribution import read_installed_version
from vulnwitness.domain.served_dataset import ServedDatasetKind
from vulnwitness.domain.tool_contracts import ToolFailure, ToolFailureCode
from vulnwitness.interfaces.knowledge_toolbox import KnowledgeToolbox
from vulnwitness.interfaces.knowledge_tools import (
    KNOWLEDGE_TOOL_SPECS,
    SERVER_INSTRUCTIONS,
    KnowledgeToolName,
    ToolAnswer,
    ToolSpec,
    build_tool_failure,
)
from vulnwitness.interfaces.mcp.session_calls import record_tool_call
from vulnwitness.ports.session_recording import SessionRecording
from vulnwitness.schema_snapshots import render_schema

SERVER_NAME = "vulnwitness"
UNKNOWN_TOOL_MESSAGE = "unknown tool"
# The SDK's sentence for parameters that fail its request model.
INVALID_PARAMETERS_MESSAGE = "Invalid request parameters"
# Tools only read deployment knowledge. An operator-selected session records transport
# facts privately; no tool exposes a write to the knowledge data or to authored findings.
READ_ONLY_ANNOTATIONS = ToolAnnotations(
    read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
)
# The default lifespan's state, which no handler reads.
LifespanState = dict[str, Any]


class KnowledgeToolHandlers:
    """The ``tools/list`` and ``tools/call`` handlers over one toolbox and its listing."""

    def __init__(
        self,
        toolbox: KnowledgeToolbox | None,
        tools: tuple[Tool, ...],
        recorder: SessionRecording | None = None,
    ) -> None:
        self._recorder = recorder
        self._toolbox = toolbox
        self._tools = tools

    def publish_toolbox(self, toolbox: KnowledgeToolbox) -> None:
        """Make a fully built toolbox available to subsequent calls."""
        self._toolbox = toolbox

    async def list_tools(
        self,
        ctx: ServerRequestContext[LifespanState],
        params: PaginatedRequestParams | None,
    ) -> ListToolsResult:
        """The available tools, in one page."""
        return ListToolsResult(tools=list(self._tools))

    async def call_tool(
        self, ctx: ServerRequestContext[LifespanState], params: CallToolRequestParams
    ) -> CallToolResult:
        """The toolbox's answer as structured content and its JSON text, or its failure as
        an error result. While loading, every call is a ``data_loading`` failure. Once
        loaded, a name that is not one of the available tools is a JSON-RPC invalid
        params error with a fixed message, which never repeats the name."""
        tool_outcome: ToolAnswer | ToolFailure
        if self._recorder is not None:
            tool_outcome = await anyio.to_thread.run_sync(
                record_tool_call, self._recorder, self._toolbox, params.name, params.arguments
            )
        elif self._toolbox is None:
            tool_outcome = build_tool_failure(ToolFailureCode.DATA_LOADING)
        else:
            try:
                tool_name = KnowledgeToolName(params.name)
            except ValueError:
                raise MCPError(INVALID_PARAMS, UNKNOWN_TOOL_MESSAGE) from None
            try:
                tool_outcome = await anyio.to_thread.run_sync(
                    self._toolbox.call, tool_name, params.arguments
                )
            except Exception:
                logging.getLogger(__name__).error(
                    "knowledge tool %s failed outside the toolbox", tool_name.value, exc_info=True
                )
                tool_outcome = build_tool_failure(ToolFailureCode.INTERNAL_ERROR)
        if isinstance(tool_outcome, ToolFailure):
            return CallToolResult(
                content=[TextContent(type="text", text=tool_outcome.model_dump_json())],
                is_error=True,
                structured_content=(
                    tool_outcome.model_dump(mode="json") if self._recorder is not None else None
                ),
            )
        return CallToolResult(
            content=[TextContent(type="text", text=tool_outcome.json_text)],
            structured_content=tool_outcome.structured_content,
            is_error=False,
        )


async def withhold_error_data(
    ctx: ServerRequestContext[LifespanState], call_next: CallNext
) -> HandlerResult:
    """Server middleware: an error raised while handling a request reaches the client
    with its code and message only. The SDK's own messages are fixed sentences, and so is
    every one this server raises, but its ``data`` can be the client's text, such as the
    name of a method the server does not serve. Parameters that fail the SDK's request
    model are the SDK's fixed invalid-params error."""
    try:
        return await call_next(ctx)
    except MCPError as error:
        raise MCPError(error.error.code, error.error.message) from None
    except ValidationError:
        raise MCPError(INVALID_PARAMS, INVALID_PARAMETERS_MESSAGE) from None


def build_mcp_tools(tool_specs: Sequence[ToolSpec]) -> tuple[Tool, ...]:
    """Each tool as listed: its description, the committed snapshot of its request contract
    as the input schema and of its response contract as the output schema, and the
    read-only annotations."""
    tools: list[Tool] = []
    for tool_spec in tool_specs:
        tools.append(
            Tool(
                name=tool_spec.name.value,
                description=tool_spec.description,
                input_schema=json.loads(render_schema(tool_spec.request_model, "validation")),
                output_schema=json.loads(render_schema(tool_spec.response_model, "serialization")),
                annotations=READ_ONLY_ANNOTATIONS,
            )
        )
    return tuple(tools)


def build_knowledge_mcp_server(
    toolbox: KnowledgeToolbox, recorder: SessionRecording | None = None
) -> Server[LifespanState]:
    """A server answering ``tools/list`` and ``tools/call`` over ``toolbox``; the listing is
    built once, here."""
    handlers = KnowledgeToolHandlers(toolbox, build_mcp_tools(KNOWLEDGE_TOOL_SPECS), recorder)
    return build_mcp_server(handlers, toolbox.describe_served_dataset().kind)


def build_mcp_server(
    handlers: KnowledgeToolHandlers, dataset_kind: ServedDatasetKind
) -> Server[LifespanState]:
    """Build the static protocol surface independently of toolbox availability."""
    server: Server[LifespanState] = Server(
        SERVER_NAME,
        version=read_installed_version(),
        instructions=SERVER_INSTRUCTIONS[dataset_kind],
        on_list_tools=handlers.list_tools,
        on_call_tool=handlers.call_tool,
    )
    server.middleware.append(withhold_error_data)
    return server
