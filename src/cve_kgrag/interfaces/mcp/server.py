"""The knowledge tools as an MCP server: the SDK's low-level ``Server`` with only the tool
handlers registered, so it advertises tools and nothing else (ADR 0003 §6).

Each tool's listed input and output schema is the committed contract snapshot. A call is
handed to ``KnowledgeToolbox.call`` on a worker thread, so the event loop never blocks;
every failure is answered as a ``ToolFailure`` with a fixed message, never exception text.
"""

import importlib.metadata
import json
import logging
from collections.abc import Sequence
from typing import Any

import anyio.to_thread
from mcp.server import Server, ServerRequestContext
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

from cve_kgrag.domain.tool_contracts import ToolFailure, ToolFailureCode
from cve_kgrag.interfaces.knowledge_toolbox import KnowledgeToolbox
from cve_kgrag.interfaces.knowledge_tools import (
    KNOWLEDGE_TOOL_SPECS,
    SERVER_INSTRUCTIONS,
    KnowledgeToolName,
    ToolSpec,
    build_tool_failure,
)
from cve_kgrag.schema_snapshots import render_schema

SERVER_NAME = "cve-kgrag"
DISTRIBUTION_NAME = "cve-kgrag"
UNKNOWN_TOOL_MESSAGE = "unknown tool"
# Every tool only reads the deployment's packaged sources: it changes nothing, answers an
# equal request equally, and reaches no system outside the deployment.
READ_ONLY_ANNOTATIONS = ToolAnnotations(
    read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
)
# The default lifespan's state, which no handler reads.
LifespanState = dict[str, Any]


class KnowledgeToolHandlers:
    """The ``tools/list`` and ``tools/call`` handlers over one toolbox and its listing."""

    def __init__(self, toolbox: KnowledgeToolbox, tools: tuple[Tool, ...]) -> None:
        self._toolbox = toolbox
        self._tools = tools

    async def list_tools(
        self,
        ctx: ServerRequestContext[LifespanState],
        params: PaginatedRequestParams | None,
    ) -> ListToolsResult:
        """The eight tools, in one page."""
        return ListToolsResult(tools=list(self._tools))

    async def call_tool(
        self, ctx: ServerRequestContext[LifespanState], params: CallToolRequestParams
    ) -> CallToolResult:
        """The toolbox's answer as structured content and its JSON text, or its failure as
        an error result. A name that is not one of the eight tools is a JSON-RPC invalid
        params error with a fixed message, which never repeats the name."""
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
            )
        return CallToolResult(
            content=[TextContent(type="text", text=tool_outcome.json_text)],
            structured_content=tool_outcome.structured_content,
            is_error=False,
        )


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


def build_knowledge_mcp_server(toolbox: KnowledgeToolbox) -> Server[LifespanState]:
    """A server answering ``tools/list`` and ``tools/call`` over ``toolbox``; the listing is
    built once, here."""
    handlers = KnowledgeToolHandlers(toolbox, build_mcp_tools(KNOWLEDGE_TOOL_SPECS))
    return Server(
        SERVER_NAME,
        version=importlib.metadata.version(DISTRIBUTION_NAME),
        instructions=SERVER_INSTRUCTIONS,
        on_list_tools=handlers.list_tools,
        on_call_tool=handlers.call_tool,
    )
