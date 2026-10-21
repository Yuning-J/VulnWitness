"""Serves the knowledge tools over stdio until the client closes stdin. Loaded only through
the ``mcp_server`` entry point of the ``cve_kgrag.adapters`` group (ADR 0003 §11)."""

from typing import Any

import anyio
from mcp.server import Server
from mcp.server.stdio import stdio_server

from cve_kgrag.interfaces.knowledge_toolbox import KnowledgeToolbox
from cve_kgrag.interfaces.mcp.server import build_knowledge_mcp_server


async def run_stdio_server(server: Server[Any]) -> None:
    """Run ``server`` over this process's stdin and stdout until stdin closes."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def serve_stdio(toolbox: KnowledgeToolbox) -> None:
    """Serve ``toolbox``'s tools over stdio; returns when the client closes stdin."""
    anyio.run(run_stdio_server, build_knowledge_mcp_server(toolbox))
