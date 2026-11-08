"""Handshake over stdio before loading the knowledge tools, until the client disconnects.
Loaded through the ``mcp_server`` entry point of ``vulnwitness.adapters``.
"""

import asyncio
import sys
import threading
import time
from collections.abc import Callable

import anyio
from mcp.server import ServerRequestContext
from mcp.server.context import CallNext, HandlerResult
from mcp.server.stdio import stdio_server
from mcp.types.version import MODERN_PROTOCOL_VERSIONS

from vulnwitness.domain.served_dataset import ServedDatasetKind
from vulnwitness.interfaces.knowledge_tools import KNOWLEDGE_TOOL_SPECS
from vulnwitness.interfaces.mcp.server import (
    KnowledgeToolHandlers,
    LifespanState,
    build_mcp_server,
    build_mcp_tools,
)
from vulnwitness.interfaces.mcp.stdio_connection import StdioConnection
from vulnwitness.interfaces.mcp.stdio_input import StdioInput
from vulnwitness.interfaces.mcp.stdio_reader import StdioReader
from vulnwitness.interfaces.mcp_deployment import McpDeployment


class StdioServer:
    """Publish one complete deployment after initialization; cancel startup on disconnect."""

    def __init__(
        self,
        load_deployment: Callable[[], McpDeployment],
        dataset_kind: ServedDatasetKind,
        recording_enabled: bool = False,
        workspace_enabled: bool = False,
    ) -> None:
        self._load_deployment = load_deployment
        self._handlers = KnowledgeToolHandlers(
            None,
            build_mcp_tools(KNOWLEDGE_TOOL_SPECS, workspace_enabled),
            recording_enabled=recording_enabled,
            workspace_enabled=workspace_enabled,
        )
        self._server = build_mcp_server(self._handlers, dataset_kind)
        self._initialized = anyio.Event()
        self._stdin_closed = anyio.Event()
        self._server.middleware.append(self.observe_initialization)
        self._loop = asyncio.get_running_loop()
        self._loaded: asyncio.Future[McpDeployment | int] = self._loop.create_future()
        self._exit_code = 0

    async def observe_initialization(
        self, ctx: ServerRequestContext[LifespanState], call_next: CallNext
    ) -> HandlerResult:
        """Start loading after protocol negotiation, including the initialize acknowledgment."""
        protocol_answer = await call_next(ctx)
        if (
            ctx.method == "notifications/initialized"
            or ctx.protocol_version in MODERN_PROTOCOL_VERSIONS
        ):
            self._initialized.set()
        return protocol_answer

    def load_in_background(self) -> None:
        """The loader thread never keeps a disconnected client process alive."""
        try:
            deployment_or_exit: McpDeployment | int = self._load_deployment()
        except SystemExit as error:
            deployment_or_exit = error.code if isinstance(error.code, int) and error.code else 1
        except BaseException:
            print("vulnwitness mcp cannot start: data loading failed", file=sys.stderr, flush=True)
            deployment_or_exit = 1
        try:
            self._loop.call_soon_threadsafe(self.finish_loading, deployment_or_exit)
        except RuntimeError:
            # A disconnected client can close the event loop before the loader finishes.
            return

    def finish_loading(self, deployment_or_exit: McpDeployment | int) -> None:
        """Deliver startup completion only while the connection is still waiting."""
        if not self._loaded.done():
            self._loaded.set_result(deployment_or_exit)

    async def load(self, cancel_scope: anyio.CancelScope, stdin: StdioInput | None) -> None:
        """Load once after negotiation, then publish the deployment or stop on failure."""
        await self._initialized.wait()
        if stdin is not None:
            # Consume the client's queued input before starting work for an idle connection.
            await stdin.wait_until_idle()
        if self._stdin_closed.is_set():
            return
        started_at = time.monotonic()
        threading.Thread(target=self.load_in_background, daemon=True).start()
        deployment_or_exit = await self._loaded
        if isinstance(deployment_or_exit, int):
            self._exit_code = deployment_or_exit
            cancel_scope.cancel()
            return
        if self._stdin_closed.is_set():
            return
        cnvd_attribution = deployment_or_exit.toolbox.describe_cnvd_attribution()
        if cnvd_attribution is not None:
            self._server.instructions = f"{self._server.instructions} {cnvd_attribution}"
        self._handlers.publish_deployment(deployment_or_exit)
        print(
            "vulnwitness mcp: "
            f"{deployment_or_exit.toolbox.describe_served_dataset().cve_search_version} "
            f"ready after {time.monotonic() - started_at:.0f} s",
            file=sys.stderr,
            flush=True,
        )

    async def run(
        self,
        *,
        stdin: anyio.AsyncFile[str] | None = None,
        stdout: anyio.AsyncFile[str] | None = None,
    ) -> int:
        """Serve until stdin closes or startup fails, returning the process exit code."""
        process_stdin = None
        if stdin is None:
            process_stdin = StdioInput(sys.stdin, self._stdin_closed)
            stdin = process_stdin
        reader = StdioReader(stdin)
        # Loader failure cancels the session, while the outer transport drains stdout.
        async with (
            stdio_server(stdin=reader, stdout=stdout) as (read_stream, write_stream),
            anyio.create_task_group() as tasks,
        ):
            tasks.start_soon(self.load, tasks.cancel_scope, process_stdin)
            connection = StdioConnection(read_stream, write_stream, self._stdin_closed)
            try:
                await self._server.run(
                    connection, connection, self._server.create_initialization_options()
                )
            finally:
                reader.stop()
            tasks.cancel_scope.cancel()
        return self._exit_code


async def run_stdio_server(
    load_deployment: Callable[[], McpDeployment],
    dataset_kind: ServedDatasetKind,
    recording_enabled: bool = False,
    workspace_enabled: bool = False,
) -> int:
    return await StdioServer(
        load_deployment, dataset_kind, recording_enabled, workspace_enabled
    ).run()


def serve_stdio(
    load_deployment: Callable[[], McpDeployment],
    *,
    dataset_kind: ServedDatasetKind,
    recording_enabled: bool = False,
    workspace_enabled: bool = False,
) -> int:
    """Serve static metadata immediately, then publish ``load_deployment``'s dependencies."""
    try:
        return anyio.run(
            run_stdio_server, load_deployment, dataset_kind, recording_enabled, workspace_enabled
        )
    except KeyboardInterrupt:
        return 0
