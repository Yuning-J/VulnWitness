"""Controllable fixture loaders behind the production stdio and guarded HTTP helpers."""

import os
import sys
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import partial
from pathlib import Path

import anyio
import httpx2
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client

from tests.support.asgi import (
    AUTHORIZATION,
    HTTP_HOST,
    HTTP_PORT,
    HTTP_SECRET_TOKEN,
    SERVER_URL,
    running_lifespan,
)
from tests.support.clocks import read_fixed_clock
from tests.support.stdio_client import observe_stdio_client, read_until_notice
from vulnwitness.adapters.session.recorder import SessionRecorder
from vulnwitness.composition import (
    build_knowledge_toolbox,
    build_serving_data_plane,
    load_packaged_fixture,
)
from vulnwitness.domain.served_dataset import ServedDatasetKind
from vulnwitness.interfaces.knowledge_tools import KNOWLEDGE_TOOL_SPECS
from vulnwitness.interfaces.mcp.http_runner import build_mcp_http_transport
from vulnwitness.interfaces.mcp.server import (
    KnowledgeToolHandlers,
    build_mcp_server,
    build_mcp_tools,
)
from vulnwitness.interfaces.mcp_deployment import McpDeployment
from vulnwitness.workspace_composition import build_workspace_investigations


@dataclass(frozen=True)
class WaitingClient:
    client: Client
    release: Callable[[], None]
    root: Path
    mode: str


def release_stdio_loader(release_path: Path) -> None:
    with release_path.open("wb") as release:
        release.write(b"1")


async def load_http_deployment(
    handlers: KnowledgeToolHandlers, release: anyio.Event, root: Path, mode: str
) -> None:
    """Load only the synthetic fixture, once the test's release signal arrives."""
    await release.wait()
    plane = build_serving_data_plane(load_packaged_fixture(), clock=read_fixed_clock)
    toolbox = build_knowledge_toolbox(plane)
    workspace = None
    recorder = None
    if mode == "workspace":
        workspace = build_workspace_investigations(root, plane, toolbox, clock=read_fixed_clock)
    elif mode == "recording":
        recorder = SessionRecorder(root, plane.session_dataset, read_fixed_clock)
    handlers.publish_deployment(McpDeployment(toolbox, recorder, workspace))


@asynccontextmanager
async def connect_waiting_client(
    directory: Path, transport: str, mode: str, protocol: str
) -> AsyncIterator[WaitingClient]:
    root = directory / mode
    if transport == "stdio":
        release_path = directory / "release"
        os.mkfifo(release_path)
        arguments = ["-m", "tests.support.stdio_startup", str(release_path), "none"]
        if mode != "plain":
            arguments.extend(["--workspace" if mode == "workspace" else "--session", str(root)])
        environment: dict[str, str] = {}
        for name, value in os.environ.items():
            if not name.startswith("VULNWITNESS_"):
                environment[name] = value
        parameters = StdioServerParameters(command=sys.executable, args=arguments, env=environment)
        async with observe_stdio_client(parameters, mode=protocol) as (client, stderr):
            await client.list_tools()
            await read_until_notice(stderr, b"test: loader blocked")
            yield WaitingClient(client, partial(release_stdio_loader, release_path), root, mode)
        return
    release = anyio.Event()
    handlers = KnowledgeToolHandlers(
        None,
        build_mcp_tools(KNOWLEDGE_TOOL_SPECS, mode == "workspace"),
        recording_enabled=mode == "recording",
        workspace_enabled=mode == "workspace",
    )
    app = build_mcp_http_transport(
        build_mcp_server(handlers, ServedDatasetKind.SYNTHETIC_FIXTURE),
        has_free_worker=release.is_set,
        request_deadline_seconds=70,
        host=HTTP_HOST,
        port=HTTP_PORT,
        token=HTTP_SECRET_TOKEN,
    )
    async with anyio.create_task_group() as tasks:
        tasks.start_soon(load_http_deployment, handlers, release, root, mode)
        async with (
            running_lifespan(app),
            httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app), headers=AUTHORIZATION
            ) as http,
            Client(
                streamable_http_client(f"{SERVER_URL}/mcp", http_client=http), mode=protocol
            ) as client,
        ):
            yield WaitingClient(client, release.set, root, mode)
        tasks.cancel_scope.cancel()
