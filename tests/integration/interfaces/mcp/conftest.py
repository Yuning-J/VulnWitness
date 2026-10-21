"""Fixtures for the MCP server tests, which need the ``mcp`` extra. The core-only lane
leaves this directory out with an explicit ``--ignore``."""

from collections.abc import AsyncIterator
from typing import Any

import pytest
from mcp import Client
from mcp.server import Server

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.interfaces.mcp.server import build_knowledge_mcp_server
from tests.support.toolbox import build_test_toolbox


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(params=["auto", "legacy"])
def client_mode(request: pytest.FixtureRequest) -> str:
    """How the client connects: the 2026 discover path, or the initialize handshake."""
    client_mode: str = request.param
    return client_mode


@pytest.fixture
def knowledge_mcp_server(fixture_bundle: FixtureBundle) -> Server[Any]:
    """The server over the production toolbox wiring, with the disabled Trustify adapter,
    the fixed wall clock and the real monotonic clock bounding each call."""
    return build_knowledge_mcp_server(build_test_toolbox(fixture_bundle))


@pytest.fixture
async def mcp_client(knowledge_mcp_server: Server[Any], client_mode: str) -> AsyncIterator[Client]:
    """An in-process client connected to ``knowledge_mcp_server`` in ``client_mode``."""
    async with Client(knowledge_mcp_server, mode=client_mode) as client:
        yield client
