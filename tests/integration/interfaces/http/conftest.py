"""Fixtures for the HTTP guard tests, which need the ASGI stack of the ``mcp`` extra. The
core-only lane leaves this directory out with an explicit ``--ignore``."""

import pytest


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
