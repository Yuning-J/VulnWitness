"""Fixtures shared by the interface tests; this file imports no optional extra, so the
core-only lane loads it too."""

import pytest


@pytest.fixture
def anyio_backend() -> str:
    """The async tests run on asyncio, the loop uvicorn serves on."""
    return "asyncio"
