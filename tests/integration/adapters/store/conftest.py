"""Fixtures for the store tests."""

from pathlib import Path

import pytest


@pytest.fixture
def store_root(tmp_path: Path) -> Path:
    """An empty store root, its parent free for the stores' inputs."""
    store_root = tmp_path / "stores"
    store_root.mkdir()
    return store_root
