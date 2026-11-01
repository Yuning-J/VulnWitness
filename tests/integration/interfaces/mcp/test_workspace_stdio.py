"""Workspace CLI admission and the complete agent flow through real stdio."""

import os
import sys
from pathlib import Path

import pytest
from mcp import StdioServerParameters

from tests.support.stdio_client import observe_stdio_client, read_until_notice
from vulnwitness.cli import main


@pytest.mark.anyio
async def test_stdio_triage_report_retry_and_later_recorded_call_have_expected_statuses(
    tmp_path: Path,
) -> None:
    # Arrange
    environment: dict[str, str] = {}
    for name, value in os.environ.items():
        if not name.startswith("VULNWITNESS_"):
            environment[name] = value
    root = tmp_path / "workspace"
    server = StdioServerParameters(
        command=str(Path(sys.executable).parent / "vulnwitness"),
        args=["mcp", "--workspace", str(root)],
        env=environment,
    )
    arguments = {"vendor": "democorp", "request_key": "stdio-triage"}
    async with observe_stdio_client(server) as (client, stderr):
        await read_until_notice(stderr, b" ready after ")

        # Act
        triage = await client.call_tool("triage_product", arguments)
        session_id = triage.structured_content["session_id"]
        retry = await client.call_tool("triage_product", arguments)
        report = await client.call_tool(
            "render_report", {"session_id": session_id, "format": "html"}
        )
        checked = await client.call_tool("check_investigation", {"session_id": session_id})
        await client.call_tool("lookup_cve", {"session_id": session_id, "cve_id": "CVE-9999-0001"})
        snapshot = await client.call_tool("get_investigation", {"session_id": session_id})

    # Assert
    assert triage.structured_content["outcome"] == "complete"
    assert retry.structured_content == triage.structured_content
    assert report.structured_content["report"] == "current"
    assert checked.structured_content["record"]["consistent"]
    assert snapshot.structured_content["report"] == "stale"
    assert root.stat().st_mode & 0o777 == 0o700
    assert (root / session_id / "report.html").is_file()


def test_symlink_workspace_root_is_refused_before_loading(tmp_path: Path) -> None:
    # Arrange
    target = tmp_path / "target"
    target.mkdir()
    root = tmp_path / "workspace"
    root.symlink_to(target, target_is_directory=True)

    # Act
    with pytest.raises(SystemExit) as refused:
        main(["mcp", "--workspace", str(root)], environment={})

    # Assert
    assert refused.value.code == 2
    assert list(target.iterdir()) == []


@pytest.mark.parametrize("store_exists", [True, False])
def test_workspace_inside_store_is_refused_before_loading(
    tmp_path: Path, store_exists: bool
) -> None:
    # Arrange
    store = tmp_path / "store"
    if store_exists:
        store.mkdir()
    root = store / "workspace"

    # Act
    with pytest.raises(SystemExit) as refused:
        main(["mcp", "--workspace", str(root)], environment={"VULNWITNESS_STORE_ROOT": str(store)})

    # Assert
    assert refused.value.code == 2
    assert not root.exists()


def test_session_and_workspace_are_mutually_exclusive(tmp_path: Path) -> None:
    # Arrange
    root = tmp_path / "workspace"
    session = tmp_path / "session"

    # Act
    with pytest.raises(SystemExit) as refused:
        main(["mcp", "--workspace", str(root), "--session", str(session)], environment={})

    # Assert
    assert refused.value.code == 2
    assert not root.exists() and not session.exists()
