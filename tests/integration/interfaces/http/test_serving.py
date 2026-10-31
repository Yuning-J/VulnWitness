"""CLI HTTP readiness describes a serving socket, and data loading alone is not ready."""

import signal
import subprocess
from collections.abc import Iterator
from pathlib import Path

import httpx2
import pytest

from cve_kgrag.cli import main
from tests.support.asgi import AUTHORIZATION
from tests.support.corpus_stores import import_store
from tests.support.process_servers import (
    CVE_KGRAG_SCRIPT,
    SERVER_START_SECONDS,
    build_server_environment,
    find_free_loopback_port,
    run_on_a_port_in_use,
)
from tests.support.stdio_client import read_until_notice


@pytest.fixture(
    params=[(["api"], "CVE_KGRAG_API_PORT"), (["mcp", "--http"], "CVE_KGRAG_MCP_HTTP_PORT")]
)
def http_command(request: pytest.FixtureRequest) -> tuple[list[str], str]:
    command: tuple[list[str], str] = request.param
    return command


@pytest.fixture
def store_settings(tmp_path: Path) -> dict[str, str]:
    store_root = tmp_path / "stores"
    store_root.mkdir()
    import_store(store_root, "first")
    settings = {"CVE_KGRAG_STORE_ROOT": str(store_root)}
    assert main(["store", "activate", "first"], settings) == 0
    return settings


@pytest.fixture
def starting_server(
    http_command: tuple[list[str], str], store_settings: dict[str, str]
) -> Iterator[tuple[subprocess.Popen[str], str]]:
    arguments, port_variable = http_command
    host = "127.0.0.1"
    port = find_free_loopback_port(host)
    server_process = subprocess.Popen(
        [str(CVE_KGRAG_SCRIPT), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**build_server_environment(port_variable, host, port), **store_settings},
    )
    try:
        yield server_process, f"http://{host}:{port}"
    finally:
        if server_process.poll() is None:
            server_process.kill()
        server_process.communicate(timeout=SERVER_START_SECONDS)


@pytest.mark.anyio
async def test_ready_notice_names_a_serving_port_after_the_data_loaded_notice(
    starting_server: tuple[subprocess.Popen[str], str], http_command: tuple[list[str], str]
) -> None:
    server_process, server_url = starting_server
    arguments, _ = http_command
    command = " ".join(arguments)
    assert server_process.stderr is not None

    notices = await read_until_notice(server_process.stderr, b" ready on ")
    ready_answer = httpx2.get(f"{server_url}/ready", headers=AUTHORIZATION)
    server_process.send_signal(signal.SIGINT)
    stdout, stderr = server_process.communicate(timeout=SERVER_START_SECONDS)

    assert ready_answer.status_code == 204
    notice_lines = notices.decode().splitlines()
    assert len(notice_lines) == 3
    assert notice_lines[0] == (
        f"cve-kgrag {command}: loading store first; a full NVD store takes minutes"
    )
    assert " data loaded after " in notice_lines[1]
    assert "ready" not in notice_lines[1]
    assert notice_lines[2] == f"cve-kgrag {command}: ready on {server_url}"
    assert server_process.returncode == 0
    assert stdout == ""
    assert stderr == ""


def test_bind_failure_exits_nonzero_after_loading_without_a_ready_notice(
    http_command: tuple[list[str], str], store_settings: dict[str, str]
) -> None:
    arguments, port_variable = http_command

    server_process = run_on_a_port_in_use(arguments, port_variable, store_settings)

    assert server_process.returncode == 1
    assert server_process.stdout == b""
    assert b" data loaded after " in server_process.stderr
    assert b": ready " not in server_process.stderr
    assert b" ready after " not in server_process.stderr
    assert b"address already in use" in server_process.stderr
