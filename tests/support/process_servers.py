"""``cve-kgrag`` HTTP servers started as processes on a free loopback port, with no
cve-kgrag setting from the shell running the tests."""

import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import httpx2
import pytest

from tests.support.asgi import HTTP_TOKEN

# The console script of the environment running the tests.
CVE_KGRAG_SCRIPT = Path(sys.executable).parent / "cve-kgrag"
# The prefix of every setting the server reads (cve_kgrag.settings).
SETTINGS_PREFIX = "CVE_KGRAG_"
SERVER_START_SECONDS = 30.0


@dataclass(frozen=True)
class ServedHttp:
    """A running HTTP server process: the address it listens on and the process."""

    host: str
    port: int
    process: subprocess.Popen[bytes]

    @property
    def url(self) -> str:
        url_host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{url_host}:{self.port}"


def find_free_loopback_port(host: str) -> int:
    """A port free on ``host``; ``pytest.skip`` when the machine has no such address."""
    address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(address_family, socket.SOCK_STREAM) as probe_socket:
        try:
            probe_socket.bind((host, 0))
        except OSError:
            pytest.skip(f"no {host} loopback address on this machine")
        free_port: int = probe_socket.getsockname()[1]
        return free_port


def build_server_environment(port_variable: str, host: str, port: int) -> dict[str, str]:
    """The test process's environment without its cve-kgrag settings, plus the token,
    ``host`` and ``port`` in ``port_variable``."""
    server_environment: dict[str, str] = {}
    for variable_name, value in os.environ.items():
        if not variable_name.startswith(SETTINGS_PREFIX):
            server_environment[variable_name] = value
    server_environment["CVE_KGRAG_HTTP_TOKEN"] = HTTP_TOKEN
    server_environment["CVE_KGRAG_HTTP_HOST"] = host
    server_environment[port_variable] = str(port)
    return server_environment


def wait_until_healthy(server_url: str, server_process: subprocess.Popen[bytes]) -> None:
    started_at = time.monotonic()
    while time.monotonic() - started_at < SERVER_START_SECONDS:
        if server_process.poll() is not None:
            raise RuntimeError("the server exited before serving")
        try:
            health_status = httpx2.get(f"{server_url}/health").status_code
        except httpx2.TransportError:
            time.sleep(0.05)
            continue
        if health_status != 204:
            raise RuntimeError(f"/health answered {health_status}")
        return
    raise RuntimeError("the server did not start serving")


def run_on_a_port_in_use(
    command_arguments: Sequence[str], port_variable: str, settings: Mapping[str, str] | None = None
) -> subprocess.CompletedProcess[bytes]:
    """``cve-kgrag`` with ``command_arguments`` run against a loopback port another socket
    is listening on."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listening_socket:
        listening_socket.bind(("127.0.0.1", 0))
        listening_socket.listen()
        taken_port: int = listening_socket.getsockname()[1]
        return subprocess.run(
            [str(CVE_KGRAG_SCRIPT), *command_arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=SERVER_START_SECONDS,
            check=False,
            env={
                **build_server_environment(port_variable, "127.0.0.1", taken_port),
                **(settings or {}),
            },
        )


def start_served_http(
    command_arguments: Sequence[str], port_variable: str, host: str
) -> Iterator[ServedHttp]:
    """``cve-kgrag`` with ``command_arguments`` serving on a free port of ``host`` once it
    answers ``/health``; killed afterwards if it is still running. For a fixture to
    ``yield from``."""
    port = find_free_loopback_port(host)
    served = ServedHttp(
        host=host,
        port=port,
        process=subprocess.Popen(
            [str(CVE_KGRAG_SCRIPT), *command_arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=build_server_environment(port_variable, host, port),
        ),
    )
    try:
        wait_until_healthy(served.url, served.process)
        yield served
    finally:
        if served.process.poll() is None:
            served.process.kill()
        served.process.communicate(timeout=SERVER_START_SECONDS)
