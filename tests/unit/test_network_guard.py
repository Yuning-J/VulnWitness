"""The test-time network guard refuses connects outside loopback and allows loopback."""

import errno
import os
import socket
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.support.network_guard import NetworkGuard, NonLoopbackConnectRefused
from tests.support.paths import REPOSITORY_ROOT

# TEST-NET-1 (RFC 5737): reserved for documentation, never routed.
DOCUMENTATION_ADDRESS = ("192.0.2.1", 80)


@pytest.fixture
def loopback_listener() -> Iterator[socket.socket]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    yield listener
    listener.close()


def test_connect_outside_loopback_is_refused_and_recorded(network_guard: NetworkGuard) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        # Should the guard ever let the connect through, it fails fast instead of hanging.
        connection.settimeout(1)
        with pytest.raises(NonLoopbackConnectRefused):
            connection.connect(DOCUMENTATION_ADDRESS)

    assert network_guard.refused_addresses == [DOCUMENTATION_ADDRESS]


def test_create_connection_outside_loopback_is_refused(network_guard: NetworkGuard) -> None:
    with pytest.raises(OSError):
        socket.create_connection(DOCUMENTATION_ADDRESS, timeout=1)

    assert network_guard.refused_addresses == [DOCUMENTATION_ADDRESS]


def test_connect_ex_outside_loopback_returns_an_error_code(network_guard: NetworkGuard) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(1)
        error_code = connection.connect_ex(DOCUMENTATION_ADDRESS)

    assert error_code == errno.ENETUNREACH
    assert network_guard.refused_addresses == [DOCUMENTATION_ADDRESS]


def test_connect_to_loopback_is_allowed(
    network_guard: NetworkGuard, loopback_listener: socket.socket
) -> None:
    with socket.create_connection(loopback_listener.getsockname(), timeout=1) as connection:
        peer = connection.getpeername()

    assert peer == loopback_listener.getsockname()
    assert network_guard.refused_addresses == []


def test_test_module_connecting_at_import_fails_collection_with_the_guard(
    tmp_path: Path,
) -> None:
    probe = tmp_path / "test_import_time_probe.py"
    probe.write_text(
        "import socket\n"
        "socket.create_connection(('192.0.2.1', 80), timeout=1)\n"
        "\n"
        "def test_never_runs():\n"
        "    pass\n",
        encoding="utf-8",
    )
    # The live-test opt-in is the one variable that turns the guard off.
    environment = dict(os.environ)
    environment.pop("VULNWITNESS_LIVE_TESTS", None)

    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "tests.conftest", str(probe)],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert completed.returncode == pytest.ExitCode.INTERRUPTED
    assert "NonLoopbackConnectRefused" in completed.stdout
