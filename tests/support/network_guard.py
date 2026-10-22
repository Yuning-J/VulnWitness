"""A socket guard for tests: only loopback and Unix-socket connects are allowed.

The default lanes promise to need no external service; the guard makes a test that would
reach one fail instead of passing on a machine that happens to be online.
"""

import errno
import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass, field

ConnectFunction = Callable[[socket.socket, object], object]


class NonLoopbackConnectRefused(OSError):
    """A test tried to connect to an address outside loopback."""


@dataclass
class NetworkGuard:
    loopback_connect: ConnectFunction
    loopback_connect_ex: ConnectFunction
    refused_addresses: list[object] = field(default_factory=list)


def is_loopback_address(address: object) -> bool:
    """True for a loopback IP address, `localhost`, or a Unix socket path."""
    if isinstance(address, str | bytes):
        return True
    if not isinstance(address, tuple) or not address:
        return False
    host = address[0]
    if not isinstance(host, str):
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def guarded_connect(connection: socket.socket, guard: NetworkGuard, address: object) -> object:
    if not is_loopback_address(address):
        guard.refused_addresses.append(address)
        raise NonLoopbackConnectRefused(
            errno.ENETUNREACH, f"tests may connect to loopback only, not {address!r}"
        )
    return guard.loopback_connect(connection, address)


def guarded_connect_ex(connection: socket.socket, guard: NetworkGuard, address: object) -> object:
    if not is_loopback_address(address):
        guard.refused_addresses.append(address)
        return errno.ENETUNREACH
    return guard.loopback_connect_ex(connection, address)
