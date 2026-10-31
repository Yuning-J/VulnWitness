"""Observe stdio startup notices while driving the server with the SDK client."""

import os
import select
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import BinaryIO, TextIO

import anyio
from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client


async def read_until_notice(stderr: TextIO, notice: bytes) -> bytes:
    """Read stderr through ``notice`` with a deadline, without blocking the test runner."""
    notices = b""
    with anyio.fail_after(10):
        while notice not in notices or not notices.endswith(b"\n"):
            await anyio.wait_readable(stderr.fileno())
            chunk = os.read(stderr.fileno(), 65536)
            if not chunk:
                raise AssertionError(f"server stopped before {notice!r}: {notices!r}")
            notices += chunk
    return notices


@asynccontextmanager
async def observe_stdio_client(
    parameters: StdioServerParameters, *, mode: str = "legacy"
) -> AsyncIterator[tuple[Client, TextIO]]:
    """A real stdio client and the server's stderr, closed together on test exit."""
    read_descriptor, write_descriptor = os.pipe()
    with (
        os.fdopen(read_descriptor) as stderr_reader,
        os.fdopen(write_descriptor, "w") as stderr_writer,
    ):
        async with Client(stdio_client(parameters, errlog=stderr_writer), mode=mode) as client:
            yield client, stderr_reader


def read_process_line(stream: BinaryIO) -> bytes:
    """Read one subprocess line within five seconds, leaving later lines untouched."""
    line = b""
    deadline = time.monotonic() + 5
    while not line.endswith(b"\n"):
        remaining_seconds = deadline - time.monotonic()
        readable, _, _ = select.select([stream], [], [], max(0, remaining_seconds))
        if not readable:
            raise AssertionError(f"server did not finish its line: {line!r}")
        chunk = os.read(stream.fileno(), 1)
        if not chunk:
            raise AssertionError(f"server stopped before finishing its line: {line!r}")
        line += chunk
    return line
