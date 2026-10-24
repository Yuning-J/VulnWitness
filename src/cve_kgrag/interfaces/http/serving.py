"""Runs an ASGI app under uvicorn on a loopback address, configured so the server adds
nothing a caller could use: no proxy headers trusted, no server banner, no access log
(it would record request targets), one HTTP parser chosen, no WebSocket support."""

import logging
import math

import uvicorn

from cve_kgrag.interfaces.http.guard import HttpGuard

# uvicorn answers its own 503 to a request arriving while this many connections (its own
# included) or requests are open. It refuses no connection: an open connection with
# unfinished headers stays open until the client closes it.
MAX_CONNECTIONS = 32
# uvicorn's logger; its warnings are per request (an upgrade it does not serve, a request
# it cannot parse, the 503 above), so any local caller could fill the log with them. Its
# errors, a port it cannot bind or an app that raised, stay.
UVICORN_LOGGER = "uvicorn.error"
KEEP_ALIVE_SECONDS = 5


def find_graceful_shutdown_seconds(guard: HttpGuard) -> int:
    """How long a stop waits for requests in flight: past the guard's request deadline,
    so every request ends with its route's answer or the guard's 504 rather than being
    cut off by uvicorn."""
    return math.ceil(guard.request_deadline_seconds) + 1


def build_server_config(guard: HttpGuard, host: str, port: int) -> uvicorn.Config:
    """The uvicorn configuration for ``guard`` on ``host`` and ``port``. It sets no logging
    configuration, so uvicorn logs through the handlers the command installed."""
    return uvicorn.Config(
        guard,
        host=host,
        port=port,
        http="h11",
        ws="none",
        lifespan="on",
        interface="asgi3",
        proxy_headers=False,
        server_header=False,
        access_log=False,
        log_config=None,
        limit_concurrency=MAX_CONNECTIONS,
        timeout_keep_alive=KEEP_ALIVE_SECONDS,
        timeout_graceful_shutdown=find_graceful_shutdown_seconds(guard),
    )


def serve(guard: HttpGuard, host: str, port: int) -> bool:
    """Serve ``guard`` until the process is interrupted, which stops it once the requests
    in flight have ended (a second interrupt stops it at once); ``False`` when it could not
    start serving, such as on a port it cannot bind, after uvicorn has logged why."""
    logging.getLogger(UVICORN_LOGGER).setLevel(logging.ERROR)
    try:
        uvicorn.Server(build_server_config(guard, host, port)).run()
    except KeyboardInterrupt:
        return True
    except SystemExit:
        # uvicorn exits the process when its startup fails; the command decides the status.
        return False
    return True
