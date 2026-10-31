"""Serves the knowledge tools over MCP Streamable HTTP on a loopback address, behind the
HTTP guard (ADR 0007). Loaded only through the ``mcp_http_server`` entry point of the
``cve_kgrag.adapters`` group.

The MCP endpoint is ``POST /mcp``: stateless, every answer one JSON body, so the server
holds no session and a deadline never cuts a stream. ``/health`` answers without the
token; ``/ready`` and ``/mcp`` require it. The guard checks Host and Origin itself, so
the SDK's own check is off rather than a second, differently worded refusal, and what
the SDK answers is restated in the server's words (``SdkAnswersRestated``).
"""

from contextlib import AbstractAsyncContextManager

from mcp.server.streamable_http_manager import (
    StreamableHTTPASGIApp,
    StreamableHTTPSessionManager,
)
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import SecretStr
from starlette.applications import Starlette

from cve_kgrag.interfaces.http.guard import DEFAULT_BODY_CAP_BYTES, GuardedRoute, HttpGuard
from cve_kgrag.interfaces.http.serving import find_request_deadline_seconds, serve
from cve_kgrag.interfaces.http.status_routes import (
    HEALTH_PATH,
    READY_PATH,
    ReadinessRoute,
    answer_health,
)
from cve_kgrag.interfaces.knowledge_toolbox import KnowledgeToolbox
from cve_kgrag.interfaces.mcp.sdk_answers import SdkAnswersRestated
from cve_kgrag.interfaces.mcp.server import build_knowledge_mcp_server

MCP_PATH = "/mcp"


class SessionManagerLifespan:
    """The app's lifespan: the session manager runs while the server does."""

    def __init__(self, session_manager: StreamableHTTPSessionManager) -> None:
        self._session_manager = session_manager

    def __call__(self, app: Starlette) -> AbstractAsyncContextManager[None]:
        return self._session_manager.run()


def build_mcp_http_app(
    toolbox: KnowledgeToolbox, *, host: str, port: int, token: SecretStr
) -> HttpGuard:
    """The guarded app serving ``toolbox``'s tools at ``/mcp`` for a server on ``host``
    and ``port``. ``/ready`` answers 204 while the toolbox has a free worker. The request
    deadline is ``find_request_deadline_seconds``."""
    session_manager = StreamableHTTPSessionManager(
        app=build_knowledge_mcp_server(toolbox),
        json_response=True,
        stateless=True,
        security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        max_request_body_size=DEFAULT_BODY_CAP_BYTES,
    )
    routes = {
        MCP_PATH: GuardedRoute(
            methods=frozenset({"POST"}),
            app=SdkAnswersRestated(StreamableHTTPASGIApp(session_manager)),
        ),
        HEALTH_PATH: GuardedRoute(methods=frozenset({"GET"}), app=answer_health, is_open=True),
        READY_PATH: GuardedRoute(
            methods=frozenset({"GET"}), app=ReadinessRoute(toolbox.has_free_worker)
        ),
    }
    return HttpGuard(
        routes=routes,
        lifespan_app=Starlette(lifespan=SessionManagerLifespan(session_manager)),
        host=host,
        port=port,
        token=token,
        request_deadline_seconds=find_request_deadline_seconds(toolbox.limits),
    )


def serve_http(toolbox: KnowledgeToolbox, *, host: str, port: int, token: SecretStr) -> bool:
    """Serve ``toolbox``'s tools over MCP Streamable HTTP until the process is
    interrupted; ``False`` when the server could not start."""
    return serve(
        build_mcp_http_app(toolbox, host=host, port=port, token=token),
        host,
        port,
        command="mcp --http",
    )
