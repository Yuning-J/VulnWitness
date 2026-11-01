"""Guarded UI routes and packaged pages, served from one loopback process."""

from pydantic import SecretStr
from starlette.applications import Starlette
from starlette.types import ASGIApp

from vulnwitness.domain.data_readiness import MAX_WAIT_SECONDS
from vulnwitness.domain.triage import TriageLimits
from vulnwitness.interfaces.http.guard import GuardedRoute, HttpGuard
from vulnwitness.interfaces.http.serving import REQUEST_DEADLINE_MARGIN_SECONDS
from vulnwitness.interfaces.knowledge_tools import ToolLimits
from vulnwitness.interfaces.ui.api_route import Operation, UiApiRoute
from vulnwitness.interfaces.ui.report_navigation import ReportNavigationRoute
from vulnwitness.interfaces.ui.state import UiState
from vulnwitness.interfaces.ui.static_route import StaticRoute


def build_ui_app(
    state: UiState,
    *,
    port: int,
    token: SecretStr,
    lifespan_app: ASGIApp | None = None,
) -> HttpGuard:
    """Public assets carry no workspace text; every data endpoint requires the launch token."""
    get_only = frozenset({"GET"})
    post_only = frozenset({"POST"})
    routes = {}
    for path, filename, media_type in (
        ("/", "start.html", "text/html"),
        ("/investigations/", "detail.html", "text/html"),
        ("/ui.js", "ui.js", "text/javascript"),
        ("/ui.css", "ui.css", "text/css"),
    ):
        routes[path] = GuardedRoute(
            methods=get_only,
            app=StaticRoute(filename, media_type),
            is_open=True,
            takes_path_segment=path.endswith("/") and path != "/",
        )
    routes["/reports/"] = GuardedRoute(
        methods=post_only,
        app=ReportNavigationRoute(state, token),
        is_open=True,
        takes_path_segment=True,
    )
    operations: tuple[Operation, ...] = (
        "wait",
        "list",
        "triage",
        "start",
        "get",
        "view",
        "lookup",
        "investigate",
        "call",
        "check",
        "render",
        "report",
    )
    for operation in operations:
        has_segment = operation in {"get", "view", "report"}
        path = "/ui-api/" + operation + ("/" if has_segment else "")
        routes[path] = GuardedRoute(
            methods=get_only if has_segment or operation == "list" else post_only,
            app=UiApiRoute(state, operation),
            takes_path_segment=has_segment,
        )
    return HttpGuard(
        routes=routes,
        lifespan_app=lifespan_app or Starlette(),
        host="127.0.0.1",
        port=port,
        token=token,
        request_deadline_seconds=max(
            TriageLimits().time_limit, ToolLimits().find_longest_call_seconds(), MAX_WAIT_SECONDS
        )
        + REQUEST_DEADLINE_MARGIN_SECONDS,
    )
