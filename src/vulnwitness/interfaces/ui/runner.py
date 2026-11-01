"""Optional api-extra runner for the local browser interface."""

import logging
from collections.abc import Callable

from pydantic import SecretStr
from starlette.applications import Starlette

from vulnwitness.interfaces.http.serving import UVICORN_LOGGER, build_server_config
from vulnwitness.interfaces.mcp_deployment import McpDeployment
from vulnwitness.interfaces.ui.app import build_ui_app
from vulnwitness.interfaces.ui.lifespan import UiLifespan
from vulnwitness.interfaces.ui.server import UiServer
from vulnwitness.interfaces.ui.state import UiState


def serve_ui(load_deployment: Callable[[], McpDeployment], *, port: int, token: SecretStr) -> int:
    """Serve until interrupted, with exit 1 for binding or dataset-loading failure."""
    state = UiState()
    guard = build_ui_app(
        state,
        port=port,
        token=token,
        lifespan_app=Starlette(lifespan=UiLifespan(state, load_deployment)),
    )
    logging.getLogger(UVICORN_LOGGER).setLevel(logging.ERROR)
    server = UiServer(
        build_server_config(guard, "127.0.0.1", port), state, token.get_secret_value()
    )
    try:
        server.run()
    except KeyboardInterrupt:
        pass
    except SystemExit:
        return 1
    return 0 if server.started and not state.failed else 1
