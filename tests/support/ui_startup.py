"""A controlled deployment loader for HTTP startup tests, using real demo services."""

import threading
from pathlib import Path

from starlette.applications import Starlette

from tests.support.asgi import HTTP_PORT, HTTP_SECRET_TOKEN
from tests.support.workspaces import build_test_workspace
from vulnwitness.interfaces.mcp_deployment import McpDeployment
from vulnwitness.interfaces.ui.app import build_ui_app
from vulnwitness.interfaces.ui.state import UiState
from vulnwitness.ports.served_corpus import ServedCorpus


def build_test_ui_app(root: Path, *, corpus: ServedCorpus | None = None) -> Starlette:
    """Expose real workspace recording and report views through the guarded UI boundary."""
    toolbox, workspace = build_test_workspace(root, corpus=corpus)
    return build_ui_app(
        UiState(McpDeployment(toolbox, workspace=workspace)),
        port=HTTP_PORT,
        token=HTTP_SECRET_TOKEN,
    )


class DeferredUiDeployment:
    def __init__(self, deployment: McpDeployment) -> None:
        self.deployment = deployment
        self.entered = threading.Event()
        self.release = threading.Event()

    def load(self) -> McpDeployment:
        self.entered.set()
        if not self.release.wait(10):
            raise TimeoutError("test did not release deployment")
        return self.deployment
