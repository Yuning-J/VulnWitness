"""A controlled deployment loader for HTTP startup tests, using real demo services."""

import threading

from vulnwitness.interfaces.mcp_deployment import McpDeployment


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
