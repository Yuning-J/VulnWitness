"""Publish the same complete workspace deployment used by MCP."""

from vulnwitness.interfaces.data_readiness import DataReadiness
from vulnwitness.interfaces.mcp_deployment import McpDeployment


class UiState:
    """One launch's dependencies; publication happens on the server event loop."""

    def __init__(self, deployment: McpDeployment | None = None) -> None:
        self.readiness = DataReadiness()
        self.deployment: McpDeployment | None = None
        self.failed = False
        if deployment is not None:
            self.publish(deployment)

    def publish(self, deployment: McpDeployment) -> None:
        if deployment.workspace is None:
            raise ValueError("UI requires workspace investigations")
        self.deployment = deployment
        self.readiness.publish()
