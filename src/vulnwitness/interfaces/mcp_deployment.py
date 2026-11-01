"""The dataset-bound dependencies published together after MCP startup loading."""

from dataclasses import dataclass

from vulnwitness.application.workspace_investigations import WorkspaceInvestigations
from vulnwitness.interfaces.knowledge_toolbox import KnowledgeToolbox
from vulnwitness.ports.session_recording import SessionRecording


@dataclass(frozen=True)
class McpDeployment:
    toolbox: KnowledgeToolbox
    recorder: SessionRecording | None = None
    workspace: WorkspaceInvestigations | None = None
