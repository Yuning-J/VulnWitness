"""Injected interruption after one genuine recorded MCP call."""

from contextlib import nullcontext

from tests.support.clocks import read_fixed_clock
from vulnwitness.adapters.session.recorder import SessionRecorder
from vulnwitness.adapters.session.workspace_files import LocalWorkspaceFiles
from vulnwitness.application.serving_data_plane import ServingDataPlane
from vulnwitness.domain.triage import TriageLimits
from vulnwitness.domain.workspace import TriageProductRequest
from vulnwitness.interfaces.knowledge_toolbox import KnowledgeToolbox
from vulnwitness.interfaces.mcp.session_calls import record_tool_call


def interrupt_triage(
    files: LocalWorkspaceFiles,
    plane: ServingDataPlane,
    toolbox: KnowledgeToolbox,
    session_id: str,
    request: TriageProductRequest,
    limits: TriageLimits,
) -> None:
    recorder = SessionRecorder(
        files.resolve(session_id),
        plane.session_dataset,
        read_fixed_clock,
        lock=nullcontext,
        allow_incomplete_triage=True,
        record_response_digest=True,
    )
    record_tool_call(recorder, toolbox, "get_knowledge_capabilities", {})
    raise RuntimeError("simulated interruption")


class FilesystemAccessTrap:
    """Any access fails, proving validation completes before the filesystem boundary."""

    def __getattr__(self, name: str) -> object:
        raise AssertionError("invalid input reached storage")
