"""Workspace service composition with packaged data and controllable clocks."""

import random
import threading
from datetime import datetime
from pathlib import Path

from tests.support.clocks import read_fixed_clock
from vulnwitness.application.workspace_investigations import WorkspaceInvestigations
from vulnwitness.composition import (
    build_knowledge_toolbox,
    build_serving_data_plane,
    load_packaged_fixture,
)
from vulnwitness.interfaces.knowledge_toolbox import KnowledgeToolbox
from vulnwitness.ports.served_corpus import ServedCorpus
from vulnwitness.workspace_composition import build_workspace_investigations


def build_test_workspace(
    root: Path, *, corpus: ServedCorpus | None = None, **options: object
) -> tuple[KnowledgeToolbox, WorkspaceInvestigations]:
    plane = build_serving_data_plane(
        corpus if corpus is not None else load_packaged_fixture(), clock=read_fixed_clock
    )
    toolbox = build_knowledge_toolbox(plane)
    service = build_workspace_investigations(
        root,
        plane,
        toolbox,
        clock=read_fixed_clock,
        random_bytes=random.Random(7).randbytes,
        **options,
    )
    return toolbox, service


def agent_note(finding_id: str, **fields: object) -> dict[str, object]:
    finding: dict[str, object] = {
        "id": finding_id,
        "kind": "analyst_note",
        "status": "unconfirmed",
        "statement": "Deployment applicability remains unknown.",
        "citations": [],
    }
    finding.update(fields)
    return finding


class PausingClock:
    """Pause one admitted recorder call while another MCP call tests the lock."""

    def __init__(self) -> None:
        self.armed = False
        self.entered = threading.Event()
        self.release = threading.Event()

    def read(self) -> datetime:
        if self.armed:
            self.armed = False
            self.entered.set()
            if not self.release.wait(10):
                raise TimeoutError("test did not release clock")
        return read_fixed_clock()
