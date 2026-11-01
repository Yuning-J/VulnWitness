"""Private workspace admission and atomic findings size limits (ADR 0013)."""

import json
import os
import random
import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from pydantic import ValidationError

from tests.support.clocks import read_fixed_clock
from tests.support.workspaces import PausingClock, agent_note, build_test_workspace
from vulnwitness.adapters.session.workspace_files import LocalWorkspaceFiles
from vulnwitness.composition import (
    build_knowledge_toolbox,
    build_serving_data_plane,
    load_packaged_fixture,
)
from vulnwitness.domain.session_record import SessionRecordingError
from vulnwitness.domain.tool_contracts import ToolFailureCode
from vulnwitness.domain.workspace import (
    MAX_FINDING_STATEMENT_BYTES,
    MAX_FINDINGS_PER_BATCH,
    MAX_WORKSPACE_FINDINGS_BYTES,
    AddFindingsRequest,
    InvestigationRequest,
    StartInvestigationRequest,
)
from vulnwitness.workspace_composition import build_workspace_investigations


@pytest.mark.parametrize("mode", [0o720, 0o702, 0o770])
def test_writable_workspace_root_is_refused_without_chmod(tmp_path: Path, mode: int) -> None:
    # Arrange
    root = tmp_path / "workspace"
    root.mkdir(mode=0o700)
    root.chmod(mode)

    # Act
    with pytest.raises(ValueError, match="group or other writable"):
        LocalWorkspaceFiles(root)

    # Assert
    assert root.stat().st_mode & 0o777 == mode
    assert list(root.iterdir()) == []


def test_workspace_root_owned_by_another_user_is_refused(tmp_path: Path) -> None:
    # Arrange
    root = tmp_path / "workspace"
    root.mkdir(mode=0o700)
    try:
        os.chown(root, os.getuid() + 1, -1)
    except PermissionError:
        pytest.skip("Changing filesystem ownership requires root on this host")

    # Act
    try:
        with pytest.raises(ValueError, match="owned by the current user"):
            LocalWorkspaceFiles(root)
    finally:
        os.chown(root, os.getuid(), -1)

    # Assert
    assert list(root.iterdir()) == []


@pytest.mark.parametrize("unsafe_directory", ["root", "investigation"])
def test_permissions_changed_after_start_refuse_appends_without_writes(
    tmp_path: Path, unsafe_directory: str
) -> None:
    # Arrange
    root = tmp_path / "workspace"
    _, workspace = build_test_workspace(root)
    session_id = workspace.start(StartInvestigationRequest(goal="Permission admission")).session_id
    directory = root / session_id
    original = (directory / "findings.yaml").read_bytes()
    unsafe = root if unsafe_directory == "root" else directory
    unsafe.chmod(0o770)
    request = AddFindingsRequest.model_validate(
        {"session_id": session_id, "findings": [agent_note("refused")]}
    )

    # Act
    with pytest.raises(ValueError, match="group or other writable"):
        workspace.add_findings(request)
    with pytest.raises(ValueError, match="group or other writable"):
        workspace.record(session_id, "get_knowledge_capabilities", {})

    # Assert
    assert (directory / "findings.yaml").read_bytes() == original
    assert list((directory / "calls").iterdir()) == []


def test_static_investigation_symlink_is_refused_without_outside_writes(tmp_path: Path) -> None:
    # Arrange
    root = tmp_path / "workspace"
    _, workspace = build_test_workspace(root)
    session_id = workspace.start(StartInvestigationRequest(goal="Static symlink")).session_id
    directory = root / session_id
    outside = tmp_path / "outside"
    directory.rename(outside)
    directory.symlink_to(outside, target_is_directory=True)

    # Act
    with pytest.raises(SessionRecordingError) as refused:
        workspace.record(session_id, "get_knowledge_capabilities", {})

    # Assert
    assert refused.value.code == ToolFailureCode.UNKNOWN_INVESTIGATION
    assert list((outside / "calls").iterdir()) == []


@pytest.mark.skip(
    reason="ADR 0013 threat model excludes concurrent directory swaps by the same user, "
    "who can modify records directly; pathname checks do not pin directories"
)
def test_same_user_symlink_swap_can_redirect_an_admitted_recorder(tmp_path: Path) -> None:
    """Review reproduction: pause the injected clock after writer admission, then swap."""
    # Arrange
    root = tmp_path / "workspace"
    plane = build_serving_data_plane(load_packaged_fixture(), clock=read_fixed_clock)
    toolbox = build_knowledge_toolbox(plane)
    clock = PausingClock()
    workspace = build_workspace_investigations(
        root, plane, toolbox, clock=clock.read, random_bytes=random.Random(7).randbytes
    )
    session_id = workspace.start(StartInvestigationRequest(goal="Concurrent swap")).session_id
    directory = root / session_id
    outside = tmp_path / "outside"
    shutil.copytree(directory, outside)
    clock.armed = True

    # Act
    with ThreadPoolExecutor(max_workers=1) as workers:
        pending = workers.submit(workspace.record, session_id, "get_knowledge_capabilities", {})
        assert clock.entered.wait(10)
        try:
            directory.rename(tmp_path / "original")
            directory.symlink_to(outside, target_is_directory=True)
        finally:
            clock.release.set()
        answer = pending.result(timeout=10)

    # Assert
    assert type(answer).__name__ == "ToolAnswer"
    assert (outside / "responses/0001.json").is_file()
    assert json.loads((outside / "calls/0001.json").read_text())["outcome"] == "ok"
    assert list((tmp_path / "original/calls").iterdir()) == []


@pytest.mark.parametrize("character", ["x", "é"])
def test_oversized_statement_is_refused_without_writing(tmp_path: Path, character: str) -> None:
    # Arrange
    root = tmp_path / "workspace"
    _, workspace = build_test_workspace(root)
    session_id = workspace.start(StartInvestigationRequest(goal="Statement size")).session_id
    path = root / session_id / "findings.yaml"
    original = path.read_bytes()
    statement = character * (MAX_FINDING_STATEMENT_BYTES // len(character.encode()) + 1)

    # Act
    with pytest.raises(ValidationError):
        request = AddFindingsRequest.model_validate(
            {"session_id": session_id, "findings": [agent_note("large", statement=statement)]}
        )
        workspace.add_findings(request)

    # Assert
    assert path.read_bytes() == original


@pytest.mark.parametrize(
    "count,statement", [(MAX_FINDINGS_PER_BATCH + 1, "note"), (130, "x" * 8192)]
)
def test_oversized_batch_is_refused_without_writing(
    tmp_path: Path, count: int, statement: str
) -> None:
    # Arrange
    root = tmp_path / "workspace"
    _, workspace = build_test_workspace(root)
    session_id = workspace.start(StartInvestigationRequest(goal="Batch size")).session_id
    path = root / session_id / "findings.yaml"
    original = path.read_bytes()
    findings = []
    for index in range(count):
        findings.append(agent_note(str(index), statement=statement))

    # Act
    with pytest.raises(ValidationError):
        request = AddFindingsRequest.model_validate(
            {"session_id": session_id, "findings": findings}
        )
        workspace.add_findings(request)

    # Assert
    assert path.read_bytes() == original


def test_combined_findings_limit_refuses_batch_and_allows_later_small_append(
    tmp_path: Path,
) -> None:
    # Arrange
    root = tmp_path / "workspace"
    _, workspace = build_test_workspace(root)
    session_id = workspace.start(
        StartInvestigationRequest(goal="Combined findings size")
    ).session_id
    path = root / session_id / "findings.yaml"
    # Synthetic operator-authored content is readable and leaves room for a small append.
    existing = {
        "findings": [],
        "selections": {"cve_ids": [], "product_queries": []},
        "open_questions": ["x" * (MAX_WORKSPACE_FINDINGS_BYTES - 4096)],
    }
    path.write_text(json.dumps(existing))
    original = path.read_bytes()
    oversized = AddFindingsRequest.model_validate(
        {"session_id": session_id, "findings": [agent_note("large", statement="x" * 8192)]}
    )
    small = AddFindingsRequest.model_validate(
        {"session_id": session_id, "findings": [agent_note("small")]}
    )

    # Act
    with pytest.raises(SessionRecordingError) as refused:
        workspace.add_findings(oversized)
    after_refusal = path.read_bytes()
    appended = workspace.add_findings(small)
    snapshot = workspace.get(InvestigationRequest(session_id=session_id))

    # Assert
    assert refused.value.code == ToolFailureCode.FINDINGS_TOO_LARGE
    assert after_refusal == original
    assert appended.written and appended.ids_written == ("small",)
    assert snapshot.record.consistent and snapshot.effective_findings == 1
    assert path.stat().st_size <= MAX_WORKSPACE_FINDINGS_BYTES
