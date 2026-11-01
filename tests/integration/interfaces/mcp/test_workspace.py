"""Workspace outcomes through real MCP sessions over in-process and HTTP transports."""

import asyncio
import json
from collections.abc import AsyncIterator
from functools import partial
from pathlib import Path
from typing import Any

import httpx2
import pytest
import yaml
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from tests.support.asgi import (
    AUTHORIZATION,
    HTTP_HOST,
    HTTP_PORT,
    HTTP_SECRET_TOKEN,
    SERVER_URL,
    running_lifespan,
)
from tests.support.clocks import SteppingClock, read_fixed_clock
from tests.support.workspace_crash import FilesystemAccessTrap, interrupt_triage
from tests.support.workspaces import PausingClock, agent_note, build_test_workspace
from vulnwitness.adapters.session.files import hold_session_lock
from vulnwitness.adapters.session.recorder import SessionRecorder
from vulnwitness.adapters.session.workspace_files import LocalWorkspaceFiles
from vulnwitness.application.workspace_investigations import WorkspaceInvestigations
from vulnwitness.composition import (
    build_knowledge_toolbox,
    build_serving_data_plane,
    load_packaged_fixture,
)
from vulnwitness.domain.session_record import SessionRecord
from vulnwitness.domain.workspace import TriageStarted
from vulnwitness.interfaces.knowledge_tools import KNOWLEDGE_TOOL_SPECS, ToolLimits
from vulnwitness.interfaces.mcp.http_runner import build_mcp_http_app
from vulnwitness.interfaces.mcp.server import build_knowledge_mcp_server
from vulnwitness.interfaces.mcp.workspace_tools import WORKSPACE_TOOL_SPECS
from vulnwitness.schema_snapshots import render_schema
from vulnwitness.workspace_composition import (
    build_workspace_investigations,
    render_workspace_report,
)

pytestmark = pytest.mark.anyio


@pytest.fixture(params=["in_process", "http"])
async def workspace_client(tmp_path: Path, request: pytest.FixtureRequest) -> AsyncIterator[Client]:
    toolbox, workspace = build_test_workspace(tmp_path / "workspace")
    if request.param == "in_process":
        async with Client(build_knowledge_mcp_server(toolbox, workspace=workspace)) as client:
            yield client
        return
    app = build_mcp_http_app(
        toolbox, host=HTTP_HOST, port=HTTP_PORT, token=HTTP_SECRET_TOKEN, workspace=workspace
    )
    async with (
        running_lifespan(app),
        httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), headers=AUTHORIZATION) as http,
        Client(streamable_http_client(f"{SERVER_URL}/mcp", http_client=http)) as client,
    ):
        yield client


async def start(client: Client, **arguments: Any) -> dict[str, Any]:
    return (
        await client.call_tool("start_investigation", {"goal": "Review demo", **arguments})
    ).structured_content


async def test_oversized_workspace_arguments_are_refused_on_each_transport(
    workspace_client: Client,
) -> None:
    # Arrange
    arguments = {"padding": "x" * ToolLimits().max_argument_bytes}
    refusals = []

    # Act
    for spec in WORKSPACE_TOOL_SPECS:
        refusals.append(await workspace_client.call_tool(spec.name, arguments))
    listing = await workspace_client.call_tool("list_investigations", {})

    # Assert
    for refusal in refusals:
        assert refusal.is_error
        assert refusal.structured_content["code"] == "arguments_too_large"
    assert listing.structured_content["investigations"] == []


async def test_triage_get_render_check_keeps_typed_outcome_and_current_report(
    workspace_client: Client,
) -> None:
    # Arrange
    arguments = {"vendor": "democorp", "lookups": 1}

    # Act
    triage = await workspace_client.call_tool("triage_product", arguments)
    session_id = triage.structured_content["session_id"]
    snapshot = await workspace_client.call_tool("get_investigation", {"session_id": session_id})
    rendered = await workspace_client.call_tool(
        "render_report", {"session_id": session_id, "format": "md"}
    )
    checked = await workspace_client.call_tool("check_investigation", {"session_id": session_id})
    current = await workspace_client.call_tool("get_investigation", {"session_id": session_id})

    # Assert
    assert triage.structured_content["outcome"] == "complete"
    assert "exit_code" not in triage.structured_content
    assert snapshot.structured_content["workflow"] == "complete"
    assert checked.structured_content["record"]["consistent"]
    assert current.structured_content["report"] == "current"
    assert rendered.structured_content["input_digest"] in rendered.structured_content["markdown"]
    assert (
        Path(rendered.structured_content["local_path"]).read_text()
        == rendered.structured_content["markdown"]
    )


async def test_later_recorded_call_makes_report_stale(workspace_client: Client) -> None:
    # Arrange
    investigation = await start(workspace_client)
    session_id = investigation["session_id"]
    await workspace_client.call_tool("render_report", {"session_id": session_id})

    # Act
    await workspace_client.call_tool(
        "lookup_cve", {"session_id": session_id, "cve_id": "CVE-9999-0001"}
    )
    snapshot = await workspace_client.call_tool("get_investigation", {"session_id": session_id})

    # Assert
    assert snapshot.structured_content["report"] == "stale"
    assert "session_id" not in snapshot.structured_content["calls"][0]["request"]


async def test_saved_call_returns_exact_bytes_and_refuses_oversized_response(
    workspace_client: Client, tmp_path: Path
) -> None:
    # Arrange
    session_id = (await start(workspace_client))["session_id"]
    await workspace_client.call_tool(
        "lookup_cve", {"session_id": session_id, "cve_id": "CVE-9999-0001"}
    )
    path = tmp_path / "workspace" / session_id / "responses/0001.json"
    original = path.read_bytes()

    # Act
    saved = await workspace_client.call_tool("read_call", {"session_id": session_id, "call": 1})
    path.write_bytes(b" " * (1024 * 1024 + 1))
    refused = await workspace_client.call_tool("read_call", {"session_id": session_id, "call": 1})

    # Assert
    assert saved.structured_content["response_json"].encode() == original
    assert (
        json.loads(saved.structured_content["response_json"])["candidates"][0]["record"]["cve_id"]
        == "CVE-9999-0001"
    )
    assert (
        refused.is_error and refused.structured_content["failure"]["code"] == "response_too_large"
    )
    assert refused.structured_content["call"]["sequence"] == 1
    assert refused.structured_content["response_json"] is None


async def test_request_key_retry_reuses_record_without_new_calls_and_rejects_conflict(
    workspace_client: Client,
) -> None:
    # Arrange
    arguments = {"vendor": "democorp", "lookups": 1, "request_key": "triage.1"}
    first = await workspace_client.call_tool("triage_product", arguments)

    # Act
    second = await workspace_client.call_tool("triage_product", arguments)
    conflict = await workspace_client.call_tool("triage_product", {**arguments, "lookups": 2})

    # Assert
    assert second.structured_content == first.structured_content
    assert conflict.is_error and conflict.structured_content["code"] == "request_key_conflict"


async def test_concurrent_request_key_creations_produce_one_investigation(
    workspace_client: Client,
) -> None:
    # Arrange / Act
    first, second = await asyncio.gather(
        start(workspace_client, request_key="shared"), start(workspace_client, request_key="shared")
    )
    listing = await workspace_client.call_tool("list_investigations", {})

    # Assert
    assert first["session_id"] == second["session_id"]
    assert len(listing.structured_content["investigations"]) == 1


async def test_findings_batch_is_atomic_and_retry_ids_are_safe(
    workspace_client: Client, tmp_path: Path
) -> None:
    # Arrange
    session_id = (await start(workspace_client))["session_id"]
    first = agent_note("first")
    path = tmp_path / "workspace" / session_id / "findings.yaml"

    # Act
    added = await workspace_client.call_tool(
        "add_findings", {"session_id": session_id, "findings": [first]}
    )
    original = path.read_bytes()
    retry = await workspace_client.call_tool(
        "add_findings", {"session_id": session_id, "findings": [first]}
    )
    conflict = await workspace_client.call_tool(
        "add_findings",
        {
            "session_id": session_id,
            "findings": [agent_note("second"), agent_note("first", statement="different")],
        },
    )
    shape = await workspace_client.call_tool(
        "add_findings",
        {
            "session_id": session_id,
            "findings": [agent_note("third"), agent_note("bad", kind="record_fact")],
        },
    )

    # Assert
    assert added.structured_content["written"]
    assert not retry.structured_content["written"] and retry.structured_content["ids_written"] == []
    assert conflict.is_error and conflict.structured_content["code"] == "finding_id_conflict"
    assert shape.is_error and shape.structured_content["code"] == "invalid_arguments"
    assert path.read_bytes() == original
    assert yaml.safe_load(original)["findings"][0]["author"] == "agent"


async def test_wrong_citation_and_contradicted_claim_are_written_with_failed_checks(
    workspace_client: Client,
) -> None:
    # Arrange
    triage = (
        await workspace_client.call_tool("triage_product", {"vendor": "democorp", "lookups": 0})
    ).structured_content
    session_id = triage["session_id"]
    wrong_citation = agent_note(
        "bad-citation", citations=[{"call": 2, "evidence_id": "ev:" + "0" * 24}]
    )
    wrong_claim = {
        "id": "bad-claim",
        "kind": "product_field_match",
        "status": "confirmed",
        "citations": [],
        "claim": {
            "kind": "product_field_match",
            "call": 2,
            "cve_id": triage["triage"]["inventory"]["cve_ids"][0],
            "vendor": "wrong",
            "product": "wrong",
        },
    }

    # Act
    added = await workspace_client.call_tool(
        "add_findings", {"session_id": session_id, "findings": [wrong_citation, wrong_claim]}
    )

    # Assert
    assert not added.is_error and added.structured_content["written"]
    assert not added.structured_content["batch_check"]["citations"]["resolved"]
    assert (
        added.structured_content["batch_check"]["claims"]["checks"][0]["status"] == "contradicted"
    )
    assert not added.structured_content["check"]["claims"]["verified"]


async def test_supersedes_changes_effective_checks_and_report(workspace_client: Client) -> None:
    # Arrange
    session_id = (await start(workspace_client))["session_id"]
    await workspace_client.call_tool(
        "add_findings",
        {"session_id": session_id, "findings": [agent_note("old", statement="Obsolete note.")]},
    )

    # Act
    revision = await workspace_client.call_tool(
        "add_findings",
        {"session_id": session_id, "findings": [agent_note("new", supersedes="old")]},
    )
    report = await workspace_client.call_tool(
        "render_report", {"session_id": session_id, "format": "md"}
    )
    snapshot = await workspace_client.call_tool("get_investigation", {"session_id": session_id})

    # Assert
    assert revision.structured_content["check"]["superseded_count"] == 1
    assert revision.structured_content["check"]["not_checked"]["finding_ids"] == ["new"]
    assert snapshot.structured_content["effective_findings"] == 1
    assert "Obsolete note." not in report.structured_content["markdown"]
    assert "Superseded findings: 1" in report.structured_content["markdown"]


async def test_unknown_call_rejects_entire_findings_batch(
    workspace_client: Client, tmp_path: Path
) -> None:
    # Arrange
    session_id = (await start(workspace_client))["session_id"]
    path = tmp_path / "workspace" / session_id / "findings.yaml"
    original = path.read_bytes()

    # Act
    refused = await workspace_client.call_tool(
        "add_findings",
        {
            "session_id": session_id,
            "findings": [
                agent_note("ok"),
                agent_note("bad", citations=[{"call": 1, "evidence_id": "ev:" + "0" * 24}]),
            ],
        },
    )

    # Assert
    assert refused.is_error and refused.structured_content["code"] == "invalid_arguments"
    assert path.read_bytes() == original


async def test_on_disk_response_and_findings_tampering_are_detected(
    workspace_client: Client, tmp_path: Path
) -> None:
    # Arrange
    session_id = (await start(workspace_client))["session_id"]
    await workspace_client.call_tool(
        "lookup_cve", {"session_id": session_id, "cve_id": "CVE-9999-0001"}
    )
    directory = tmp_path / "workspace" / session_id
    content = (directory / "responses/0001.json").read_bytes()

    # Act
    (directory / "responses/0001.json").write_bytes(content + b"\n")
    (directory / "findings.yaml").write_text("findings: malformed")
    checked = await workspace_client.call_tool("check_investigation", {"session_id": session_id})

    # Assert
    violations = checked.structured_content["record"]["violations"]
    assert not checked.structured_content["record"]["consistent"]
    assert any(violation["location"] == "responses/0001.json" for violation in violations)
    assert any(violation["location"] == "findings.yaml" for violation in violations)


async def test_interrupted_triage_is_readable_and_refuses_appends(
    workspace_client: Client, tmp_path: Path
) -> None:
    # Arrange
    session_id = (await start(workspace_client, request_key="crashed"))["session_id"]
    directory = tmp_path / "workspace" / session_id
    session = SessionRecord.model_validate_json((directory / "session.json").read_bytes())
    (directory / "session.json").write_text(
        session.model_copy(
            update={"origin": "triage", "triage_request": {"vendor": "democorp"}}
        ).model_dump_json()
    )
    marker = TriageStarted(
        request={"vendor": "democorp"},
        started_at=read_fixed_clock(),
        remaining_steps=("product inventory",),
    )
    (directory / "triage.started.json").write_text(marker.model_dump_json())

    # Act
    snapshot = await workspace_client.call_tool("get_investigation", {"session_id": session_id})
    refused = await workspace_client.call_tool(
        "lookup_cve", {"session_id": session_id, "cve_id": "CVE-9999-0001"}
    )
    refused_findings = await workspace_client.call_tool(
        "add_findings", {"session_id": session_id, "findings": [agent_note("new")]}
    )

    # Assert
    assert snapshot.structured_content["workflow"] == "interrupted"
    assert snapshot.structured_content["remaining_steps"] == ["product inventory"]
    assert refused.structured_content["code"] == "investigation_interrupted"
    assert refused_findings.structured_content["code"] == "investigation_interrupted"
    assert list((directory / "calls").iterdir()) == []


@pytest.mark.parametrize(
    "session_id", ["../escape", "inv_" + "a" * 19, "/tmp/example", "inv_" + "a" * 20 + "\n"]
)
async def test_path_like_ids_are_rejected_before_storage_access(
    workspace_client: Client, tmp_path: Path, session_id: str
) -> None:
    # Arrange
    requests = list((tmp_path / "workspace").iterdir())

    # Act
    refused = await workspace_client.call_tool("get_investigation", {"session_id": session_id})

    # Assert
    assert refused.is_error and refused.structured_content["code"] == "invalid_arguments"
    assert list((tmp_path / "workspace").iterdir()) == requests


async def test_workspace_annotations_match_static_side_effect_contract(
    workspace_client: Client,
) -> None:
    # Arrange / Act
    listing = await workspace_client.list_tools()

    # Assert
    read_only = {
        "get_investigation",
        "read_call",
        "check_investigation",
        "list_investigations",
        "wait_for_data",
    }
    idempotent = read_only | {"render_report"}
    assert len(listing.tools) == 18
    for tool in listing.tools:
        assert tool.annotations.read_only_hint == (tool.name in read_only)
        assert tool.annotations.idempotent_hint == (tool.name in idempotent)
        assert tool.annotations.destructive_hint is False
        assert tool.annotations.open_world_hint is False


async def test_quota_admission_under_lock_allows_only_one_concurrent_creation(
    tmp_path: Path,
) -> None:
    # Arrange
    toolbox, workspace = build_test_workspace(tmp_path / "workspace", workspace_limit=1)
    async with Client(build_knowledge_mcp_server(toolbox, workspace=workspace)) as client:
        # Act
        first, second = await asyncio.gather(
            client.call_tool("start_investigation", {"goal": "first"}),
            client.call_tool("start_investigation", {"goal": "second"}),
        )

    # Assert
    assert first.is_error != second.is_error
    refused = first if first.is_error else second
    assert refused.structured_content["code"] == "workspace_full"
    assert len(LocalWorkspaceFiles(tmp_path / "workspace").list_ids()) == 1


async def test_concurrent_knowledge_call_on_same_investigation_returns_busy(tmp_path: Path) -> None:
    # Arrange
    clock = PausingClock()
    plane = build_serving_data_plane(load_packaged_fixture(), clock=read_fixed_clock)
    toolbox = build_knowledge_toolbox(plane)
    workspace = build_workspace_investigations(
        tmp_path / "workspace", plane, toolbox, clock=clock.read
    )
    async with Client(build_knowledge_mcp_server(toolbox, workspace=workspace)) as client:
        session_id = (await start(client))["session_id"]
        clock.armed = True
        pending = asyncio.create_task(
            client.call_tool("lookup_cve", {"session_id": session_id, "cve_id": "CVE-9999-0001"})
        )
        assert await asyncio.to_thread(clock.entered.wait, 5)
        try:
            # Act
            busy = await client.call_tool(
                "lookup_cve", {"session_id": session_id, "cve_id": "CVE-9999-0002"}
            )
        finally:
            clock.release.set()
        completed = await pending

    # Assert
    assert busy.is_error and busy.structured_content["code"] == "investigation_busy"
    assert not completed.is_error


@pytest.mark.parametrize("recording", [False, True])
async def test_read_only_and_recording_schemas_and_annotations_stay_unchanged(
    tmp_path: Path, recording: bool
) -> None:
    # Arrange

    plane = build_serving_data_plane(load_packaged_fixture(), clock=read_fixed_clock)
    toolbox = build_knowledge_toolbox(plane)
    recorder = (
        SessionRecorder(tmp_path / "recording", plane.session_dataset, read_fixed_clock)
        if recording
        else None
    )
    async with Client(build_knowledge_mcp_server(toolbox, recorder=recorder)) as client:
        # Act
        listing = await client.list_tools()
        refused = await client.call_tool(
            "lookup_cve", {"session_id": "inv_" + "a" * 20, "cve_id": "CVE-9999-0001"}
        )

    # Assert
    assert len(listing.tools) == 10
    for tool, spec in zip(listing.tools[:-1], KNOWLEDGE_TOOL_SPECS, strict=True):
        assert tool.input_schema == json.loads(render_schema(spec.request_model, "validation"))
        assert tool.output_schema == json.loads(render_schema(spec.response_model, "serialization"))
        assert tool.annotations.read_only_hint and tool.annotations.idempotent_hint
    assert refused.is_error and refused.structured_content["code"] == "investigations_not_enabled"


async def test_direct_child_symlink_is_refused_without_reading_target(
    workspace_client: Client, tmp_path: Path
) -> None:
    # Arrange
    session_id = (await start(workspace_client))["session_id"]
    directory = tmp_path / "workspace" / session_id
    target = tmp_path / "outside"
    directory.rename(target)
    directory.symlink_to(target, target_is_directory=True)

    # Act
    refused = await workspace_client.call_tool("get_investigation", {"session_id": session_id})

    # Assert
    assert refused.is_error and refused.structured_content["code"] == "unknown_investigation"


async def test_unindexed_creation_is_listed_as_orphan(
    workspace_client: Client, tmp_path: Path
) -> None:
    # Arrange
    session_id = (await start(workspace_client, request_key="lost-index"))["session_id"]
    (tmp_path / "workspace" / "requests/lost-index.json").unlink()

    # Act
    listing = await workspace_client.call_tool("list_investigations", {})
    replacement = await start(workspace_client, request_key="lost-index")

    # Assert
    assert listing.structured_content["investigations"][0]["orphan"]
    assert listing.structured_content["investigations"][0]["session_id"] == session_id
    assert replacement["session_id"] != session_id


async def test_workspace_lock_timeout_returns_retryable_busy(
    workspace_client: Client, tmp_path: Path
) -> None:
    # Arrange
    files = LocalWorkspaceFiles(tmp_path / "workspace", lock_wait=0)
    with files.workspace_lock():
        # Act
        refused = await workspace_client.call_tool("start_investigation", {"goal": "Busy root"})

    # Assert
    assert refused.is_error and refused.structured_content["code"] == "workspace_busy"
    assert files.list_ids() == ()


async def test_busy_triage_lock_is_reported_as_running(
    workspace_client: Client, tmp_path: Path
) -> None:
    # Arrange
    session_id = (await start(workspace_client))["session_id"]
    directory = tmp_path / "workspace" / session_id
    session = SessionRecord.model_validate_json((directory / "session.json").read_bytes())
    (directory / "session.json").write_text(
        session.model_copy(update={"origin": "triage"}).model_dump_json()
    )
    with hold_session_lock(directory):
        # Act
        snapshot = await workspace_client.call_tool("get_investigation", {"session_id": session_id})
        refused = await workspace_client.call_tool(
            "check_investigation", {"session_id": session_id}
        )

    # Assert
    assert snapshot.structured_content["workflow"] == "running"
    assert refused.is_error and refused.structured_content["code"] == "investigation_busy"


@pytest.mark.parametrize(
    "vendor,select,outcome",
    [
        ("no-such-demo-vendor", [], "no_match"),
        ("democorp", ["CVE-9999-0999"], "failed"),
    ],
)
async def test_empty_inventory_and_invalid_selection_return_typed_outcomes(
    workspace_client: Client, vendor: str, select: list[str], outcome: str
) -> None:
    # Arrange / Act
    triage = await workspace_client.call_tool(
        "triage_product", {"vendor": vendor, "select": select}
    )

    # Assert
    assert not triage.is_error and triage.structured_content["outcome"] == outcome
    assert triage.structured_content["workflow"] == outcome


async def test_finding_append_makes_report_stale(workspace_client: Client) -> None:
    # Arrange
    session_id = (await start(workspace_client))["session_id"]
    await workspace_client.call_tool("render_report", {"session_id": session_id})

    # Act
    await workspace_client.call_tool(
        "add_findings", {"session_id": session_id, "findings": [agent_note("new")]}
    )
    snapshot = await workspace_client.call_tool("get_investigation", {"session_id": session_id})

    # Assert
    assert snapshot.structured_content["report"] == "stale"


async def test_lower_investigation_call_limit_is_enforced_before_append(tmp_path: Path) -> None:
    # Arrange
    toolbox, workspace = build_test_workspace(tmp_path / "workspace", call_limit=1)
    async with Client(build_knowledge_mcp_server(toolbox, workspace=workspace)) as client:
        session_id = (await start(client))["session_id"]
        await client.call_tool("lookup_cve", {"session_id": session_id, "cve_id": "CVE-9999-0001"})

        # Act
        refused = await client.call_tool(
            "lookup_cve", {"session_id": session_id, "cve_id": "CVE-9999-0002"}
        )
        snapshot = await client.call_tool("get_investigation", {"session_id": session_id})

    # Assert
    assert refused.is_error and refused.structured_content["code"] == "session_call_limit"
    assert len(snapshot.structured_content["calls"]) == 1


async def test_superseding_wrong_citation_removes_its_violation_from_effective_set(
    workspace_client: Client,
) -> None:
    # Arrange
    session_id = (await start(workspace_client))["session_id"]
    await workspace_client.call_tool(
        "lookup_cve", {"session_id": session_id, "cve_id": "CVE-9999-0001"}
    )
    await workspace_client.call_tool(
        "add_findings",
        {
            "session_id": session_id,
            "findings": [
                agent_note("wrong", citations=[{"call": 1, "evidence_id": "ev:" + "0" * 24}])
            ],
        },
    )

    # Act
    revision = await workspace_client.call_tool(
        "add_findings",
        {
            "session_id": session_id,
            "findings": [agent_note("revision", supersedes="wrong")],
        },
    )

    # Assert
    assert revision.structured_content["check"]["citations"]["resolved"]
    assert revision.structured_content["check"]["superseded_count"] == 1


@pytest.mark.parametrize("supersedes", ["missing", "new"])
async def test_unknown_or_self_supersession_rejects_atomic_batch(
    workspace_client: Client, tmp_path: Path, supersedes: str
) -> None:
    # Arrange
    session_id = (await start(workspace_client))["session_id"]
    path = tmp_path / "workspace" / session_id / "findings.yaml"
    original = path.read_bytes()

    # Act
    refused = await workspace_client.call_tool(
        "add_findings",
        {
            "session_id": session_id,
            "findings": [agent_note("otherwise-valid"), agent_note("new", supersedes=supersedes)],
        },
    )

    # Assert
    assert refused.is_error and refused.structured_content["code"] == "invalid_arguments"
    assert path.read_bytes() == original


async def test_crash_retains_call_and_identical_retry_never_reexecutes(tmp_path: Path) -> None:
    # Arrange
    root = tmp_path / "workspace"
    files = LocalWorkspaceFiles(root)
    plane = build_serving_data_plane(load_packaged_fixture(), clock=read_fixed_clock)
    toolbox = build_knowledge_toolbox(plane)
    workspace = build_workspace_investigations(
        root,
        plane,
        toolbox,
        clock=read_fixed_clock,
        workflow=partial(interrupt_triage, files, plane, toolbox),
    )
    arguments = {"vendor": "democorp", "request_key": "crash"}
    async with Client(build_knowledge_mcp_server(toolbox, workspace=workspace)) as client:
        # Act
        interrupted = await client.call_tool("triage_product", arguments)
        retry = await client.call_tool("triage_product", arguments)
        session_id = retry.structured_content["session_id"]
        refused = await client.call_tool(
            "lookup_cve", {"session_id": session_id, "cve_id": "CVE-9999-0001"}
        )

    # Assert
    assert interrupted.is_error and interrupted.structured_content["code"] == "internal_error"
    assert retry.structured_content["workflow"] == "interrupted"
    assert retry.structured_content["outcome"] is None
    assert len(retry.structured_content["calls"]) == 1
    assert "capabilities" not in retry.structured_content["remaining_steps"]
    assert refused.structured_content["code"] == "investigation_interrupted"
    assert (root / session_id / "triage.started.json").is_file()
    assert not (root / session_id / "triage.json").exists()


async def test_time_cap_returns_typed_stopped_outcome(tmp_path: Path) -> None:
    # Arrange
    toolbox, workspace = build_test_workspace(
        tmp_path / "workspace", monotonic=SteppingClock(seconds_per_read=60).read
    )
    async with Client(build_knowledge_mcp_server(toolbox, workspace=workspace)) as client:
        # Act
        triage = await client.call_tool("triage_product", {"vendor": "democorp"})

    # Assert
    assert not triage.is_error and triage.structured_content["outcome"] == "stopped_at_cap"
    assert triage.structured_content["triage"]["stop_reason"] == "time_limit"
    assert triage.structured_content["remaining_steps"]


async def test_invalid_ids_and_keys_do_not_access_injected_filesystem(tmp_path: Path) -> None:
    # Arrange
    plane = build_serving_data_plane(load_packaged_fixture(), clock=read_fixed_clock)
    toolbox = build_knowledge_toolbox(plane)
    workspace = WorkspaceInvestigations(
        files=FilesystemAccessTrap(),
        dataset=plane.session_dataset,
        clock=read_fixed_clock,
        random_bytes=bytes,
        record_call=partial(bytes),
        workflow=partial(bytes),
        renderer=render_workspace_report,
    )
    async with Client(build_knowledge_mcp_server(toolbox, workspace=workspace)) as client:
        # Act
        invalid_id = await client.call_tool("get_investigation", {"session_id": "../escape"})
        invalid_key = await client.call_tool(
            "start_investigation", {"goal": "Review", "request_key": "../escape"}
        )
        invalid_call = await client.call_tool(
            "lookup_cve", {"session_id": "../escape", "cve_id": "CVE-9999-0001"}
        )

    # Assert
    assert invalid_id.structured_content["code"] == "invalid_arguments"
    assert invalid_key.structured_content["code"] == "invalid_arguments"
    assert invalid_call.structured_content["code"] == "invalid_arguments"


async def test_effective_citation_violation_keeps_its_original_file_index(
    workspace_client: Client,
) -> None:
    # Arrange
    session_id = (await start(workspace_client))["session_id"]
    await workspace_client.call_tool(
        "lookup_cve", {"session_id": session_id, "cve_id": "CVE-9999-0001"}
    )
    await workspace_client.call_tool(
        "add_findings", {"session_id": session_id, "findings": [agent_note("old")]}
    )
    revision = agent_note(
        "revision", supersedes="old", citations=[{"call": 1, "evidence_id": "ev:" + "0" * 24}]
    )

    # Act
    added = await workspace_client.call_tool(
        "add_findings", {"session_id": session_id, "findings": [revision]}
    )

    # Assert
    assert (
        added.structured_content["check"]["citations"]["violations"][0]["location"]
        == "findings.yaml.findings[1].citations[0]"
    )


async def test_normalized_product_and_explicit_defaults_reuse_request_key(
    workspace_client: Client,
) -> None:
    # Arrange
    first = await workspace_client.call_tool(
        "triage_product", {"vendor": "DEMOCORP", "request_key": "normalized"}
    )

    # Act
    retry = await workspace_client.call_tool(
        "triage_product",
        {
            "vendor": "democorp",
            "product": None,
            "version": None,
            "lookups": 5,
            "max_pages": 20,
            "select": [],
            "goal": None,
            "request_key": "normalized",
        },
    )

    # Assert
    assert retry.structured_content == first.structured_content
    assert retry.structured_content["session"]["triage_request"]["vendor"] == "democorp"


async def test_tighter_operator_limit_does_not_rerun_or_refuse_keyed_retry(tmp_path: Path) -> None:
    # Arrange
    root = tmp_path / "workspace"
    toolbox, workspace = build_test_workspace(root)
    arguments = {"vendor": "democorp", "request_key": "retained"}
    async with Client(build_knowledge_mcp_server(toolbox, workspace=workspace)) as client:
        original = await client.call_tool("triage_product", arguments)
    toolbox, workspace = build_test_workspace(root, call_limit=1)

    # Act
    async with Client(build_knowledge_mcp_server(toolbox, workspace=workspace)) as client:
        retry = await client.call_tool("triage_product", arguments)

    # Assert
    assert not retry.is_error and retry.structured_content == original.structured_content


async def test_recording_mode_records_workspace_refusals_with_existing_recorder(
    tmp_path: Path,
) -> None:
    # Arrange
    plane = build_serving_data_plane(load_packaged_fixture(), clock=read_fixed_clock)
    toolbox = build_knowledge_toolbox(plane)
    directory = tmp_path / "recording"
    recorder = SessionRecorder(directory, plane.session_dataset, read_fixed_clock)
    async with Client(build_knowledge_mcp_server(toolbox, recorder=recorder)) as client:
        # Act
        refused = await client.call_tool(
            "lookup_cve", {"session_id": "inv_" + "a" * 20, "cve_id": "CVE-9999-0001"}
        )

    # Assert
    assert refused.is_error and refused.structured_content["code"] == "investigations_not_enabled"
    assert (
        json.loads((directory / "calls/0001.json").read_bytes())["outcome"]
        == "investigations_not_enabled"
    )
    assert (directory / "responses/0001.json").read_bytes() == refused.content[0].text.encode()
