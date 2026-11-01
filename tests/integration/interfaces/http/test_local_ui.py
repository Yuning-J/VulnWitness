"""Local UI operations on demo data through the guarded in-process HTTP client."""

import json
from collections.abc import AsyncIterator
from contextlib import nullcontext
from pathlib import Path

import anyio
import httpx2
import pytest
from starlette.applications import Starlette

from tests.support.asgi import (
    HTTP_PORT,
    HTTP_SECRET_TOKEN,
    SERVER_URL,
    AsgiRequest,
    open_app_client,
    send_request,
)
from tests.support.ui_startup import DeferredUiDeployment
from tests.support.workspaces import agent_note, build_test_workspace
from vulnwitness.adapters.session.files import hold_session_lock
from vulnwitness.domain.investigation import KnowledgeEvidenceSet
from vulnwitness.domain.session_record import SessionRecord
from vulnwitness.domain.tool_contracts import TOOL_FAILURE_MESSAGES, ToolFailureCode
from vulnwitness.domain.workspace import AddFindingsRequest, RenderReportRequest
from vulnwitness.interfaces.mcp_deployment import McpDeployment
from vulnwitness.interfaces.ui.app import build_ui_app
from vulnwitness.interfaces.ui.lifespan import UiLifespan
from vulnwitness.interfaces.ui.state import UiState

pytestmark = pytest.mark.anyio


@pytest.fixture
async def ui_client(tmp_path: Path) -> AsyncIterator[httpx2.AsyncClient]:
    toolbox, workspace = build_test_workspace(tmp_path / "workspace")
    state = UiState(McpDeployment(toolbox, workspace=workspace))
    app = build_ui_app(state, port=HTTP_PORT, token=HTTP_SECRET_TOKEN)
    async with open_app_client(app) as client:
        yield client


async def test_product_submission_retries_return_one_triage_investigation(
    ui_client: httpx2.AsyncClient,
) -> None:
    # Arrange
    query = {"product": "demo_gateway", "vendor": "democorp", "request_key": "same-submission"}

    # Act
    first = await ui_client.post("/ui-api/triage", json=query)
    retry = await ui_client.post("/ui-api/triage", json=query)
    listing = await ui_client.get("/ui-api/list")

    # Assert
    assert first.status_code == retry.status_code == 200
    assert first.json()["session_id"] == retry.json()["session_id"]
    assert first.json()["session"]["origin"] == "triage"
    assert first.json()["triage"]["inventory"]["items_seen"] > 0
    assert first.json()["calls"] == retry.json()["calls"]
    assert len(listing.json()["investigations"]) == 1
    assert listing.json()["investigations"][0]["dataset"]["served"]["kind"] == "synthetic_fixture"


@pytest.mark.parametrize(
    "operation,arguments,command",
    [
        ("lookup", {"cve_id": "CVE-9999-0001"}, "lookup_cve"),
        (
            "investigate",
            {"query": "5G core authentication", "scope": "mixed"},
            "investigate_telecom_topic",
        ),
    ],
)
async def test_manual_entry_records_one_call_with_its_investigation(
    ui_client: httpx2.AsyncClient, operation: str, arguments: dict[str, str], command: str
) -> None:
    # Arrange
    started = await ui_client.post("/ui-api/start", json={"goal": "Review demo evidence"})
    session_id = started.json()["session_id"]

    # Act
    recorded = await ui_client.post(
        f"/ui-api/{operation}", json={"session_id": session_id, **arguments}
    )
    snapshot = await ui_client.get(f"/ui-api/get/{session_id}")
    saved = await ui_client.post("/ui-api/call", json={"session_id": session_id, "call": 1})

    # Assert
    assert recorded.status_code == 200
    assert snapshot.json()["session"]["origin"] == "manual"
    assert len(snapshot.json()["calls"]) == 1
    assert snapshot.json()["calls"][0]["command"] == command
    assert saved.json()["call"]["command"] == command
    assert json.loads(saved.json()["response_json"]) == recorded.json()


async def test_follow_up_makes_report_stale_until_rendered_again(
    ui_client: httpx2.AsyncClient,
) -> None:
    # Arrange
    started = await ui_client.post("/ui-api/triage", json={"product": "demo_gateway"})
    session_id = started.json()["session_id"]
    request = {"session_id": session_id}

    # Act
    rendered = await ui_client.post("/ui-api/render", json=request)
    current = await ui_client.get(f"/ui-api/get/{session_id}")
    follow_up = await ui_client.post("/ui-api/lookup", json={**request, "cve_id": "CVE-9999-0001"})
    stale = await ui_client.get(f"/ui-api/get/{session_id}")
    rerendered = await ui_client.post("/ui-api/render", json=request)
    refreshed = await ui_client.get(f"/ui-api/get/{session_id}")
    report = await ui_client.get(f"/ui-api/report/{session_id}")
    view = await ui_client.get(f"/ui-api/view/{session_id}")
    checked = await ui_client.post("/ui-api/check", json=request)

    # Assert
    assert rendered.status_code == follow_up.status_code == rerendered.status_code == 200
    assert current.json()["report"] == refreshed.json()["report"] == "current"
    assert stale.json()["report"] == "stale"
    assert len(stale.json()["calls"]) == len(current.json()["calls"]) + 1
    assert report.status_code == view.status_code == checked.status_code == 200
    assert report.headers["content-type"].startswith("text/html")
    assert "Content-Security-Policy" in report.text
    assert view.json()["report"]["check"] == checked.json()
    assert len(view.json()["report"]["sections"][2]["sections"]) > 0


@pytest.mark.parametrize("path", ["/", "/ui-api/list", "/ui-api/start"])
@pytest.mark.parametrize(
    "headers,status,code",
    [
        ({"host": "attacker.invalid"}, 421, "host_not_allowed"),
        ({"origin": "https://attacker.invalid"}, 403, "origin_not_allowed"),
        ({"origin": "null"}, 403, "origin_not_allowed"),
    ],
)
async def test_foreign_host_or_origin_is_refused_on_assets_and_operations(
    ui_client: httpx2.AsyncClient, path: str, headers: dict[str, str], status: int, code: str
) -> None:
    # Arrange / Act
    answer = await ui_client.request(
        "POST" if path.endswith("start") else "GET", path, headers=headers
    )

    # Assert
    assert answer.status_code == status
    assert answer.json()["code"] == code


async def test_state_changes_require_bearer_header(ui_client: httpx2.AsyncClient) -> None:
    # Arrange / Act
    answer = await ui_client.post(
        "/ui-api/start", json={"goal": "Refused"}, headers={"authorization": ""}
    )
    listing = await ui_client.get("/ui-api/list")

    # Assert
    assert answer.status_code == 401
    assert answer.json()["code"] == "unauthorized"
    assert listing.json()["investigations"] == []


@pytest.mark.parametrize(
    "session_id,status,code",
    [
        ("..%2Fsession.json", 422, "invalid_arguments"),
        ("inv_" + "a" * 20, 404, "unknown_investigation"),
    ],
)
@pytest.mark.parametrize("operation", ["get", "view", "report"])
async def test_invalid_or_unknown_ids_return_typed_failures(
    ui_client: httpx2.AsyncClient, session_id: str, status: int, code: str, operation: str
) -> None:
    # Arrange / Act
    answer = await ui_client.get(f"/ui-api/{operation}/{session_id}")

    # Assert
    assert answer.status_code == status
    assert answer.json()["code"] == code


async def test_report_endpoint_serves_only_its_investigations_fixed_report(
    ui_client: httpx2.AsyncClient,
) -> None:
    # Arrange
    first = await ui_client.post("/ui-api/start", json={"goal": "First private report"})
    second = await ui_client.post("/ui-api/start", json={"goal": "Second private report"})
    first_id = first.json()["session_id"]
    second_id = second.json()["session_id"]
    await ui_client.post("/ui-api/render", json={"session_id": first_id})

    # Act
    report = await ui_client.get(f"/ui-api/report/{first_id}")
    absent = await ui_client.get(f"/ui-api/report/{second_id}")
    path_parameter = await ui_client.get(f"/ui-api/report/{first_id}?path=session.json")
    extra_segment = await ui_client.get(f"/ui-api/report/{first_id}/session.json")

    # Assert
    assert report.status_code == 200
    assert "First private report" in report.text and "Second private report" not in report.text
    assert absent.status_code == path_parameter.status_code == extra_segment.status_code == 404
    assert absent.json()["code"] == "unknown_investigation"


async def test_hostile_record_text_stays_text_in_json_and_page(tmp_path: Path) -> None:
    # Arrange
    toolbox, workspace = build_test_workspace(tmp_path / "workspace")
    app = build_ui_app(
        UiState(McpDeployment(toolbox, workspace=workspace)),
        port=HTTP_PORT,
        token=HTTP_SECRET_TOKEN,
    )
    hostile = '<img src=x onerror="alert(1)"><script>alert(2)</script>'
    async with open_app_client(app) as client:
        started = await client.post("/ui-api/start", json={"goal": hostile})
        session_id = started.json()["session_id"]
        workspace.add_findings(
            AddFindingsRequest.model_validate(
                {"session_id": session_id, "findings": [agent_note("hostile", statement=hostile)]}
            )
        )

        # Act
        view = await client.get(f"/ui-api/view/{session_id}")
        script = await client.get("/ui.js")
        page = await client.get(f"/investigations/{session_id}")

    # Assert
    assert view.json()["report"]["title"] == hostile
    assert "<img" not in view.text and "\\u003cimg" in view.text
    assert "textContent" in script.text
    assert "innerHTML" not in script.text and "insertAdjacentHTML" not in script.text
    assert hostile not in page.text
    assert "default-src 'none'" in page.headers["content-security-policy"]
    assert "script-src 'self'" in page.headers["content-security-policy"]


async def test_pages_and_list_answer_while_data_operations_fail_fast(tmp_path: Path) -> None:
    # Arrange
    state = UiState()
    app = build_ui_app(state, port=HTTP_PORT, token=HTTP_SECRET_TOKEN)
    toolbox, workspace = build_test_workspace(tmp_path / "workspace")
    async with open_app_client(app) as client:
        # Act
        page = await client.get("/")
        listing = await client.get("/ui-api/list")
        refused = await client.post(
            "/ui-api/triage", json={"product": "demo_gateway", "request_key": "retry"}
        )
        state.publish(McpDeployment(toolbox, workspace=workspace))
        ready = await client.post("/ui-api/wait", json={})
        retried = await client.post(
            "/ui-api/triage", json={"product": "demo_gateway", "request_key": "retry"}
        )

    # Assert
    assert page.status_code == listing.status_code == 200
    assert listing.json() == {"status": "loading", "investigations": []}
    assert refused.status_code == 503 and refused.json()["code"] == "data_loading"
    assert ready.json() == {"status": "ready"}
    assert retried.status_code == 200
    assert len(workspace.list().investigations) == 1


async def test_encoded_raw_path_is_rejected_without_filesystem_access(tmp_path: Path) -> None:
    # Arrange
    toolbox, workspace = build_test_workspace(tmp_path / "workspace")
    app = build_ui_app(
        UiState(McpDeployment(toolbox, workspace=workspace)),
        port=HTTP_PORT,
        token=HTTP_SECRET_TOKEN,
    )

    # Act
    answer = await send_request(app, AsgiRequest(target=b"/ui-api/report/%2e%2e%2fsecret"))

    # Assert
    assert answer.status == 422
    assert answer.read_json()["code"] == "invalid_arguments"


@pytest.mark.parametrize("interrupted", [False, True], ids=["busy", "interrupted"])
async def test_refused_follow_up_preserves_the_typed_workflow_message(
    tmp_path: Path, interrupted: bool
) -> None:
    # Arrange
    toolbox, workspace = build_test_workspace(tmp_path / "workspace")
    app = build_ui_app(
        UiState(McpDeployment(toolbox, workspace=workspace)),
        port=HTTP_PORT,
        token=HTTP_SECRET_TOKEN,
    )
    async with open_app_client(app) as client:
        started = await client.post("/ui-api/start", json={"goal": "Recorded demo"})
        session_id = started.json()["session_id"]
        directory = tmp_path / "workspace" / session_id
        if interrupted:
            metadata = SessionRecord.model_validate_json((directory / "session.json").read_bytes())
            (directory / "session.json").write_text(
                metadata.model_copy(update={"origin": "triage"}).model_dump_json()
            )
        lock = nullcontext() if interrupted else hold_session_lock(directory)

        # Act
        with lock:
            refused = await client.post(
                "/ui-api/lookup", json={"session_id": session_id, "cve_id": "CVE-9999-0001"}
            )

    # Assert
    expected_code = (
        ToolFailureCode.INVESTIGATION_INTERRUPTED
        if interrupted
        else ToolFailureCode.INVESTIGATION_BUSY
    )
    assert refused.status_code == 409
    assert refused.json()["code"] == expected_code.value
    assert refused.json()["message"] == TOOL_FAILURE_MESSAGES[expected_code]
    assert workspace.list().investigations[0].session_id == session_id


async def test_markdown_render_does_not_refresh_the_ui_html_report(tmp_path: Path) -> None:
    # Arrange
    toolbox, workspace = build_test_workspace(tmp_path / "workspace")
    app = build_ui_app(
        UiState(McpDeployment(toolbox, workspace=workspace)),
        port=HTTP_PORT,
        token=HTTP_SECRET_TOKEN,
    )
    async with open_app_client(app) as client:
        started = await client.post("/ui-api/start", json={"goal": "Format-specific freshness"})
        session_id = started.json()["session_id"]
        await client.post("/ui-api/render", json={"session_id": session_id})
        await client.post(
            "/ui-api/lookup", json={"session_id": session_id, "cve_id": "CVE-9999-0001"}
        )
        workspace.render(RenderReportRequest(session_id=session_id, format="md"))

        # Act
        snapshot = await client.get(f"/ui-api/get/{session_id}")
        listing = await client.get("/ui-api/list")

    # Assert
    assert snapshot.json()["report"] == "stale"
    assert listing.json()["investigations"][0]["report"] == "stale"


async def test_background_startup_serves_pages_before_publication(tmp_path: Path) -> None:
    # Arrange
    toolbox, workspace = build_test_workspace(tmp_path / "workspace")
    loader = DeferredUiDeployment(McpDeployment(toolbox, workspace=workspace))
    state = UiState()
    app = build_ui_app(
        state,
        port=HTTP_PORT,
        token=HTTP_SECRET_TOKEN,
        lifespan_app=Starlette(lifespan=UiLifespan(state, loader.load)),
    )
    try:
        async with open_app_client(app) as client:
            assert await anyio.to_thread.run_sync(loader.entered.wait, 5)

            # Act
            page = await client.get("/")
            loading = await client.get("/ui-api/list")
            loader.release.set()
            ready = await client.post("/ui-api/wait", json={})
            listing = await client.get("/ui-api/list")
    finally:
        loader.release.set()

    # Assert
    assert page.status_code == 200
    assert loading.json()["status"] == "loading"
    assert ready.json() == {"status": "ready"}
    assert listing.json()["status"] == "ready"


async def test_report_navigation_requires_launch_token_and_serves_fixed_html(
    ui_client: httpx2.AsyncClient,
) -> None:
    # Arrange
    started = await ui_client.post("/ui-api/start", json={"goal": "Browser export"})
    session_id = started.json()["session_id"]
    await ui_client.post("/ui-api/render", json={"session_id": session_id})
    target = f"/reports/{session_id}"
    token = HTTP_SECRET_TOKEN.get_secret_value()

    # Act
    page = await ui_client.get(f"/investigations/{session_id}")
    start_page = await ui_client.get("/")
    missing = await ui_client.post(target, headers={"origin": SERVER_URL})
    wrong = await ui_client.post(target, data={"token": "wrong"})
    foreign = await ui_client.post(
        target, data={"token": token}, headers={"origin": "https://attacker.invalid"}
    )
    null_origin = await ui_client.post(target, data={"token": token}, headers={"origin": "null"})
    report = await ui_client.post(
        target, data={"token": token}, headers={"origin": SERVER_URL, "authorization": ""}
    )
    api_report = await ui_client.get(f"/ui-api/report/{session_id}")
    script = await ui_client.get("/ui.js")

    # Assert
    assert missing.status_code == wrong.status_code == 401
    assert page.headers["referrer-policy"] == start_page.headers["referrer-policy"] == "same-origin"
    assert missing.json()["code"] == wrong.json()["code"] == "unauthorized"
    assert foreign.status_code == null_origin.status_code == 403
    assert foreign.json()["code"] == null_origin.json()["code"] == "origin_not_allowed"
    assert report.status_code == 200
    assert report.content == api_report.content
    assert report.headers["content-security-policy"] == (
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'self'"
    )
    assert report.headers["referrer-policy"] == "no-referrer"
    assert '<meta http-equiv="Content-Security-Policy"' in report.text
    assert "default-src 'none'; style-src 'unsafe-inline'" in report.text
    assert "<style>" in report.text and "<script" not in report.text
    assert "innerHTML" not in script.text


async def test_topic_detail_api_exposes_the_shared_investigation_sections(
    ui_client: httpx2.AsyncClient,
) -> None:
    # Arrange
    started = await ui_client.post("/ui-api/start", json={"goal": "5G-AKA topic review"})
    session_id = started.json()["session_id"]
    recorded = await ui_client.post(
        "/ui-api/investigate", json={"session_id": session_id, "query": "5G-AKA", "scope": "mixed"}
    )
    answer = KnowledgeEvidenceSet.model_validate(recorded.json())

    # Act
    view = await ui_client.get(f"/ui-api/view/{session_id}")
    investigation = next(
        section
        for section in view.json()["report"]["sections"]
        if section["title"] == "Investigations"
    )["sections"][0]
    sections = investigation["sections"]

    # Assert
    assert view.status_code == 200
    titles = []
    for section in sections:
        titles.append(section["title"])
    assert titles == [
        "Status and needs",
        "Implementation candidates",
        "Protocol context (FiGHT)",
        "Warnings",
    ]
    for candidate, row in zip(
        answer.implementation_candidates, sections[1]["tables"][0]["rows"], strict=True
    ):
        assert row[0] == candidate.candidate.record.cve_id
    for technique, row in zip(
        answer.protocol_context, sections[2]["tables"][0]["rows"], strict=True
    ):
        assert row[0] == technique.technique_id and row[1] == technique.name
        assert row[2] == ", ".join(technique.tactic_names)
        assert row[3] == technique.status.value
        assert row[4] == ", ".join(technique.matched_terms)
        for evidence_id in technique.evidence_ids:
            assert evidence_id in row[5]
    for warning in answer.warnings:
        assert any(
            warning.code.value in bullet and warning.subject in bullet
            for bullet in sections[3]["bullets"]
        )


async def test_topic_detail_omits_empty_inventory_and_shows_empty_candidates_as_text(
    ui_client: httpx2.AsyncClient,
) -> None:
    # Arrange
    started = await ui_client.post("/ui-api/start", json={"goal": "GTP topic review"})
    session_id = started.json()["session_id"]
    await ui_client.post(
        "/ui-api/investigate", json={"session_id": session_id, "query": "GTP", "scope": "mixed"}
    )

    # Act
    view = await ui_client.get(f"/ui-api/view/{session_id}")
    script = await ui_client.get("/ui.js")

    # Assert
    assert view.status_code == 200
    sections = view.json()["report"]["sections"]
    assert sections[1]["sections"][0]["bullets"] == [
        "Call 1 investigation (mixed): 0 implementation candidates, "
        "4 FiGHT techniques, status partial"
    ]
    for section in sections:
        assert not section["title"].startswith(("CVE details", "Read inventory"))
    investigation = next(section for section in sections if section["title"] == "Investigations")
    candidates = investigation["sections"][0]["sections"][1]
    assert candidates["tables"] == []
    assert candidates["paragraphs"][0]["text"] == "No implementation candidates were returned."
    assert "Open saved JSON in Trajectory to inspect" not in script.text


async def test_report_symlink_cannot_serve_an_unrelated_file(tmp_path: Path) -> None:
    # Arrange
    toolbox, workspace = build_test_workspace(tmp_path / "workspace")
    app = build_ui_app(
        UiState(McpDeployment(toolbox, workspace=workspace)),
        port=HTTP_PORT,
        token=HTTP_SECRET_TOKEN,
    )
    async with open_app_client(app) as client:
        started = await client.post("/ui-api/start", json={"goal": "Fixed artifact"})
        session_id = started.json()["session_id"]
        unrelated = tmp_path / "unrelated.html"
        unrelated.write_text("private unrelated file")
        (tmp_path / "workspace" / session_id / "report.html").symlink_to(unrelated)

        # Act
        refused = await client.get(f"/ui-api/report/{session_id}")

    # Assert
    assert refused.status_code == 422
    assert refused.json()["code"] == "invalid_arguments"
    assert "private unrelated file" not in refused.text
