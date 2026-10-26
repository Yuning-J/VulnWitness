"""Proves the API's one read-only data plane (ADR 0009 §12): the toolbox's deployment and
the verification route's are built over one data plane, sharing its search service, FiGHT
source and evidence catalog, while their call runners and admission stay apart, so an
investigation runs while verification is busy and verification runs while every tool
worker is; concurrent searches and replays answer as serial runs do; and both paths
report the same capability versions."""

import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import anyio
import httpx2
import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.application.serving_data_plane import ServingDataPlane
from cve_kgrag.cli import build_evidence_set_check
from cve_kgrag.composition import (
    build_investigation_deployment,
    build_investigation_service,
    build_knowledge_toolbox,
    build_serving_data_plane,
)
from cve_kgrag.domain.evidence_set_verification_report import (
    VerificationReport,
    VerificationVerdict,
)
from cve_kgrag.domain.investigation import InvestigationRequest, KnowledgeEvidenceSet
from cve_kgrag.domain.search import SearchResponse
from cve_kgrag.interfaces.knowledge_toolbox import KnowledgeToolbox
from cve_kgrag.interfaces.knowledge_tools import KnowledgeToolName, ToolLimits
from cve_kgrag.interfaces.rest.api_runner import build_api_app
from tests.support.asgi import (
    GENEROUS_WAIT_SECONDS,
    HTTP_HOST,
    HTTP_PORT,
    HTTP_SECRET_TOKEN,
    open_app_client,
)
from tests.support.fakes import BlockingTrustifyPort
from tests.support.toolbox import TOOL_ARGUMENTS, require_answer

pytestmark = pytest.mark.anyio

INVESTIGATION = {"query": "5gaka", "scope": "mixed"}
SEARCH_QUERIES = ("ausf crash", "5G-AKA resynchronization", "democorp gateway", "CVE-9999-0003")


class GatedCheck:
    """The production check, entered and then held until ``release`` is set."""

    def __init__(self, check: Callable[[bytes], VerificationReport], release: threading.Event):
        self._check = check
        self.release = release
        self.entered = threading.Event()

    def __call__(self, evidence_set_bytes: bytes) -> VerificationReport:
        self.entered.set()
        self.release.wait()
        return self._check(evidence_set_bytes)


@pytest.fixture
def data_plane(fixture_bundle: FixtureBundle) -> ServingDataPlane:
    return build_serving_data_plane(fixture_bundle)


def seal_investigation(data_plane: ServingDataPlane) -> bytes:
    """A set sealed by a deployment of ``data_plane`` with the disabled affectedness port."""
    evidence_set = build_investigation_service(data_plane).investigate(
        InvestigationRequest.model_validate(INVESTIGATION)
    )
    return evidence_set.model_dump_json().encode()


def wait_until_every_worker_is_busy(toolbox: KnowledgeToolbox) -> None:
    deadline = time.monotonic() + GENEROUS_WAIT_SECONDS
    while toolbox.has_free_worker():
        assert time.monotonic() < deadline, "the blocked call never took its worker"
        time.sleep(0.01)


def test_deployments_of_one_data_plane_share_it_and_keep_their_own_call_runners(
    data_plane: ServingDataPlane,
) -> None:
    tool_deployment = build_investigation_deployment(data_plane)
    verification_deployment = build_investigation_deployment(data_plane)

    for shared_part in ("search_service", "evidence_catalog", "topic_registry"):
        assert getattr(tool_deployment, shared_part) is getattr(data_plane, shared_part)
        assert getattr(verification_deployment, shared_part) is getattr(data_plane, shared_part)
    assert tool_deployment.call_runner is not verification_deployment.call_runner
    assert tool_deployment.topic_context_service is not (
        verification_deployment.topic_context_service
    )


async def test_investigation_runs_while_verification_holds_its_route(
    data_plane: ServingDataPlane, blocked_call_release: threading.Event
) -> None:
    gated_check = GatedCheck(build_evidence_set_check(data_plane, None), blocked_call_release)
    api_app = build_api_app(
        build_knowledge_toolbox(data_plane),
        gated_check,
        host=HTTP_HOST,
        port=HTTP_PORT,
        token=HTTP_SECRET_TOKEN,
    )
    verification_answers: list[httpx2.Response] = []

    async with open_app_client(api_app) as http_client, anyio.create_task_group() as task_group:
        task_group.start_soon(
            post_into,
            http_client,
            "/api/v2/verify",
            seal_investigation(data_plane),
            verification_answers,
        )
        with anyio.fail_after(GENEROUS_WAIT_SECONDS):
            await anyio.to_thread.run_sync(gated_check.entered.wait)
        investigation_answer = await http_client.post("/api/v2/investigate", json=INVESTIGATION)
        blocked_call_release.set()

    assert investigation_answer.status_code == 200
    KnowledgeEvidenceSet.model_validate_json(investigation_answer.content)
    assert VerificationReport.model_validate_json(verification_answers[0].content).verdict is (
        VerificationVerdict.VERIFIED
    )


async def post_into(
    http_client: httpx2.AsyncClient, path: str, body: bytes, answers: list[httpx2.Response]
) -> None:
    answers.append(await http_client.post(path, content=body))


async def test_verification_runs_while_every_tool_worker_is_busy(
    data_plane: ServingDataPlane, blocked_call_release: threading.Event
) -> None:
    toolbox = build_knowledge_toolbox(
        data_plane,
        trustify_port=BlockingTrustifyPort(blocked_call_release),
        limits=ToolLimits(max_calls_in_flight=1),
    )
    api_app = build_api_app(
        toolbox,
        build_evidence_set_check(data_plane, None),
        host=HTTP_HOST,
        port=HTTP_PORT,
        token=HTTP_SECRET_TOKEN,
    )
    sealed_set = seal_investigation(data_plane)

    with ThreadPoolExecutor(max_workers=1) as executor:
        blocked_call = executor.submit(
            toolbox.call,
            KnowledgeToolName.CHECK_AFFECTEDNESS,
            TOOL_ARGUMENTS[KnowledgeToolName.CHECK_AFFECTEDNESS],
        )
        await anyio.to_thread.run_sync(wait_until_every_worker_is_busy, toolbox)
        async with open_app_client(api_app) as http_client:
            busy_tool_answer = await http_client.post("/api/v2/investigate", json=INVESTIGATION)
            verification_answer = await http_client.post("/api/v2/verify", content=sealed_set)
        blocked_call_release.set()
        blocked_call.result(timeout=GENEROUS_WAIT_SECONDS)

    assert busy_tool_answer.status_code == 503
    assert VerificationReport.model_validate_json(verification_answer.content).verdict is (
        VerificationVerdict.VERIFIED
    )


def search_result_sha256(toolbox: KnowledgeToolbox, query: str) -> str:
    search_answer = require_answer(
        toolbox.call(KnowledgeToolName.SEARCH_VULNERABILITIES, {"query": query})
    )
    return SearchResponse.model_validate_json(search_answer.json_text).result_sha256


def test_concurrent_searches_and_replays_answer_as_serial_runs_do(
    data_plane: ServingDataPlane,
) -> None:
    toolbox = build_knowledge_toolbox(data_plane)
    check = build_evidence_set_check(data_plane, None)
    sealed_set = seal_investigation(data_plane)
    serial_hashes: list[str] = []
    for query in SEARCH_QUERIES:
        serial_hashes.append(search_result_sha256(toolbox, query))

    with ThreadPoolExecutor(max_workers=8) as executor:
        search_futures = []
        for query in SEARCH_QUERIES * 4:
            search_futures.append(
                executor.submit(
                    toolbox.call, KnowledgeToolName.SEARCH_VULNERABILITIES, {"query": query}
                )
            )
        replay_futures = []
        for _ in range(4):
            replay_futures.append(executor.submit(check, sealed_set))
        concurrent_hashes: list[str] = []
        for search_future in search_futures:
            search_answer = require_answer(search_future.result())
            concurrent_hashes.append(
                SearchResponse.model_validate_json(search_answer.json_text).result_sha256
            )
        verdicts: set[VerificationVerdict] = set()
        for replay_future in replay_futures:
            verdicts.add(replay_future.result().verdict)

    assert concurrent_hashes == serial_hashes * 4
    assert verdicts == {VerificationVerdict.VERIFIED}


def test_set_the_tools_seal_verifies_on_the_route_sharing_their_data_plane(
    data_plane: ServingDataPlane,
) -> None:
    """Verification compares every capability version, so a set the tool deployment
    sealed verifies only where the route reports the same cve_search and mitre_fight
    versions."""
    toolbox = build_knowledge_toolbox(data_plane)
    check = build_evidence_set_check(data_plane, None)
    investigation_answer = require_answer(
        toolbox.call(KnowledgeToolName.INVESTIGATE_TELECOM_TOPIC, INVESTIGATION)
    )

    report = check(investigation_answer.json_text.encode())

    assert report.verdict is VerificationVerdict.VERIFIED
