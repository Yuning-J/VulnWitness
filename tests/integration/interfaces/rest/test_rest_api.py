"""The v2 REST API: each route one toolbox call or one verification behind the HTTP
guard, a tool's failure answered with its REST status and the bare ``ToolFailure``, and
every verdict answered 200 (ADR 0007, decisions 8 and 9)."""

import json
import signal
import threading
from collections.abc import AsyncIterator, Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any

import anyio
import httpx2
import pytest
from starlette.types import ASGIApp

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.application.evidence_set_verification import check_evidence_set
from cve_kgrag.domain.evidence_set_verification_report import (
    VerificationReport,
    VerificationVerdict,
)
from cve_kgrag.domain.http_rejection import HttpRejection, HttpRejectionCode
from cve_kgrag.domain.investigation import KnowledgeEvidenceSet
from cve_kgrag.domain.search import SearchResponse
from cve_kgrag.domain.tool_contracts import (
    EvidenceLookup,
    KnowledgeCapabilities,
    ToolFailure,
    ToolFailureCode,
)
from cve_kgrag.interfaces.http.guard import GuardedRoute, HttpGuard
from cve_kgrag.interfaces.knowledge_toolbox import KnowledgeToolbox
from cve_kgrag.interfaces.knowledge_tools import KnowledgeToolName, ToolLimits
from cve_kgrag.interfaces.rest.api_runner import build_api_app
from cve_kgrag.interfaces.rest.tool_routes import TOOL_FAILURE_STATUSES
from cve_kgrag.interfaces.rest.verification_route import EvidenceSetCheck, VerificationRoute
from tests.support.asgi import (
    AUTHORIZATION,
    GENEROUS_WAIT_SECONDS,
    HTTP_HOST,
    HTTP_PORT,
    HTTP_SECRET_TOKEN,
    HTTP_TOKEN,
    AsgiAnswer,
    AsgiRequest,
    answer_nothing,
    open_app_client,
    send_request,
)
from tests.support.clocks import SteppingClock
from tests.support.fakes import BlockingRetriever, RaisingRetriever
from tests.support.investigation import build_test_deployment
from tests.support.investigation_runs import forge_set_whose_replay_differs
from tests.support.marker_sweep import ECHO_MARKER
from tests.support.planners import DETERMINISTIC_VERIFIER
from tests.support.process_servers import (
    SERVER_START_SECONDS,
    ServedHttp,
    run_on_a_port_in_use,
    start_served_http,
)
from tests.support.toolbox import (
    FIXTURE_EVIDENCE_ID,
    SECRET_ERROR_TEXT,
    UNKNOWN_EVIDENCE_ID,
    build_test_toolbox,
)

pytestmark = pytest.mark.anyio

# The published body caps (ADR 0007, decisions 9 and 11).
VERIFY_BODY_CAP_BYTES = 4 * 1024 * 1024
ROUTE_BODY_CAP_BYTES = 256 * 1024
# Each failure's status, as ADR 0007 decision 8 publishes it.
EXPECTED_FAILURE_STATUSES = {
    ToolFailureCode.INVALID_ARGUMENTS: 422,
    ToolFailureCode.ARGUMENTS_TOO_LARGE: 413,
    ToolFailureCode.UNKNOWN_EVIDENCE_ID: 404,
    ToolFailureCode.SERVER_BUSY: 503,
    ToolFailureCode.TIMED_OUT: 504,
    ToolFailureCode.RESPONSE_TOO_LARGE: 500,
    ToolFailureCode.INTEGRITY_CHECK_FAILED: 500,
    ToolFailureCode.INTERNAL_ERROR: 500,
}


def build_evidence_set_check(
    fixture_bundle: FixtureBundle, **deployment_wiring: Any
) -> EvidenceSetCheck:
    """``check_evidence_set`` over the test deployment with ``deployment_wiring``,
    accepting the deterministic planner, as the API's verification route runs it."""
    return partial(
        check_evidence_set,
        deployment=build_test_deployment(fixture_bundle, **deployment_wiring),
        accepted_planner_capabilities=DETERMINISTIC_VERIFIER,
    )


def build_test_api(
    fixture_bundle: FixtureBundle,
    toolbox: KnowledgeToolbox | None = None,
    check: EvidenceSetCheck | None = None,
) -> HttpGuard:
    return build_api_app(
        toolbox or build_test_toolbox(fixture_bundle),
        check or build_evidence_set_check(fixture_bundle),
        host=HTTP_HOST,
        port=HTTP_PORT,
        token=HTTP_SECRET_TOKEN,
    )


async def call_api(
    api_app: HttpGuard, method: str, path: str, **request_options: Any
) -> httpx2.Response:
    """One request to ``api_app`` with the token, its lifespan running."""
    async with open_app_client(api_app) as http_client:
        return await http_client.request(method, path, **request_options)


@pytest.fixture
async def api_client(fixture_bundle: FixtureBundle) -> AsyncIterator[httpx2.AsyncClient]:
    """An in-process client of the API over the production toolbox wiring, sending the
    token."""
    async with open_app_client(build_test_api(fixture_bundle)) as http_client:
        yield http_client


def read_tool_failure(answer: httpx2.Response) -> ToolFailure:
    """The bare ``ToolFailure`` a failed tool's answer is, with its published status."""
    tool_failure = ToolFailure.model_validate_json(answer.content)
    assert answer.status_code == EXPECTED_FAILURE_STATUSES[tool_failure.code]
    return tool_failure


def test_every_failure_code_has_its_published_rest_status() -> None:
    assert set(TOOL_FAILURE_STATUSES) == set(ToolFailureCode)
    assert TOOL_FAILURE_STATUSES == EXPECTED_FAILURE_STATUSES


async def test_request_deadline_is_fifty_seconds(fixture_bundle: FixtureBundle) -> None:
    assert build_test_api(fixture_bundle).request_deadline_seconds == 50.0


async def test_capabilities_route_answers_the_capabilities_contract(
    api_client: httpx2.AsyncClient,
) -> None:
    answer = await api_client.get("/api/v2/capabilities")

    assert answer.status_code == 200
    assert answer.headers["content-type"] == "application/json"
    KnowledgeCapabilities.model_validate_json(answer.content)


async def test_search_route_answers_the_search_contract(api_client: httpx2.AsyncClient) -> None:
    answer = await api_client.post("/api/v2/search", json={"query": "ausf crash", "limit": 3})

    assert answer.status_code == 200
    search_response = SearchResponse.model_validate_json(answer.content)
    assert search_response.query == "ausf crash"


async def test_evidence_route_reads_the_evidence_id_from_the_path(
    api_client: httpx2.AsyncClient,
) -> None:
    answer = await api_client.get(f"/api/v2/evidence/{FIXTURE_EVIDENCE_ID}")

    assert answer.status_code == 200
    assert EvidenceLookup.model_validate_json(answer.content).evidence.evidence_id == (
        FIXTURE_EVIDENCE_ID
    )


async def test_investigation_sealed_over_the_api_verifies_over_the_api(
    api_client: httpx2.AsyncClient,
) -> None:
    investigation_answer = await api_client.post(
        "/api/v2/investigate", json={"query": "5gaka", "scope": "mixed"}
    )
    verification_answer = await api_client.post(
        "/api/v2/verify", content=investigation_answer.content
    )

    assert investigation_answer.status_code == 200
    KnowledgeEvidenceSet.model_validate_json(investigation_answer.content)
    assert verification_answer.status_code == 200
    assert VerificationReport.model_validate_json(verification_answer.content).verdict is (
        VerificationVerdict.VERIFIED
    )


@pytest.mark.parametrize(
    ("path", "request_options", "expected_code"),
    [
        (
            "/api/v2/search",
            {"json": {"query": "ausf", "limit": ECHO_MARKER}},
            ToolFailureCode.INVALID_ARGUMENTS,
        ),
        (
            "/api/v2/search",
            {"json": {"query": "ausf", ECHO_MARKER: 1}},
            ToolFailureCode.INVALID_ARGUMENTS,
        ),
        ("/api/v2/search", {"content": ECHO_MARKER.encode()}, ToolFailureCode.INVALID_ARGUMENTS),
        ("/api/v2/search", {"json": [ECHO_MARKER]}, ToolFailureCode.INVALID_ARGUMENTS),
        ("/api/v2/search", {"json": [["query", "ausf"]]}, ToolFailureCode.INVALID_ARGUMENTS),
        ("/api/v2/search", {"content": b"null"}, ToolFailureCode.INVALID_ARGUMENTS),
        (
            "/api/v2/search",
            {"content": b"[" * 100_000 + b"]" * 100_000},
            ToolFailureCode.INVALID_ARGUMENTS,
        ),
        (
            "/api/v2/search",
            {"json": {"query": "x" * 100_000}},
            ToolFailureCode.ARGUMENTS_TOO_LARGE,
        ),
        (
            "/api/v2/investigate",
            {"json": {"query": ECHO_MARKER, "scope": ECHO_MARKER}},
            ToolFailureCode.INVALID_ARGUMENTS,
        ),
    ],
    ids=[
        "wrong_type",
        "unexpected_field",
        "not_json",
        "not_an_object",
        "array_of_pairs",
        "null",
        "nested_too_deep",
        "arguments_too_large",
        "unknown_scope",
    ],
)
async def test_body_the_tool_cannot_take_is_its_failure_with_its_status_and_no_echo(
    api_client: httpx2.AsyncClient,
    path: str,
    request_options: dict[str, Any],
    expected_code: ToolFailureCode,
) -> None:
    answer = await api_client.post(path, **request_options)

    assert read_tool_failure(answer).code is expected_code
    assert ECHO_MARKER not in answer.text


@pytest.mark.parametrize(
    ("evidence_id", "expected_code"),
    [
        (UNKNOWN_EVIDENCE_ID, ToolFailureCode.UNKNOWN_EVIDENCE_ID),
        (ECHO_MARKER, ToolFailureCode.INVALID_ARGUMENTS),
        ("ev%3A" + "0" * 24, ToolFailureCode.INVALID_ARGUMENTS),
    ],
    ids=["unknown", "not_an_evidence_id", "percent_encoded"],
)
async def test_evidence_id_the_catalogue_does_not_serve_is_its_failure_with_its_status(
    api_client: httpx2.AsyncClient, evidence_id: str, expected_code: ToolFailureCode
) -> None:
    answer = await api_client.get(f"/api/v2/evidence/{evidence_id}")

    assert read_tool_failure(answer).code is expected_code
    assert ECHO_MARKER not in answer.text


async def test_evidence_id_that_is_not_ascii_is_invalid_arguments(
    fixture_bundle: FixtureBundle,
) -> None:
    api_app = build_test_api(fixture_bundle)

    answer = await send_request(api_app, AsgiRequest(target="/api/v2/evidence/év".encode()))

    assert answer.status == 422
    assert ToolFailure.model_validate_json(answer.body).code is ToolFailureCode.INVALID_ARGUMENTS


async def test_tool_that_raises_is_internal_error_500_without_its_error_text(
    fixture_bundle: FixtureBundle,
) -> None:
    toolbox = build_test_toolbox(
        fixture_bundle, lexical_retriever=RaisingRetriever(SECRET_ERROR_TEXT)
    )

    answer = await call_api(
        build_test_api(fixture_bundle, toolbox), "POST", "/api/v2/search", json={"query": "ausf"}
    )

    assert read_tool_failure(answer).code is ToolFailureCode.INTERNAL_ERROR
    assert "secret" not in answer.text


async def test_tool_that_runs_out_of_time_is_timed_out_504(
    fixture_bundle: FixtureBundle, blocked_call_release: threading.Event
) -> None:
    toolbox = build_test_toolbox(
        fixture_bundle,
        tool_clock=SteppingClock(seconds_per_read=0.03).read,
        limits=ToolLimits(time_limit_seconds=0.05, affectedness_timeout_seconds=0.04),
        lexical_retriever=BlockingRetriever(blocked_call_release),
    )

    answer = await call_api(
        build_test_api(fixture_bundle, toolbox), "POST", "/api/v2/search", json={"query": "ausf"}
    )

    assert read_tool_failure(answer).code is ToolFailureCode.TIMED_OUT


async def test_call_while_every_worker_is_busy_is_server_busy_503(
    fixture_bundle: FixtureBundle, blocked_call_release: threading.Event
) -> None:
    blocking_retriever = BlockingRetriever(blocked_call_release)
    toolbox = build_test_toolbox(
        fixture_bundle,
        limits=ToolLimits(max_calls_in_flight=1),
        lexical_retriever=blocking_retriever,
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        blocked_call = executor.submit(
            toolbox.call, KnowledgeToolName.SEARCH_VULNERABILITIES, {"query": "ausf"}
        )
        assert blocking_retriever.entered.wait(timeout=GENEROUS_WAIT_SECONDS)

        answer = await call_api(
            build_test_api(fixture_bundle, toolbox), "GET", "/api/v2/capabilities"
        )

        blocked_call_release.set()
        blocked_call.result(timeout=GENEROUS_WAIT_SECONDS)

    assert read_tool_failure(answer).code is ToolFailureCode.SERVER_BUSY


def build_marked_malformed_set(fixture_bundle: FixtureBundle) -> bytes:
    return b"{" + ECHO_MARKER.encode()


def build_set_whose_replay_differs(fixture_bundle: FixtureBundle) -> bytes:
    return forge_set_whose_replay_differs(fixture_bundle).model_dump_json().encode()


@pytest.mark.parametrize(
    ("build_body", "expected_verdict"),
    [
        (build_marked_malformed_set, VerificationVerdict.MALFORMED),
        (build_set_whose_replay_differs, VerificationVerdict.REPLAY_DIFFERS),
    ],
    ids=["malformed", "replay_differs"],
)
async def test_verification_answers_every_verdict_with_200(
    fixture_bundle: FixtureBundle,
    build_body: Callable[[FixtureBundle], bytes],
    expected_verdict: VerificationVerdict,
) -> None:
    check = build_evidence_set_check(fixture_bundle, fight="failing")

    answer = await call_api(
        build_test_api(fixture_bundle, check=check),
        "POST",
        "/api/v2/verify",
        content=build_body(fixture_bundle),
    )

    assert answer.status_code == 200
    assert VerificationReport.model_validate_json(answer.content).verdict is expected_verdict
    assert ECHO_MARKER not in answer.text


class RecordingCheck:
    """An evidence-set check that records the size of each set and answers ``malformed``."""

    def __init__(self) -> None:
        self.checked_sizes: list[int] = []

    def __call__(self, evidence_set_bytes: bytes) -> VerificationReport:
        self.checked_sizes.append(len(evidence_set_bytes))
        return VerificationReport(verdict=VerificationVerdict.MALFORMED, violations=("x",))


async def test_verification_takes_a_set_up_to_four_mib_and_refuses_a_larger_one_413(
    fixture_bundle: FixtureBundle,
) -> None:
    check = RecordingCheck()
    api_app = build_test_api(fixture_bundle, check=check)

    accepted_answer = await call_api(
        api_app, "POST", "/api/v2/verify", content=b" " * VERIFY_BODY_CAP_BYTES
    )
    refused_answer = await call_api(
        api_app, "POST", "/api/v2/verify", content=b" " * (VERIFY_BODY_CAP_BYTES + 1)
    )

    assert accepted_answer.status_code == 200
    assert refused_answer.status_code == 413
    assert HttpRejection.model_validate_json(refused_answer.content).code is (
        HttpRejectionCode.BODY_TOO_LARGE
    )
    assert check.checked_sizes == [VERIFY_BODY_CAP_BYTES]


@pytest.mark.parametrize("path", ["/api/v2/search", "/api/v2/investigate"], ids=str)
async def test_tool_route_keeps_the_256_kib_cap(api_client: httpx2.AsyncClient, path: str) -> None:
    answer = await api_client.post(path, content=b" " * (ROUTE_BODY_CAP_BYTES + 1))

    assert answer.status_code == 413
    assert (
        HttpRejection.model_validate_json(answer.content).code is HttpRejectionCode.BODY_TOO_LARGE
    )


class BlockingCheck:
    """An evidence-set check that blocks until ``release`` is set, then answers
    ``malformed``; ``entered`` is set when a check starts and ``returned`` when the
    first one returns."""

    def __init__(self, release: threading.Event) -> None:
        self.release = release
        self.entered = threading.Event()
        self.returned = threading.Event()

    def __call__(self, evidence_set_bytes: bytes) -> VerificationReport:
        self.entered.set()
        self.release.wait()
        self.returned.set()
        return VerificationReport(verdict=VerificationVerdict.MALFORMED, violations=("x",))


async def send_until_not_busy(app: ASGIApp, verify_request: AsgiRequest) -> AsgiAnswer:
    """The first answer to ``verify_request`` other than 503: the route frees itself on
    its worker thread just after the check returns."""
    with anyio.fail_after(GENEROUS_WAIT_SECONDS):
        while True:
            answer = await send_request(app, verify_request)
            if answer.status != 503:
                return answer
            await anyio.sleep(0.01)


async def test_second_verification_while_one_runs_is_route_busy_503(
    fixture_bundle: FixtureBundle, blocked_call_release: threading.Event
) -> None:
    check = BlockingCheck(blocked_call_release)
    api_app = build_test_api(fixture_bundle, check=check)
    first_answers: list[httpx2.Response] = []

    async with open_app_client(api_app) as http_client, anyio.create_task_group() as task_group:
        task_group.start_soon(post_verification, http_client, first_answers)
        with anyio.fail_after(GENEROUS_WAIT_SECONDS):
            await anyio.to_thread.run_sync(check.entered.wait)
        busy_answer = await http_client.post("/api/v2/verify", content=b"{}")
        blocked_call_release.set()
    later_answer = await send_until_not_busy(
        api_app, AsgiRequest(method="POST", target=b"/api/v2/verify", body_parts=(b"{}",))
    )

    assert busy_answer.status_code == 503
    assert HttpRejection.model_validate_json(busy_answer.content).code is (
        HttpRejectionCode.ROUTE_BUSY
    )
    assert first_answers[0].status_code == 200
    assert later_answer.status == 200


def build_verification_guard(check: EvidenceSetCheck, deadline_seconds: float) -> HttpGuard:
    """A guard serving only ``POST /verify`` over ``check``, with ``deadline_seconds``."""
    return HttpGuard(
        routes={"/verify": GuardedRoute(methods=frozenset({"POST"}), app=VerificationRoute(check))},
        lifespan_app=answer_nothing,
        host=HTTP_HOST,
        port=HTTP_PORT,
        token=HTTP_SECRET_TOKEN,
        request_deadline_seconds=deadline_seconds,
    )


async def test_check_abandoned_at_its_deadline_keeps_the_route_until_it_returns(
    blocked_call_release: threading.Event,
) -> None:
    check = BlockingCheck(blocked_call_release)
    guard = build_verification_guard(check, deadline_seconds=0.2)
    verify_request = AsgiRequest(method="POST", target=b"/verify", body_parts=(b"{}",))

    with anyio.fail_after(GENEROUS_WAIT_SECONDS):
        abandoned_answer = await send_request(guard, verify_request)
    busy_answer = await send_request(guard, verify_request)
    blocked_call_release.set()
    await anyio.to_thread.run_sync(check.returned.wait)
    later_answer = await send_until_not_busy(guard, verify_request)

    assert abandoned_answer.status == 504
    assert busy_answer.status == 503
    assert HttpRejection.model_validate_json(busy_answer.body).code is HttpRejectionCode.ROUTE_BUSY
    assert later_answer.status == 200


async def test_verification_cancelled_before_its_check_starts_does_not_hold_the_route() -> None:
    """A request cancelled while its check is still being handed to a worker thread, as
    the deadline can cancel one whose body arrived just before it, leaves the route free."""
    check = RecordingCheck()
    route = VerificationRoute(check)
    verify_request = AsgiRequest(method="POST", target=b"/verify", body_parts=(b"{}",))

    with anyio.CancelScope() as cancelled_scope:
        cancelled_scope.cancel()
        await send_request(route, verify_request)
    later_answer = await send_request(route, verify_request)

    assert later_answer.status == 200
    assert check.checked_sizes == [2]


async def post_verification(
    http_client: httpx2.AsyncClient, answers: list[httpx2.Response]
) -> None:
    answers.append(await http_client.post("/api/v2/verify", content=b"{}"))


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/v2/search"),
        ("GET", "/api/v2/investigate"),
        ("POST", "/api/v2/capabilities"),
        ("POST", f"/api/v2/evidence/{FIXTURE_EVIDENCE_ID}"),
        ("GET", "/api/v2/verify"),
    ],
    ids=["get_search", "get_investigate", "post_capabilities", "post_evidence", "get_verify"],
)
async def test_route_refuses_a_method_it_does_not_take_405(
    api_client: httpx2.AsyncClient, method: str, path: str
) -> None:
    answer = await api_client.request(method, path)

    assert answer.status_code == 405
    assert HttpRejection.model_validate_json(answer.content).code is (
        HttpRejectionCode.METHOD_NOT_ALLOWED
    )


async def test_every_api_route_needs_the_token(fixture_bundle: FixtureBundle) -> None:
    api_app = build_test_api(fixture_bundle)
    unauthenticated_answers: list[int] = []

    async with open_app_client(api_app, headers={}) as http_client:
        for method, path in [
            ("GET", "/api/v2/capabilities"),
            ("POST", "/api/v2/search"),
            ("POST", "/api/v2/investigate"),
            ("GET", f"/api/v2/evidence/{FIXTURE_EVIDENCE_ID}"),
            ("POST", "/api/v2/verify"),
            ("GET", "/ready"),
        ]:
            unauthenticated_answers.append((await http_client.request(method, path)).status_code)
        health_status = (await http_client.get("/health")).status_code

    assert unauthenticated_answers == [401] * 6
    assert health_status == 204


@pytest.fixture
def served_api() -> Iterator[ServedHttp]:
    """``cve-kgrag api`` on a free 127.0.0.1 port."""
    yield from start_served_http(["api"], "CVE_KGRAG_API_PORT", HTTP_HOST)


def test_cve_kgrag_api_serves_the_routes_logs_nothing_and_stops_on_interrupt(
    served_api: ServedHttp,
) -> None:
    capabilities_answer = httpx2.get(f"{served_api.url}/api/v2/capabilities", headers=AUTHORIZATION)
    investigation_answer = httpx2.post(
        f"{served_api.url}/api/v2/investigate",
        json={"query": "5gaka", "scope": "protocol_context_only"},
        headers=AUTHORIZATION,
        timeout=SERVER_START_SECONDS,
    )
    verification_answer = httpx2.post(
        f"{served_api.url}/api/v2/verify",
        content=investigation_answer.content,
        headers=AUTHORIZATION,
        timeout=SERVER_START_SECONDS,
    )
    served_api.process.send_signal(signal.SIGINT)
    stdout, stderr = served_api.process.communicate(timeout=GENEROUS_WAIT_SECONDS)

    assert capabilities_answer.status_code == 200
    assert "server" not in capabilities_answer.headers
    assert json.loads(verification_answer.content)["verdict"] == "verified"
    assert served_api.process.returncode == 0
    assert stdout == b""
    assert stderr == b""


def test_cve_kgrag_api_on_a_port_in_use_exits_one_saying_why() -> None:
    server_process = run_on_a_port_in_use(["api"], "CVE_KGRAG_API_PORT")

    assert server_process.returncode == 1
    assert server_process.stdout == b""
    assert b"address already in use" in server_process.stderr
    assert HTTP_TOKEN.encode() not in server_process.stderr
