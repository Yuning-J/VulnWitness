"""CLI behavior: exit codes and output shape."""

import json
import logging
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import SecretStr, TypeAdapter

from cve_kgrag.adapter_discovery import MCP_EXTRA_MISSING_DETAIL, InterfaceUnavailable
from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.application.investigation_policy import describe_deterministic_planner
from cve_kgrag.cli import (
    MAX_EVIDENCE_SET_FILE_BYTES,
    OVERSIZED_EVIDENCE_SET_MESSAGE,
    main,
    print_verification,
    run_evidence_lookup,
    run_mcp_http_server,
    run_mcp_server,
)
from cve_kgrag.composition import (
    build_investigation_deployment,
    build_search_service,
    build_topic_context_service,
)
from cve_kgrag.domain.affectedness import AffectednessCheck, ApplicabilityStatus
from cve_kgrag.domain.budget import InvestigationBudget
from cve_kgrag.domain.evidence import seal_evidence_anchor
from cve_kgrag.domain.evidence_set_verification_report import (
    VerificationReport,
    VerificationVerdict,
)
from cve_kgrag.domain.investigation import (
    KnowledgeEvidenceSet,
    PlannerOutcome,
    SourceCapability,
    SourceCapabilityState,
    describe_planner_capability,
)
from cve_kgrag.domain.planning import (
    ModelPlannerIdentity,
    ModelPlannerUnavailableDetail,
    ModelReplyFailureDetail,
)
from cve_kgrag.domain.search import (
    ChannelOutcome,
    SearchFilters,
    SearchRequest,
    SearchResponse,
    SemanticUnavailableDetail,
)
from cve_kgrag.domain.taxonomy import (
    AssertionKind,
    BackendFailureDetail,
    BackendStatus,
    RetrievalChannel,
)
from cve_kgrag.domain.tool_contracts import ConceptResolution, EvidenceLookup, KnowledgeCapabilities
from cve_kgrag.domain.topic_context import TopicContextRequest, TopicContextResponse
from cve_kgrag.interfaces.knowledge_toolbox import KnowledgeToolbox
from cve_kgrag.interfaces.knowledge_tools import KnowledgeToolName
from tests.support.fake_chat_server import (
    FakeChatServer,
    FakeChatServers,
    ScriptedAnswer,
    build_completion_body,
)
from tests.support.fakes import ExtraEvidenceFightSource
from tests.support.investigation import (
    DEPLOYMENT_VIOLATION,
    choose_fight_source,
    list_packaged_fight_anchors,
    reseal_evidence_set,
    rewrite_step,
)
from tests.support.investigation_runs import run_model_accepted
from tests.support.paths import REPOSITORY_SCHEMA_DIR
from tests.support.secrets import assert_secret_absent
from tests.support.toolbox import FIXTURE_EVIDENCE_ID, UNKNOWN_EVIDENCE_ID, require_answer

FORGED_SHA256 = "f" * 64
NO_SETTINGS: Mapping[str, str] = {}
CLI_PLANNER_KEY = "sk-test-cli-planner-key-0123456789"
INSTALLED_PLANNER_ADAPTER = "cve_kgrag.adapters.planner.openai_compatible:build_model_port"
SEARCH_5G_AKA = {"tool": "cve_search", "query": "5g aka"}
# A model planner enabled without its key: investigations plan deterministically and
# report it unavailable. No adapter is reached, installed or not.
PLANNER_WITHOUT_A_KEY = {
    "CVE_KGRAG_PLANNER_ENABLED": "true",
    "CVE_KGRAG_PLANNER_BASE_URL": "https://planner.invalid/v1",
    "CVE_KGRAG_PLANNER_MODEL_NAME": "example-chat",
}


HTTP_TOKEN = "Kq3vY8xN2pL5sT7wB9dF1gH4jM6zC0aE-tR8uI2oP5a"
HTTP_LISTENER: dict[str, Any] = {"host": "::1", "port": 9001, "token": SecretStr(HTTP_TOKEN)}


def run_cli(arguments: list[str], environment: Mapping[str, str] = NO_SETTINGS) -> int:
    """``cve-kgrag`` with ``arguments`` and the settings ``environment`` holds, never the
    environment the tests run in."""
    return main(arguments, environment)


class RecordingMcpServerRunner:
    """An MCP server runner that records the toolbox it is handed and returns at once, as
    the stdio runner does when the client closes stdin."""

    def __init__(self) -> None:
        self.served_toolboxes: list[KnowledgeToolbox] = []

    def __call__(self, toolbox: KnowledgeToolbox) -> None:
        self.served_toolboxes.append(toolbox)


class RecordingMcpHttpServerRunner:
    """An MCP HTTP server runner that records what it is handed and returns at once, as
    the HTTP runner does when the process is interrupted, or when its server could not
    start unless ``has_served``."""

    def __init__(self, has_served: bool = True) -> None:
        self._has_served = has_served
        self.served_toolboxes: list[KnowledgeToolbox] = []
        self.listeners: list[tuple[str, int, str]] = []

    def __call__(
        self, toolbox: KnowledgeToolbox, *, host: str, port: int, token: SecretStr
    ) -> bool:
        self.served_toolboxes.append(toolbox)
        self.listeners.append((host, port, token.get_secret_value()))
        return self._has_served


def test_demo_runs_offline_and_reports_each_query(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_cli(["demo"])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert output.count('"result_sha256"') == 5
    assert '"status": "no_match"' in output


def test_lookup_known_id_prints_valid_response_and_exits_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = run_cli(["lookup", "cve-9999-0005"])

    response = SearchResponse.model_validate_json(capsys.readouterr().out)
    assert exit_code == 0
    assert response.candidates[0].record.kev is not None


def test_lookup_unknown_id_exits_one(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_cli(["lookup", "CVE-9999-4242"])

    assert exit_code == 1
    assert json.loads(capsys.readouterr().out)["status"] == "no_match"


def test_lookup_malformed_id_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as raised:
        run_cli(["lookup", "not-a-cve"])

    assert raised.value.code == 2


def test_schema_check_passes_against_committed_snapshots() -> None:
    assert run_cli(["schema", "check", "--dir", str(REPOSITORY_SCHEMA_DIR)]) == 0


def test_schema_check_reports_drift_for_empty_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = run_cli(["schema", "check", "--dir", str(tmp_path)])

    assert exit_code == 1
    assert "missing search_response.schema.json" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("arguments", "expected_exit_code", "expected_status"),
    [
        (["investigate", "5gaka", "--scope", "protocol_context_only"], 0, "ok"),
        (["investigate", "aka", "--scope", "mixed"], 1, "no_match"),
        (
            ["investigate", "5gaka", "--scope", "implementation_only", "--product", "open5gs"],
            1,
            "partial",
        ),
    ],
    ids=["protocol_topic", "excluded_alias", "unknown_affectedness"],
)
def test_investigate_prints_an_evidence_set_and_exits_zero_only_when_ok(
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
    expected_exit_code: int,
    expected_status: str,
) -> None:
    exit_code = run_cli(arguments)

    evidence_set = KnowledgeEvidenceSet.model_validate_json(capsys.readouterr().out)
    assert exit_code == expected_exit_code
    assert evidence_set.status.value == expected_status


@pytest.mark.parametrize(
    "arguments",
    [
        ["investigate", "5gaka"],
        ["investigate", "5gaka", "--scope", "protocol_only"],
        ["investigate", "5gaka", "--scope", "mixed", "--purl", "not a purl"],
        ["investigate", "5gaka", "--scope", "mixed", "--vendor", "acme", "--vendor", "acme"],
    ],
    ids=["missing_scope", "unknown_scope", "malformed_purl", "duplicate_vendor"],
)
def test_investigate_with_invalid_arguments_is_a_usage_error(arguments: list[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        run_cli(arguments)

    assert raised.value.code == 2


@pytest.fixture
def sealed_set(capsys: pytest.CaptureFixture[str]) -> KnowledgeEvidenceSet:
    """The set ``cve-kgrag investigate`` prints for a protocol-context question."""
    run_cli(["investigate", "5gaka", "--scope", "protocol_context_only"])
    return KnowledgeEvidenceSet.model_validate_json(capsys.readouterr().out)


def write_evidence_set_file(directory: Path, evidence_set_bytes: bytes) -> Path:
    evidence_set_path = directory / "evidence_set.json"
    evidence_set_path.write_bytes(evidence_set_bytes)
    return evidence_set_path


def verify_file(
    directory: Path,
    evidence_set_bytes: bytes,
    capsys: pytest.CaptureFixture[str],
    environment: Mapping[str, str] = NO_SETTINGS,
) -> tuple[int, dict[str, Any]]:
    """``cve-kgrag verify`` on a file holding ``evidence_set_bytes`` under ``environment``:
    its exit code and the report it prints."""
    exit_code = run_cli(
        ["verify", str(write_evidence_set_file(directory, evidence_set_bytes))], environment
    )
    return exit_code, json.loads(capsys.readouterr().out)


def test_verify_sealed_set_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sealed_set: KnowledgeEvidenceSet
) -> None:
    exit_code, verification_report = verify_file(
        tmp_path, sealed_set.model_dump_json().encode(), capsys
    )

    assert exit_code == 0
    assert verification_report == {"verdict": "verified", "violations": [], "differences": []}


def test_verify_forged_set_exits_one_with_violations(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sealed_set: KnowledgeEvidenceSet
) -> None:
    forged_set = reseal_evidence_set(sealed_set, source_capabilities=())

    exit_code, verification_report = verify_file(
        tmp_path, forged_set.model_dump_json().encode(), capsys
    )

    assert exit_code == 1
    assert verification_report["verdict"] == "invalid"
    assert DEPLOYMENT_VIOLATION in verification_report["violations"]


def test_verify_model_planned_set_exits_one_as_invalid(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], fixture_bundle: FixtureBundle
) -> None:
    """The packaged deployment plans deterministically, so a set reporting a model planner
    reports a capability it does not serve."""
    model_planned_set = run_model_accepted(fixture_bundle)

    exit_code, verification_report = verify_file(
        tmp_path, model_planned_set.model_dump_json().encode(), capsys
    )

    assert exit_code == 1
    assert verification_report["verdict"] == "invalid"
    assert DEPLOYMENT_VIOLATION in verification_report["violations"]


def test_verify_set_whose_replay_differs_exits_one_naming_the_part(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sealed_set: KnowledgeEvidenceSet
) -> None:
    forged_set = rewrite_step(sealed_set, 1, result_sha256=FORGED_SHA256)

    exit_code, verification_report = verify_file(
        tmp_path, forged_set.model_dump_json().encode(), capsys
    )

    assert exit_code == 1
    assert verification_report == {
        "verdict": "replay_differs",
        "violations": [],
        "differences": [{"step_index": 1, "part": "result_sha256"}],
    }


def test_verify_wrong_schema_version_reports_malformed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sealed_set: KnowledgeEvidenceSet
) -> None:
    evidence_set_document = json.loads(sealed_set.model_dump_json())
    evidence_set_document["schema_version"] = "2.0.0-dev.1"

    exit_code, verification_report = verify_file(
        tmp_path, json.dumps(evidence_set_document).encode(), capsys
    )

    assert exit_code == 1
    assert verification_report["verdict"] == "malformed"
    assert verification_report["violations"][0].startswith("schema_version: ")


def test_verify_reports_at_most_one_hundred_violations(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code, verification_report = verify_file(
        tmp_path, json.dumps({"warnings": [0] * 150}).encode(), capsys
    )

    assert exit_code == 1
    assert verification_report["verdict"] == "malformed"
    assert len(verification_report["violations"]) == 100


def test_verify_file_at_the_size_cap_is_read_and_parsed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code, verification_report = verify_file(
        tmp_path, b" " * MAX_EVIDENCE_SET_FILE_BYTES, capsys
    )

    assert exit_code == 1
    assert verification_report["verdict"] == "malformed"


def test_verify_oversized_file_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    oversized_path = write_evidence_set_file(tmp_path, b" " * (MAX_EVIDENCE_SET_FILE_BYTES + 1))

    with pytest.raises(SystemExit) as raised:
        run_cli(["verify", str(oversized_path)])

    assert raised.value.code == 2
    assert OVERSIZED_EVIDENCE_SET_MESSAGE in capsys.readouterr().err


def test_verify_missing_file_exits_two(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as raised:
        run_cli(["verify", str(tmp_path / "missing.json")])

    assert raised.value.code == 2


def test_report_other_than_verified_prints_and_exits_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = print_verification(VerificationReport(verdict=VerificationVerdict.REPLAY_TIMED_OUT))

    assert exit_code == 1
    assert json.loads(capsys.readouterr().out) == {
        "verdict": "replay_timed_out",
        "violations": [],
        "differences": [],
    }


@pytest.mark.parametrize(
    "detail",
    [
        MCP_EXTRA_MISSING_DETAIL,
        "mcp_server adapter entry point is not installed",
        "more than one mcp_server adapter is installed",
        "mcp_server adapter could not load: ImportError",
    ],
    ids=["extra_missing", "no_entry_point", "duplicate_runners", "failed_load"],
)
def test_mcp_with_an_unusable_runner_exits_one_naming_the_reason(
    capsys: pytest.CaptureFixture[str], detail: str
) -> None:
    exit_code = run_mcp_server(InterfaceUnavailable(detail))

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == f"cve-kgrag mcp cannot start: {detail}\n"


def test_mcp_serves_the_packaged_fixture_toolbox_and_exits_zero_when_the_runner_returns(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = RecordingMcpServerRunner()

    exit_code = run_mcp_server(runner)

    assert exit_code == 0
    assert capsys.readouterr().out == ""
    assert len(runner.served_toolboxes) == 1
    lookup_answer = require_answer(
        runner.served_toolboxes[0].call(KnowledgeToolName.LOOKUP_CVE, {"cve_id": "CVE-9999-0003"})
    )
    assert lookup_answer.structured_content["status"] == "ok"


def test_mcp_http_without_a_token_is_a_usage_error_naming_the_variable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        run_cli(["mcp", "--http"])

    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert captured.out == ""
    assert "invalid settings: CVE_KGRAG_HTTP_TOKEN: required by mcp --http" in captured.err


def test_mcp_http_with_an_unusable_runner_exits_one_naming_the_reason(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = run_mcp_http_server(InterfaceUnavailable(MCP_EXTRA_MISSING_DETAIL), **HTTP_LISTENER)

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == f"cve-kgrag mcp --http cannot start: {MCP_EXTRA_MISSING_DETAIL}\n"


def test_mcp_http_serves_the_packaged_fixture_on_the_listener_it_is_given(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = RecordingMcpHttpServerRunner()

    exit_code = run_mcp_http_server(runner, **HTTP_LISTENER)

    assert exit_code == 0
    assert capsys.readouterr().out == ""
    assert runner.listeners == [("::1", 9001, HTTP_TOKEN)]
    lookup_answer = require_answer(
        runner.served_toolboxes[0].call(KnowledgeToolName.LOOKUP_CVE, {"cve_id": "CVE-9999-0003"})
    )
    assert lookup_answer.structured_content["status"] == "ok"


def test_mcp_http_whose_server_could_not_start_exits_one() -> None:
    exit_code = run_mcp_http_server(RecordingMcpHttpServerRunner(has_served=False), **HTTP_LISTENER)

    assert exit_code == 1


def test_invalid_settings_are_a_usage_error_naming_the_variable_not_its_value(
    capsys: pytest.CaptureFixture[str],
) -> None:
    credential_url = "https://planner-user:hunter2-password@planner.invalid/v1"
    environment = {**PLANNER_WITHOUT_A_KEY, "CVE_KGRAG_PLANNER_BASE_URL": credential_url}

    with pytest.raises(SystemExit) as raised:
        run_cli(["demo"], environment)

    error_output = capsys.readouterr().err
    assert raised.value.code == 2
    assert "CVE_KGRAG_PLANNER_BASE_URL" in error_output
    assert "hunter2-password" not in error_output


def test_investigate_with_a_planner_missing_its_key_plans_deterministically_and_says_why(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = run_cli(
        ["investigate", "5gaka", "--scope", "protocol_context_only"], PLANNER_WITHOUT_A_KEY
    )

    evidence_set = KnowledgeEvidenceSet.model_validate_json(capsys.readouterr().out)
    assert exit_code == 0
    assert evidence_set.trajectory.planner == describe_deterministic_planner()
    assert evidence_set.source_capabilities[-1] == describe_planner_capability(
        describe_deterministic_planner(), ModelPlannerUnavailableDetail.MISSING_API_KEY
    )


@pytest.mark.parametrize(
    ("environment", "expected_verdict"),
    [(PLANNER_WITHOUT_A_KEY, "verified"), (NO_SETTINGS, "invalid")],
    ids=["same_settings", "planner_not_configured"],
)
def test_verify_set_sealed_without_a_planner_key_holds_only_under_the_settings_that_sealed_it(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    environment: Mapping[str, str],
    expected_verdict: str,
) -> None:
    run_cli(["investigate", "5gaka", "--scope", "protocol_context_only"], PLANNER_WITHOUT_A_KEY)
    sealed_bytes = capsys.readouterr().out.encode()

    exit_code, verification_report = verify_file(tmp_path, sealed_bytes, capsys, environment)

    assert verification_report["verdict"] == expected_verdict
    assert exit_code == (0 if expected_verdict == "verified" else 1)


def test_verify_deterministic_set_holds_under_an_enabled_planner(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sealed_set: KnowledgeEvidenceSet
) -> None:
    """The MCP tools always plan deterministically, so an enabled planner still accepts
    the sets they seal."""
    exit_code, verification_report = verify_file(
        tmp_path, sealed_set.model_dump_json().encode(), capsys, PLANNER_WITHOUT_A_KEY
    )

    assert exit_code == 0
    assert verification_report["verdict"] == "verified"


def test_main_without_an_environment_reads_the_process_environment(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The entry point is where settings are read, so the process environment is its input."""
    monkeypatch.setenv("CVE_KGRAG_PLANNER_ENABLED", "maybe")

    with pytest.raises(SystemExit) as raised:
        main(["demo"])

    assert raised.value.code == 2
    assert "CVE_KGRAG_PLANNER_ENABLED" in capsys.readouterr().err


def build_planner_environment(server: FakeChatServer) -> dict[str, str]:
    """Settings enabling the planner adapter against ``server`` on loopback http."""
    return {
        "CVE_KGRAG_PLANNER_ENABLED": "true",
        "CVE_KGRAG_PLANNER_BASE_URL": f"{server.base_url}/v1",
        "CVE_KGRAG_PLANNER_MODEL_NAME": "example-chat",
        "CVE_KGRAG_PLANNER_API_KEY": CLI_PLANNER_KEY,
    }


def test_investigate_plans_with_the_installed_adapter_and_the_set_verifies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], fake_chat_servers: FakeChatServers
) -> None:
    server = fake_chat_servers.start(
        ScriptedAnswer(body=build_completion_body(json.dumps({"steps": [SEARCH_5G_AKA]})))
    )
    environment = build_planner_environment(server)

    exit_code = run_cli(["investigate", "5G-AKA", "--scope", "implementation_only"], environment)
    sealed_output = capsys.readouterr().out
    evidence_set = KnowledgeEvidenceSet.model_validate_json(sealed_output)
    verify_exit_code, verification_report = verify_file(
        tmp_path, sealed_output.encode(), capsys, environment
    )

    planner = evidence_set.trajectory.planner
    assert exit_code == 0
    assert isinstance(planner, ModelPlannerIdentity)
    assert planner.adapter == INSTALLED_PLANNER_ADAPTER
    assert evidence_set.trajectory.rounds[0].planner_outcome is PlannerOutcome.MODEL_ACCEPTED
    assert evidence_set.source_capabilities[-1].state is SourceCapabilityState.AVAILABLE
    assert server.received_requests[0].path == "/v1/chat/completions"
    assert (verify_exit_code, verification_report["verdict"]) == (0, "verified")


@pytest.mark.parametrize(
    ("status", "expected_detail"),
    [
        (401, ModelReplyFailureDetail.CREDENTIALS_REJECTED),
        (429, ModelReplyFailureDetail.RATE_LIMITED),
        (500, ModelReplyFailureDetail.ENDPOINT_ERROR),
        (200, ModelReplyFailureDetail.MALFORMED_RESPONSE),
    ],
    ids=["401", "429", "500", "200_echo"],
)
def test_endpoint_echoing_the_key_never_puts_it_in_the_set_output_or_log(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    fake_chat_servers: FakeChatServers,
    status: int,
    expected_detail: ModelReplyFailureDetail,
) -> None:
    """Every answer quotes the Authorization header it received; a 200 quotes it as the
    plan. The round records the server's sentence, and the set still verifies."""
    server = fake_chat_servers.start(ScriptedAnswer(status=status, echoes_authorization=True))
    environment = build_planner_environment(server)

    with caplog.at_level(logging.DEBUG):
        run_cli(["investigate", "5G-AKA", "--scope", "implementation_only"], environment)
    investigate_output = capsys.readouterr()
    evidence_set = KnowledgeEvidenceSet.model_validate_json(investigate_output.out)
    verify_exit_code, _ = verify_file(
        tmp_path, investigate_output.out.encode(), capsys, environment
    )

    model_reply = evidence_set.trajectory.rounds[0].model_reply
    assert model_reply is not None
    assert model_reply.detail is expected_detail
    assert verify_exit_code == 0
    assert_secret_absent(investigate_output.out, CLI_PLANNER_KEY, "stdout")
    assert_secret_absent(investigate_output.err, CLI_PLANNER_KEY, "stderr")
    assert_secret_absent(caplog.text, CLI_PLANNER_KEY, "the log")


def build_semantic_environment(persist_directory: Path) -> dict[str, str]:
    """Settings enabling the semantic channel over an empty directory: whether or not the
    ``semantic`` extra is installed, its adapter cannot open the collection."""
    return {
        "CVE_KGRAG_SEMANTIC_ENABLED": "true",
        "CVE_KGRAG_SEMANTIC_PERSIST_DIRECTORY": str(persist_directory),
    }


def test_semantic_investigation_on_an_unusable_adapter_says_so_and_never_verifies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    """``verify`` loads no semantic adapter, so a set that asked for the channel while it
    was enabled reports a capability ``verify`` does not serve, under any settings."""
    environment = build_semantic_environment(tmp_path / "vectors")

    with caplog.at_level(logging.DEBUG):
        exit_code = run_cli(
            ["investigate", "5G-AKA", "--scope", "implementation_only", "--semantic"], environment
        )
    sealed_output = capsys.readouterr()
    evidence_set = KnowledgeEvidenceSet.model_validate_json(sealed_output.out)
    same_settings = verify_file(tmp_path, sealed_output.out.encode(), capsys, environment)
    semantic_disabled = verify_file(tmp_path, sealed_output.out.encode(), capsys)

    assert exit_code == 1
    assert evidence_set.request.semantic is True
    assert evidence_set.source_capabilities[3] == SourceCapability(
        source="semantic_channel",
        state=SourceCapabilityState.UNAVAILABLE,
        detail=SemanticUnavailableDetail.ADAPTER_UNUSABLE,
    )
    assert_secret_absent(caplog.text, str(tmp_path), "the log")
    assert (same_settings[0], same_settings[1]["verdict"]) == (1, "invalid")
    assert (semantic_disabled[0], semantic_disabled[1]["verdict"]) == (1, "invalid")


def test_investigation_without_semantic_ignores_the_semantic_settings_and_verifies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    environment = build_semantic_environment(tmp_path / "vectors")

    run_cli(["investigate", "5G-AKA", "--scope", "implementation_only"], environment)
    sealed_output = capsys.readouterr().out
    evidence_set = KnowledgeEvidenceSet.model_validate_json(sealed_output)
    verify_exit_code, verification_report = verify_file(
        tmp_path, sealed_output.encode(), capsys, environment
    )

    assert evidence_set.source_capabilities[3].state is SourceCapabilityState.NOT_CONFIGURED
    assert (verify_exit_code, verification_report["verdict"]) == (0, "verified")


def test_semantic_search_on_an_unusable_adapter_reports_the_channel_failed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    environment = build_semantic_environment(tmp_path / "vectors")

    exit_code = run_cli(["search", "ausf crash", "--semantic"], environment)

    response = SearchResponse.model_validate_json(capsys.readouterr().out)
    semantic_outcomes: list[ChannelOutcome] = []
    for channel_outcome in response.channel_outcomes:
        if channel_outcome.channel is RetrievalChannel.SEMANTIC:
            semantic_outcomes.append(channel_outcome)
    assert exit_code == 1
    assert semantic_outcomes == [
        ChannelOutcome(
            channel=RetrievalChannel.SEMANTIC,
            status=BackendStatus.UNAVAILABLE,
            detail=BackendFailureDetail.ADAPTER_UNUSABLE,
        )
    ]


def test_semantic_topic_on_an_unusable_adapter_reports_the_channel_failed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    environment = build_semantic_environment(tmp_path / "vectors")

    run_cli(["topic", "5gaka", "--scope", "mixed", "--semantic"], environment)

    response = TopicContextResponse.model_validate_json(capsys.readouterr().out)
    semantic_failures: list[ChannelOutcome] = []
    for source_outcome in response.source_outcomes:
        for channel_failure in source_outcome.channel_failures:
            if channel_failure.channel is RetrievalChannel.SEMANTIC:
                semantic_failures.append(channel_failure)
    assert semantic_failures != []
    for channel_failure in semantic_failures:
        assert channel_failure.detail is BackendFailureDetail.ADAPTER_UNUSABLE


@pytest.mark.parametrize(
    "arguments",
    [
        ["lookup", "CVE-9999-0003"],
        ["demo"],
        ["search", "ausf crash"],
        ["topic", "5gaka", "--scope", "mixed"],
        ["investigate", "5G-AKA", "--scope", "implementation_only"],
        ["capabilities"],
        ["resolve", "5G-AKA"],
        ["evidence", FIXTURE_EVIDENCE_ID],
        ["affectedness", "CVE-9999-0003", "--purl", "pkg:generic/open5gs@2.7.0"],
    ],
    ids=[
        "lookup",
        "demo",
        "search",
        "topic",
        "investigate",
        "capabilities",
        "resolve",
        "evidence",
        "affectedness",
    ],
)
def test_command_that_does_not_ask_for_the_semantic_channel_loads_no_adapter(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, arguments: list[str]
) -> None:
    environment = build_semantic_environment(tmp_path / "vectors")

    with caplog.at_level(logging.DEBUG, logger="cve_kgrag.adapter_discovery"):
        exit_code = run_cli(arguments, environment)

    assert exit_code in (0, 1)
    assert caplog.records == []
    assert not (tmp_path / "vectors").exists()


# A query every vendor's records answer, so each filter has records to narrow.
BROAD_QUERY = "democorp fictional5g examplenet exampleorg"
BROAD_QUERY_IDS = [
    "CVE-9999-0005",
    "CVE-9999-0006",
    "CVE-9999-0001",
    "CVE-9999-0002",
    "CVE-9999-0003",
    "CVE-9999-0007",
    "CVE-9999-0004",
]
OPEN5GS_PURL = "pkg:generic/open5gs@2.7.0"


def list_distinct_cve_ids(count: int) -> list[str]:
    cve_ids: list[str] = []
    for number in range(count):
        cve_ids.append(f"CVE-9999-{1000 + number}")
    return cve_ids


def list_candidate_ids(response: SearchResponse) -> list[str]:
    candidate_ids: list[str] = []
    for candidate in response.candidates:
        candidate_ids.append(candidate.record.cve_id)
    return candidate_ids


def test_search_without_filters_returns_every_record_the_broad_query_names(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = run_cli(["search", BROAD_QUERY, "--limit", "20"])

    response = SearchResponse.model_validate_json(capsys.readouterr().out)
    assert exit_code == 0
    assert list_candidate_ids(response) == BROAD_QUERY_IDS


@pytest.mark.parametrize(
    ("filter_arguments", "expected_ids"),
    [
        (["--vendor", "democorp"], ["CVE-9999-0001", "CVE-9999-0002", "CVE-9999-0007"]),
        (["--product", "f5gc"], ["CVE-9999-0003", "CVE-9999-0004"]),
        (["--purl", "pkg:pypi/example-parser"], ["CVE-9999-0006"]),
        (["--cwe", "cwe-20"], ["CVE-9999-0003", "CVE-9999-0007"]),
        (["--severity", "critical"], ["CVE-9999-0005", "CVE-9999-0001"]),
        (["--year", "2025"], []),
        (["--origin", "configuration"], ["CVE-9999-0005"]),
        (["--kev-only"], ["CVE-9999-0005"]),
        (
            ["--severity", "HIGH", "--severity", "MEDIUM", "--vendor", "fictional5g"],
            ["CVE-9999-0003", "CVE-9999-0004"],
        ),
    ],
    ids=["vendor", "product", "purl", "cwe", "severity", "year", "origin", "kev_only", "combined"],
)
def test_search_filter_option_narrows_the_results_to_the_matching_records(
    capsys: pytest.CaptureFixture[str], filter_arguments: list[str], expected_ids: list[str]
) -> None:
    exit_code = run_cli(["search", BROAD_QUERY, "--limit", "20", *filter_arguments])

    response = SearchResponse.model_validate_json(capsys.readouterr().out)
    assert list_candidate_ids(response) == expected_ids
    assert exit_code == (0 if expected_ids else 1)


def test_search_year_keeps_the_dated_records_and_drops_the_undated_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = run_cli(["search", "democorp vulnerability", "--year", "2026"])

    response = SearchResponse.model_validate_json(capsys.readouterr().out)
    assert exit_code == 0
    assert list_candidate_ids(response) == ["CVE-9999-0001", "CVE-9999-0002", "CVE-9999-0007"]


def test_search_graph_expand_adds_the_records_the_graph_links(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = run_cli(["search", "injection", "--graph-expand"])

    response = SearchResponse.model_validate_json(capsys.readouterr().out)
    assert exit_code == 0
    assert list_candidate_ids(response) == ["CVE-9999-0001", "CVE-9999-0002", "CVE-9999-0007"]


def test_search_with_options_answers_as_the_service_does_for_the_same_request(
    fixture_bundle: FixtureBundle, capsys: pytest.CaptureFixture[str]
) -> None:
    expected_response = build_search_service(fixture_bundle).search(
        SearchRequest(
            query=BROAD_QUERY,
            limit=5,
            filters=SearchFilters(vendors=("democorp", "fictional5g"), cwe_ids=("CWE-20",)),
            graph_expand=True,
        )
    )

    run_cli(
        [
            "search",
            BROAD_QUERY,
            "--limit",
            "5",
            "--vendor",
            "democorp",
            "--vendor",
            "fictional5g",
            "--cwe",
            "CWE-20",
            "--graph-expand",
        ]
    )

    assert capsys.readouterr().out == expected_response.model_dump_json(indent=2) + "\n"


@pytest.mark.parametrize(
    "arguments",
    [
        ["search", "q", "--cwe", "20"],
        ["search", "q", "--severity", "SEVERE"],
        ["search", "q", "--year", "twenty"],
        ["search", "q", "--origin", "elsewhere"],
        ["search", "q", "--vendor", "a", "--vendor", "a"],
        ["topic", "5gaka", "--scope", "mixed", "--max-results-per-search", "0"],
        ["investigate", "5gaka", "--scope", "mixed", "--max-rounds", "3"],
        ["investigate", "5gaka", "--scope", "mixed", "--max-wall-time-seconds", "0"],
        ["resolve", ""],
        ["evidence", "ev:not-hex"],
        ["affectedness", "CVE-9999-0003", "--purl", "pkg:generic/open5gs"],
        ["affectedness", "CVE-9999-0003"],
        ["lookup", "CVE-2020-" + "1" * 600],
        ["affectedness", *list_distinct_cve_ids(21), "--purl", OPEN5GS_PURL],
    ],
    ids=[
        "cwe_without_prefix",
        "unknown_severity",
        "year_not_a_number",
        "unknown_origin",
        "repeated_vendor",
        "max_results_per_search_zero",
        "rounds_over_the_cap",
        "zero_wall_time",
        "empty_resolve_query",
        "malformed_evidence_id",
        "unversioned_purl",
        "affectedness_without_purl",
        "lookup_id_over_the_length_cap",
        "affectedness_over_twenty_ids",
    ],
)
def test_argument_the_contract_rejects_is_a_usage_error(arguments: list[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        run_cli(arguments)

    assert raised.value.code == 2


@pytest.mark.parametrize(
    ("budget_option", "budget_field", "value"),
    [
        ("--max-rounds", "max_rounds", 1),
        ("--max-tool-calls", "max_tool_calls", 3),
        ("--max-sources", "max_sources", 2),
        ("--max-results-per-call", "max_results_per_call", 5),
        ("--max-wall-time-seconds", "max_wall_time_seconds", 5),
        ("--max-context-bytes", "max_context_bytes", 65_536),
    ],
    ids=["rounds", "tool_calls", "sources", "results_per_call", "wall_time", "context_bytes"],
)
def test_investigate_budget_option_sets_its_field_and_leaves_the_others_at_their_caps(
    capsys: pytest.CaptureFixture[str], budget_option: str, budget_field: str, value: int
) -> None:
    expected_budget = InvestigationBudget().model_copy(update={budget_field: value})

    run_cli(
        [
            "investigate",
            "CVE-9999-0003",
            "--scope",
            "implementation_only",
            budget_option,
            str(value),
        ]
    )

    evidence_set = KnowledgeEvidenceSet.model_validate_json(capsys.readouterr().out)
    assert evidence_set.request.budget == expected_budget


def test_topic_max_results_per_search_reaches_the_request(
    fixture_bundle: FixtureBundle, capsys: pytest.CaptureFixture[str]
) -> None:
    expected_response = build_topic_context_service(fixture_bundle).explore(
        TopicContextRequest(query="5gaka", scope="mixed", max_results_per_search=1)
    )

    run_cli(["topic", "5gaka", "--scope", "mixed", "--max-results-per-search", "1"])

    assert capsys.readouterr().out == expected_response.model_dump_json(indent=2) + "\n"


def build_no_settings(tmp_path: Path) -> Mapping[str, str]:
    return NO_SETTINGS


def build_planner_without_a_key(tmp_path: Path) -> Mapping[str, str]:
    return PLANNER_WITHOUT_A_KEY


def build_unusable_semantic_adapter(tmp_path: Path) -> Mapping[str, str]:
    return build_semantic_environment(tmp_path / "vectors")


@pytest.mark.parametrize(
    ("build_environment", "semantic_arguments"),
    [
        (build_no_settings, []),
        (build_planner_without_a_key, []),
        (build_unusable_semantic_adapter, ["--semantic"]),
    ],
    ids=["no_settings", "planner_without_a_key", "unusable_semantic_adapter"],
)
def test_capabilities_prints_the_sources_investigate_reports_and_exits_zero(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    build_environment: Callable[[Path], Mapping[str, str]],
    semantic_arguments: list[str],
) -> None:
    environment = build_environment(tmp_path)

    exit_code = run_cli(["capabilities", *semantic_arguments], environment)
    capabilities = KnowledgeCapabilities.model_validate_json(capsys.readouterr().out)
    run_cli(
        ["investigate", "CVE-9999-0003", "--scope", "implementation_only", *semantic_arguments],
        environment,
    )
    evidence_set = KnowledgeEvidenceSet.model_validate_json(capsys.readouterr().out)

    assert exit_code == 0
    assert capabilities.source_capabilities == evidence_set.source_capabilities


def test_resolve_known_topic_prints_its_match_and_exits_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = run_cli(["resolve", "5G-AKA"])

    resolution = ConceptResolution.model_validate_json(capsys.readouterr().out)
    assert exit_code == 0
    assert resolution.resolution.matches != ()


def test_resolve_query_naming_no_topic_exits_one(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_cli(["resolve", "printer driver"])

    resolution = ConceptResolution.model_validate_json(capsys.readouterr().out)
    assert exit_code == 1
    assert resolution.resolution.matches == ()


def test_evidence_served_under_its_id_prints_it_and_exits_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = run_cli(["evidence", FIXTURE_EVIDENCE_ID])

    evidence_lookup = EvidenceLookup.model_validate_json(capsys.readouterr().out)
    assert exit_code == 0
    assert evidence_lookup.evidence.evidence_id == FIXTURE_EVIDENCE_ID


def test_unknown_evidence_id_exits_one_with_one_line_on_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = run_cli(["evidence", UNKNOWN_EVIDENCE_ID])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == f"no evidence anchor is served under {UNKNOWN_EVIDENCE_ID}\n"


def test_catalogued_anchor_failing_the_anchor_rules_exits_one_with_one_line_on_stderr(
    fixture_bundle: FixtureBundle, capsys: pytest.CaptureFixture[str]
) -> None:
    fight_anchor = list_packaged_fight_anchors()[0]
    inferred_anchor = seal_evidence_anchor(
        fight_anchor.model_copy(update={"assertion_kind": AssertionKind.INFERRED})
    )
    packaged_fight_source, pinned_fight_snapshot = choose_fight_source("packaged")
    deployment = build_investigation_deployment(
        fixture_bundle,
        fight_source=ExtraEvidenceFightSource(
            packaged_fight_source, extra_evidence=(inferred_anchor,)
        ),
        pinned_fight_snapshot=pinned_fight_snapshot,
    )

    exit_code = run_evidence_lookup(inferred_anchor.evidence_id, deployment)

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == (
        f"the anchor catalogued under {inferred_anchor.evidence_id} fails the anchor rules, "
        "so it is not served\n"
    )


def test_affectedness_prints_one_unknown_answer_per_cve_and_exits_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = run_cli(["affectedness", "CVE-9999-0003", "cve-9999-0004", "--purl", OPEN5GS_PURL])

    answers = TypeAdapter(list[AffectednessCheck]).validate_json(capsys.readouterr().out)
    answered_ids: list[str] = []
    applicabilities: list[ApplicabilityStatus] = []
    for answer in answers:
        answered_ids.append(answer.request.cve_id)
        applicabilities.append(answer.applicability)
    assert exit_code == 1
    assert answered_ids == ["CVE-9999-0003", "CVE-9999-0004"]
    assert applicabilities == [ApplicabilityStatus.UNKNOWN, ApplicabilityStatus.UNKNOWN]


def test_verify_prints_the_verified_report_text_exactly(
    tmp_path: Path, sealed_set: KnowledgeEvidenceSet, capsys: pytest.CaptureFixture[str]
) -> None:
    evidence_set_path = write_evidence_set_file(tmp_path, sealed_set.model_dump_json().encode())

    run_cli(["verify", str(evidence_set_path)])

    assert capsys.readouterr().out == (
        '{\n  "verdict": "verified",\n  "violations": [],\n  "differences": []\n}\n'
    )


def test_verify_prints_the_malformed_report_text_exactly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    evidence_set_path = write_evidence_set_file(tmp_path, b"[]")

    run_cli(["verify", str(evidence_set_path)])

    assert capsys.readouterr().out == (
        '{\n  "verdict": "malformed",\n  "violations": [\n'
        '    "Input should be an object"\n  ],\n  "differences": []\n}\n'
    )


def test_report_prints_non_ascii_violation_text_ascii_escaped(
    capsys: pytest.CaptureFixture[str],
) -> None:
    print_verification(VerificationReport(verdict=VerificationVerdict.INVALID, violations=("été",)))

    first_violation_line = capsys.readouterr().out.splitlines()[3]
    assert first_violation_line == '    "\\u00e9t\\u00e9"'


def test_verify_reports_unexpected_fields_as_a_count_without_their_names(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sealed_set: KnowledgeEvidenceSet
) -> None:
    evidence_set_document = json.loads(sealed_set.model_dump_json())
    evidence_set_document["été"] = 1
    evidence_set_document["claims"][0]["forged_field"] = 1
    evidence_set_document["claims"][0]["another_forged_field"] = 1

    exit_code, verification_report = verify_file(
        tmp_path, json.dumps(evidence_set_document).encode(), capsys
    )

    assert exit_code == 1
    assert verification_report["violations"] == [
        "1 unexpected field",
        "claims.0: 2 unexpected fields",
    ]


def test_verify_reports_an_unknown_planner_kind_without_repeating_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sealed_set: KnowledgeEvidenceSet
) -> None:
    forged_kind = "forged-planner-kind"
    evidence_set_document = json.loads(sealed_set.model_dump_json())
    evidence_set_document["trajectory"]["planner"]["kind"] = forged_kind

    exit_code, verification_report = verify_file(
        tmp_path, json.dumps(evidence_set_document).encode(), capsys
    )

    assert exit_code == 1
    assert verification_report["verdict"] == "malformed"
    assert verification_report["violations"][0].startswith("trajectory.planner: Input tag")
    assert forged_kind not in json.dumps(verification_report)


def test_verify_output_stays_small_for_a_set_with_a_huge_field_name(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    huge_field_name = "\U0001f600" * 200_000

    exit_code, verification_report = verify_file(
        tmp_path, json.dumps({huge_field_name: 1}).encode(), capsys
    )

    assert exit_code == 1
    assert verification_report["verdict"] == "malformed"
    assert "1 unexpected field" in verification_report["violations"]
    assert len(json.dumps(verification_report)) < 4096


@pytest.mark.parametrize(
    "evidence_set_bytes",
    [b"[]", b'{"unknown_field": 1}'],
    ids=["not_an_object", "unknown_field"],
)
def test_verify_output_is_valid_under_the_verification_report_schema(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], evidence_set_bytes: bytes
) -> None:
    schema = json.loads((REPOSITORY_SCHEMA_DIR / "verification_report.schema.json").read_text())
    evidence_set_path = write_evidence_set_file(tmp_path, evidence_set_bytes)

    run_cli(["verify", str(evidence_set_path)])

    report = json.loads(capsys.readouterr().out)
    assert list(Draft202012Validator(schema).iter_errors(report)) == []
