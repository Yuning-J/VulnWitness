"""CLI behavior: exit codes and output shape."""

import json
import logging
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from cve_kgrag.adapter_discovery import MCP_EXTRA_MISSING_DETAIL, InterfaceUnavailable
from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.application.investigation_policy import describe_deterministic_planner
from cve_kgrag.cli import (
    MAX_EVIDENCE_SET_FILE_BYTES,
    OVERSIZED_EVIDENCE_SET_MESSAGE,
    main,
    run_mcp_server,
    run_verify,
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
from cve_kgrag.domain.search import ChannelOutcome, SearchResponse, SemanticUnavailableDetail
from cve_kgrag.domain.taxonomy import BackendFailureDetail, BackendStatus, RetrievalChannel
from cve_kgrag.domain.topic_context import TopicContextResponse
from cve_kgrag.interfaces.knowledge_toolbox import KnowledgeToolbox
from cve_kgrag.interfaces.knowledge_tools import KnowledgeToolName
from tests.support.fake_chat_server import (
    FakeChatServer,
    FakeChatServers,
    ScriptedAnswer,
    build_completion_body,
)
from tests.support.fakes import BlockingRetriever
from tests.support.investigation import (
    DEPLOYMENT_VIOLATION,
    ONE_SECOND_REQUEST,
    build_test_deployment,
    build_test_investigation_service,
    reseal_evidence_set,
    rewrite_step,
)
from tests.support.investigation_runs import run_model_accepted
from tests.support.paths import REPOSITORY_SCHEMA_DIR
from tests.support.planners import DETERMINISTIC_VERIFIER
from tests.support.secrets import assert_secret_absent
from tests.support.toolbox import require_answer

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
    unknown_fields: dict[str, int] = {}
    for field_number in range(150):
        unknown_fields[f"unknown_field_{field_number}"] = field_number

    exit_code, verification_report = verify_file(
        tmp_path, json.dumps(unknown_fields).encode(), capsys
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


def test_verify_replay_past_its_deadline_reports_replay_timed_out(
    fixture_bundle: FixtureBundle,
    capsys: pytest.CaptureFixture[str],
    blocked_call_release: threading.Event,
) -> None:
    evidence_set = build_test_investigation_service(fixture_bundle).investigate(ONE_SECOND_REQUEST)
    blocking_deployment = build_test_deployment(
        fixture_bundle,
        monotonic_clock=time.monotonic,
        lexical_retriever=BlockingRetriever(blocked_call_release),
    )

    exit_code = run_verify(
        evidence_set.model_dump_json().encode(),
        blocking_deployment,
        DETERMINISTIC_VERIFIER,
    )

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
        "mcp server runner could not load: ImportError",
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
    ],
    ids=["lookup", "demo", "search", "topic", "investigate"],
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
