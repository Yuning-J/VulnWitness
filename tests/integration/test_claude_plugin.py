"""Plugin processes exercise real demo records without importing the MCP extra."""

import json
import os
import re
import stat
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest

from tests.support.paths import REPOSITORY_ROOT
from tests.support.workspaces import build_test_workspace
from vulnwitness.domain.workspace import AddFindingsRequest, TriageProductRequest

PLUGIN = REPOSITORY_ROOT / "plugins/vulnwitness"
HOOKS = PLUGIN / "hooks"
INVESTIGATION_ID = "inv_abcdefghijklmnopqrst"
OTHER_INVESTIGATION_ID = "inv_bbbbbbbbbbbbbbbbbbbb"
TOOL_PREFIX = "mcp__plugin_vulnwitness_vulnwitness__"
LIMIT_SENTENCE = (
    "These checks cover the record, citations and structured claims; they do not verify narrative."
)
ISOLATED_VARIABLES = (
    "VULNWITNESS_STORE_ROOT",
    "VULNWITNESS_FIGHT_SNAPSHOT_PATH",
    "VULNWITNESS_MITRE_SNAPSHOT_PATH",
    "VULNWITNESS_FIGHT_SNAPSHOT_SHA256",
    "VULNWITNESS_MITRE_SNAPSHOT_SHA256",
    "VULNWITNESS_PLANNER_ENABLED",
    "VULNWITNESS_PLANNER_BASE_URL",
    "VULNWITNESS_PLANNER_MODEL_NAME",
    "VULNWITNESS_PLANNER_API_KEY",
    "VULNWITNESS_PLANNER_REASONING_EFFORT",
    "VULNWITNESS_SEMANTIC_ENABLED",
)


def hook_environment(directory: Path) -> dict[str, str]:
    environment = dict(os.environ)
    for name in tuple(environment):
        if name.startswith("VULNWITNESS_"):
            del environment[name]
    environment.update(
        {
            "CLAUDE_PLUGIN_DATA": str(directory / "plugin-data"),
            "VULNWITNESS_WORKSPACE": str(directory / "workspace"),
            "VULNWITNESS_BIN": str(Path(sys.executable).parent / "vulnwitness"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return environment


def run_hook(
    command: str, event: object, environment: dict[str, str], *, raw: bool = False
) -> subprocess.CompletedProcess[str]:
    stdin = str(event) if raw else json.dumps(event)
    return subprocess.run(
        [str(PLUGIN / "bin/vulnwitness-hook"), command],
        input=stdin,
        text=True,
        capture_output=True,
        env=environment,
        timeout=25,
        check=False,
    )


def conversation_file(environment: dict[str, str], session_id: str = "conversation-1") -> Path:
    return Path(environment["CLAUDE_PLUGIN_DATA"]) / "conversations" / f"{session_id}.json"


def record_ids(environment: dict[str, str], investigation_id: str) -> None:
    recording = run_hook(
        "record-investigation",
        {
            "session_id": "conversation-1",
            "tool_name": TOOL_PREFIX + "triage_product",
            "tool_response": {"session_id": investigation_id},
        },
        environment,
    )
    assert recording.returncode == 0


def create_demo_investigation(environment: dict[str, str]) -> Path:
    _, workspace = build_test_workspace(Path(environment["VULNWITNESS_WORKSPACE"]))
    triage = workspace.triage(
        TriageProductRequest(vendor="democorp", product="demo_gateway", lookups=1)
    )
    record_ids(environment, triage.session_id)
    return Path(environment["VULNWITNESS_WORKSPACE"]) / triage.session_id


@pytest.mark.parametrize(
    "tool_response",
    [
        {"session_id": INVESTIGATION_ID},
        json.dumps({"session_id": INVESTIGATION_ID, "session": {"name": INVESTIGATION_ID}}),
        [{"type": "text", "text": json.dumps({"session_id": INVESTIGATION_ID})}],
        {"content": [{"type": "text", "text": json.dumps({"session_id": INVESTIGATION_ID})}]},
        {"structuredContent": {"session_id": INVESTIGATION_ID}},
    ],
    ids=["object", "json-string-observed", "content-list", "content-envelope", "structured"],
)
def test_record_hook_collects_supported_tool_shapes(tmp_path: Path, tool_response: object) -> None:
    # Arrange
    environment = hook_environment(tmp_path)
    event = {
        "session_id": "conversation-1",
        "tool_name": TOOL_PREFIX + "triage_product",
        "tool_response": tool_response,
    }

    # Act
    recording = run_hook("record-investigation", event, environment)

    # Assert
    assert recording.returncode == 0
    assert recording.stdout == ""
    assert recording.stderr == ""
    conversation = json.loads(conversation_file(environment).read_text())
    assert conversation == {"investigations": [INVESTIGATION_ID], "checked": {}}


def test_record_hook_records_the_session_id_argument_when_the_answer_omits_it(
    tmp_path: Path,
) -> None:
    # Arrange
    environment = hook_environment(tmp_path)
    event = {
        "session_id": "conversation-1",
        "tool_name": TOOL_PREFIX + "check_investigation",
        "tool_input": {"session_id": INVESTIGATION_ID},
        "tool_response": json.dumps({"record": {"consistent": False}, "citations": {}}),
    }

    # Act
    recording = run_hook("record-investigation", event, environment)

    # Assert
    assert recording.returncode == 0
    conversation = json.loads(conversation_file(environment).read_text())
    assert conversation["investigations"] == [INVESTIGATION_ID]


def test_record_hook_appends_unique_ids_and_preserves_checks(tmp_path: Path) -> None:
    # Arrange
    environment = hook_environment(tmp_path)
    record_ids(environment, INVESTIGATION_ID)
    path = conversation_file(environment)
    conversation = json.loads(path.read_text())
    conversation["checked"][INVESTIGATION_ID] = "checked-inputs"
    path.write_text(json.dumps(conversation))

    # Act
    record_ids(environment, INVESTIGATION_ID)
    record_ids(environment, OTHER_INVESTIGATION_ID)

    # Assert
    conversation = json.loads(path.read_text())
    assert conversation["investigations"] == [INVESTIGATION_ID, OTHER_INVESTIGATION_ID]
    assert conversation["checked"] == {INVESTIGATION_ID: "checked-inputs"}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not list(path.parent.glob(".conversation-*"))


@pytest.mark.parametrize(
    "event",
    [
        {
            "tool_name": "mcp__other__triage_product",
            "tool_response": {"session_id": INVESTIGATION_ID},
        },
        {"tool_name": TOOL_PREFIX + "lookup_cve", "tool_response": {"session_id": "../../escape"}},
        {"tool_name": TOOL_PREFIX + "lookup_cve", "tool_response": {"session_id": "inv_A"}},
        {"tool_name": TOOL_PREFIX + "lookup_cve", "tool_response": "not JSON"},
        {"tool_name": TOOL_PREFIX + "lookup_cve", "tool_response": INVESTIGATION_ID},
        {
            "tool_name": TOOL_PREFIX + "get_investigation",
            "tool_response": json.dumps({"nested": {"session_id": INVESTIGATION_ID}}),
        },
        {
            "tool_name": TOOL_PREFIX + "list_investigations",
            "tool_response": json.dumps(
                {
                    "investigations": [{"session_id": INVESTIGATION_ID}],
                    "session_id": INVESTIGATION_ID,
                }
            ),
        },
        [],
    ],
)
def test_record_hook_ignores_unrelated_or_invalid_content(tmp_path: Path, event: object) -> None:
    # Arrange
    environment = hook_environment(tmp_path)
    if isinstance(event, dict):
        event = {"session_id": "conversation-1", **event}

    # Act
    recording = run_hook("record-investigation", event, environment)

    # Assert
    assert recording.returncode == 0
    assert not conversation_file(environment).exists()


@pytest.mark.parametrize("command", ["record-investigation", "check-on-stop"])
def test_hook_malformed_input_exits_zero_and_logs(tmp_path: Path, command: str) -> None:
    # Arrange
    environment = hook_environment(tmp_path)

    # Act
    invocation = run_hook(command, "{invalid", environment, raw=True)

    # Assert
    assert invocation.returncode == 0
    assert invocation.stdout == ""
    assert "JSONDecodeError" in (tmp_path / "plugin-data/hooks.log").read_text()


def test_record_hook_rejects_conversation_path_traversal(tmp_path: Path) -> None:
    # Arrange
    environment = hook_environment(tmp_path)

    # Act
    recording = run_hook(
        "record-investigation",
        {
            "session_id": "../../escape",
            "tool_name": TOOL_PREFIX + "triage_product",
            "tool_response": {"session_id": INVESTIGATION_ID},
        },
        environment,
    )

    # Assert
    assert recording.returncode == 0
    assert not (tmp_path / "escape.json").exists()
    assert "ValueError" in (tmp_path / "plugin-data/hooks.log").read_text()


@pytest.mark.parametrize("active", [True, False])
def test_stop_without_investigations_does_not_block(tmp_path: Path, active: bool) -> None:
    # Arrange
    environment = hook_environment(tmp_path)

    # Act
    stopping = run_hook(
        "check-on-stop",
        {"session_id": "conversation-1", "stop_hook_active": active},
        environment,
    )

    # Assert
    assert stopping.returncode == 0
    assert stopping.stdout == ""
    assert not (tmp_path / "plugin-data/hooks.log").exists()


def test_stop_valid_demo_investigation_does_not_block(tmp_path: Path) -> None:
    # Arrange
    environment = hook_environment(tmp_path)
    directory = create_demo_investigation(environment)
    # Invalid inherited settings must not prevent the record-only check in demo mode.
    for name in ISOLATED_VARIABLES:
        environment[name] = "invalid-inherited-setting"

    # Act
    stopping = run_hook("check-on-stop", {"session_id": "conversation-1"}, environment)

    # Assert
    assert stopping.returncode == 0
    assert stopping.stdout == ""
    assert directory.name in json.loads(conversation_file(environment).read_text())["checked"]
    assert not (tmp_path / "plugin-data/hooks.log").exists()


@pytest.mark.parametrize("tamper", ["findings", "response", "claim"])
def test_stop_failed_layers_block_once_until_inputs_change(tmp_path: Path, tamper: str) -> None:
    # Arrange
    environment = hook_environment(tmp_path)
    directory = create_demo_investigation(environment)
    initial_stop = run_hook("check-on-stop", {"session_id": "conversation-1"}, environment)
    assert initial_stop.stdout == ""
    if tamper == "findings":
        with (directory / "findings.yaml").open("a") as stream:
            stream.write("\ninvalid: [\n")
        expected_layer = "record"
    elif tamper == "response":
        response_path = next((directory / "responses").iterdir())
        with response_path.open("a") as stream:
            stream.write(" \n")
        expected_layer = "record"
    else:
        findings_path = directory / "findings.yaml"
        findings_text = findings_path.read_text()
        assert "CVE-9999-0001" in findings_text
        findings_path.write_text(findings_text.replace("CVE-9999-0001", "CVE-9999-9999"))
        expected_layer = "claims"

    # Act
    stopping = run_hook("check-on-stop", {"session_id": "conversation-1"}, environment)
    unchanged_stop = run_hook("check-on-stop", {"session_id": "conversation-1"}, environment)

    # Assert
    assert stopping.returncode == 0
    decision = json.loads(stopping.stdout)
    assert decision["decision"] == "block"
    assert directory.name in decision["reason"]
    assert expected_layer in decision["reason"]
    assert LIMIT_SENTENCE in decision["reason"]
    assert unchanged_stop.stdout == ""
    assert unchanged_stop.returncode == 0


def test_active_stop_does_not_check_or_block_invalid_record(tmp_path: Path) -> None:
    # Arrange
    environment = hook_environment(tmp_path)
    directory = create_demo_investigation(environment)
    (directory / "findings.yaml").write_text("invalid: [")

    # Act
    stopping = run_hook(
        "check-on-stop",
        {"session_id": "conversation-1", "stop_hook_active": True},
        environment,
    )

    # Assert
    assert stopping.stdout == ""
    assert stopping.returncode == 0
    assert json.loads(conversation_file(environment).read_text())["checked"] == {}


@pytest.mark.parametrize("command", ["record-investigation", "check-on-stop"])
@pytest.mark.parametrize("override", [False, True])
def test_hook_missing_cli_exits_zero_with_one_stderr_line(
    tmp_path: Path, command: str, override: bool
) -> None:
    # Arrange
    environment = hook_environment(tmp_path)
    create_demo_investigation(environment)
    environment["PATH"] = str(tmp_path)
    if override:
        environment["VULNWITNESS_BIN"] = str(tmp_path / "missing-cli")
    else:
        del environment["VULNWITNESS_BIN"]

    # Act
    stopping = run_hook(command, {"session_id": "conversation-1"}, environment)

    # Assert
    assert stopping.stdout == ""
    assert stopping.returncode == 0
    assert len(stopping.stderr.splitlines()) == 1
    assert "CLI not found" in stopping.stderr
    assert "VULNWITNESS_BIN" in stopping.stderr
    assert not (tmp_path / "plugin-data/hooks.log").exists()
    assert json.loads(conversation_file(environment).read_text())["checked"] == {}


def fake_cli(directory: Path) -> Path:
    executable = directory / "vulnwitness"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "print(json.dumps({'arguments': sys.argv[1:], 'environment': dict(os.environ)}))\n"
    )
    executable.chmod(0o700)
    return executable


def run_wrapper(
    environment: dict[str, str], wrapper: str = "vulnwitness-mcp"
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(PLUGIN / "bin" / wrapper), "check-on-stop"]
        if wrapper == "vulnwitness-hook"
        else [str(PLUGIN / "bin" / wrapper)],
        text=True,
        capture_output=True,
        env=environment,
        timeout=10,
        check=False,
    )


@pytest.mark.parametrize("opt_in", [False, True])
@pytest.mark.parametrize("wrapper", ["vulnwitness-mcp", "vulnwitness-hook"])
def test_wrapper_isolates_demo_environment_unless_real_data_is_enabled(
    tmp_path: Path, opt_in: bool, wrapper: str
) -> None:
    # Arrange
    fake_cli(tmp_path)
    environment = hook_environment(tmp_path)
    del environment["VULNWITNESS_BIN"]
    environment["PATH"] = str(tmp_path)
    environment["VULNWITNESS_PLUGIN_REAL_DATA"] = "1" if opt_in else "0"
    for name in ISOLATED_VARIABLES:
        environment[name] = "operator-value"

    # Act
    invocation = run_wrapper(environment, wrapper)

    # Assert
    assert invocation.returncode == 0
    execution = json.loads(invocation.stdout)
    expected_arguments = (
        ["hook", "check-on-stop"]
        if wrapper == "vulnwitness-hook"
        else ["mcp", "--workspace", str(tmp_path / "workspace")]
    )
    assert execution["arguments"] == expected_arguments
    for name in ISOLATED_VARIABLES:
        assert (name in execution["environment"]) is opt_in


@pytest.mark.parametrize("workspace_setting", [None, ""])
def test_wrapper_uses_default_home_workspace(tmp_path: Path, workspace_setting: str | None) -> None:
    # Arrange
    executable = fake_cli(tmp_path)
    environment = hook_environment(tmp_path)
    environment["VULNWITNESS_BIN"] = str(executable)
    environment["HOME"] = str(tmp_path / "home with spaces")
    del environment["VULNWITNESS_WORKSPACE"]
    if workspace_setting is not None:
        environment["VULNWITNESS_WORKSPACE"] = workspace_setting

    # Act
    invocation = run_wrapper(environment)

    # Assert
    assert invocation.returncode == 0
    assert json.loads(invocation.stdout)["arguments"] == [
        "mcp",
        "--workspace",
        str(tmp_path / "home with spaces/.vulnwitness/workspace"),
    ]


@pytest.mark.parametrize("override", [False, True])
def test_wrapper_missing_cli_explains_installation(tmp_path: Path, override: bool) -> None:
    # Arrange
    environment = hook_environment(tmp_path)
    environment["PATH"] = str(tmp_path)
    if override:
        environment["VULNWITNESS_BIN"] = str(tmp_path / "missing-cli")
    else:
        del environment["VULNWITNESS_BIN"]

    # Act
    invocation = run_wrapper(environment)

    # Assert
    assert invocation.returncode != 0
    assert "CLI not found" in invocation.stderr
    assert "VULNWITNESS_BIN" in invocation.stderr


def test_plugin_structure_matches_manifest_server_and_tool_namespace() -> None:
    # Arrange
    package = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text())
    manifest = json.loads((PLUGIN / ".claude-plugin/plugin.json").read_text())
    mcp_configuration = json.loads((PLUGIN / ".mcp.json").read_text())
    analyst = (PLUGIN / "agents/vulnwitness-analyst.md").read_text()
    hooks: dict[str, Any] = json.loads((HOOKS / "hooks.json").read_text())["hooks"]

    # Act
    server = mcp_configuration["mcpServers"]["vulnwitness"]
    tool_pattern = re.search(r"^tools: (.+)$", analyst, re.MULTILINE)

    # Assert
    assert manifest["name"] == "vulnwitness"
    assert manifest["version"] == package["project"]["version"]
    assert manifest["license"] == package["project"]["license"]
    assert manifest["homepage"] == package["project"]["urls"]["Repository"]
    assert server["command"] == "${CLAUDE_PLUGIN_ROOT}/bin/vulnwitness-mcp"
    assert tool_pattern is not None
    assert tool_pattern.group(1) == TOOL_PREFIX + "*"
    assert "mcpServers:" not in analyst
    assert "hooks:" not in analyst
    assert re.fullmatch(hooks["PostToolUse"][0]["matcher"], TOOL_PREFIX + "triage_product")
    assert hooks["Stop"][0]["hooks"][0]["timeout"] == 60
    assert hooks["PostToolUse"][0]["hooks"][0]["timeout"] == 10
    for event, command in (("PostToolUse", "record-investigation"), ("Stop", "check-on-stop")):
        assert hooks[event][0]["hooks"][0]["command"] == (
            f'"${{CLAUDE_PLUGIN_ROOT}}/bin/vulnwitness-hook" {command}'
        )
    assert not list(HOOKS.glob("*.py"))
    assert (PLUGIN / "skills/vulnwitness-investigation/SKILL.md").is_file()
    assert not (REPOSITORY_ROOT / "skills/vulnwitness-investigation").exists()
    for executable in (
        PLUGIN / "bin/vulnwitness-mcp",
        PLUGIN / "bin/vulnwitness-hook",
    ):
        assert os.access(executable, os.X_OK)


def test_stop_reports_citation_layer_with_at_most_five_violations(tmp_path: Path) -> None:
    # Arrange
    environment = hook_environment(tmp_path)
    directory = create_demo_investigation(environment)
    _, workspace = build_test_workspace(Path(environment["VULNWITNESS_WORKSPACE"]))
    findings = []
    for number in range(7):
        findings.append(
            {
                "id": f"unresolved-{number}",
                "kind": "analyst_note",
                "status": "unconfirmed",
                "statement": "Applicability remains unknown.",
                "citations": [{"call": 2, "evidence_id": "ev:" + "0" * 24}],
            }
        )
    written = workspace.add_findings(
        AddFindingsRequest.model_validate({"session_id": directory.name, "findings": findings})
    )
    assert written.written
    assert not written.check.citations.resolved

    # Act
    stopping = run_hook("check-on-stop", {"session_id": "conversation-1"}, environment)

    # Assert
    assert stopping.returncode == 0
    reason = json.loads(stopping.stdout)["reason"]
    assert "failing layers: citations" in reason
    assert reason.count("citations[0]") == 5
    assert LIMIT_SENTENCE in reason


def test_parallel_tool_hooks_preserve_all_returned_ids(tmp_path: Path) -> None:
    # Arrange
    environment = hook_environment(tmp_path)
    investigations = []
    for letter in "abcdefghijkl":
        investigations.append("inv_" + letter * 20)
    invocations = []

    # Act
    for investigation_id in investigations:
        process = subprocess.Popen(
            [str(PLUGIN / "bin/vulnwitness-hook"), "record-investigation"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
        assert process.stdin is not None
        process.stdin.write(
            json.dumps(
                {
                    "session_id": "conversation-1",
                    "tool_name": TOOL_PREFIX + "triage_product",
                    "tool_response": {"session_id": investigation_id},
                }
            )
        )
        process.stdin.close()
        invocations.append(process)
    for process in invocations:
        process.wait(timeout=10)

    # Assert
    for process in invocations:
        assert process.returncode == 0
    assert set(json.loads(conversation_file(environment).read_text())["investigations"]) == set(
        investigations
    )
    assert not (tmp_path / "plugin-data/hooks.log").exists()


def test_stop_uses_the_wrapper_default_workspace(tmp_path: Path) -> None:
    # Arrange
    environment = hook_environment(tmp_path)
    environment["HOME"] = str(tmp_path / "home")
    environment["VULNWITNESS_WORKSPACE"] = str(tmp_path / "home/.vulnwitness/workspace")
    directory = create_demo_investigation(environment)
    del environment["VULNWITNESS_WORKSPACE"]

    # Act
    stopping = run_hook("check-on-stop", {"session_id": "conversation-1"}, environment)

    # Assert
    assert stopping.returncode == 0
    assert stopping.stdout == ""
    assert directory.name in json.loads(conversation_file(environment).read_text())["checked"]
    assert not (tmp_path / "plugin-data/hooks.log").exists()


def test_stop_discovers_cli_on_path(tmp_path: Path) -> None:
    # Arrange
    environment = hook_environment(tmp_path)
    directory = create_demo_investigation(environment)
    del environment["VULNWITNESS_BIN"]
    environment["PATH"] = str(Path(sys.executable).parent)

    # Act
    stopping = run_hook("check-on-stop", {"session_id": "conversation-1"}, environment)

    # Assert
    assert stopping.returncode == 0
    assert stopping.stdout == ""
    assert directory.name in json.loads(conversation_file(environment).read_text())["checked"]


@pytest.mark.parametrize("tamper", [False, True])
def test_hooks_use_installed_cli_with_only_system_path(tmp_path: Path, tamper: bool) -> None:
    # Arrange
    environment = hook_environment(tmp_path)
    environment["PATH"] = "/usr/bin:/bin"
    directory = create_demo_investigation(environment)
    if tamper:
        (directory / "findings.yaml").write_text("invalid: [")

    # Act
    stopping = run_hook("check-on-stop", {"session_id": "conversation-1"}, environment)
    unchanged_stop = run_hook("check-on-stop", {"session_id": "conversation-1"}, environment)

    # Assert
    assert stopping.returncode == unchanged_stop.returncode == 0
    assert stopping.stderr == unchanged_stop.stderr == ""
    if tamper:
        decision = json.loads(stopping.stdout)
        assert decision["decision"] == "block"
        assert decision["reason"].endswith(LIMIT_SENTENCE)
    else:
        assert stopping.stdout == ""
    assert unchanged_stop.stdout == ""
    assert directory.name in json.loads(conversation_file(environment).read_text())["checked"]
    assert not (tmp_path / "plugin-data/hooks.log").exists()


@pytest.mark.parametrize("command", ["record-investigation", "check-on-stop"])
def test_hooks_unwritable_plugin_data_exits_zero(tmp_path: Path, command: str) -> None:
    # Arrange
    environment = hook_environment(tmp_path)
    plugin_data = tmp_path / "plugin-data"
    plugin_data.write_text("not a directory")
    event = {
        "session_id": "conversation-1",
        "tool_name": TOOL_PREFIX + "triage_product",
        "tool_response": {"session_id": INVESTIGATION_ID},
    }

    # Act
    invocation = run_hook(command, event, environment)

    # Assert
    assert invocation.returncode == 0
    assert invocation.stdout == invocation.stderr == ""
    assert plugin_data.read_text() == "not a directory"
