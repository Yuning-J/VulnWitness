"""The CI workflow runs the offline lane scripts with no service, no secret and no live test."""

import re
from typing import Any

import pytest
import yaml

from tests.support.paths import REPOSITORY_ROOT

WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "offline.yml"
PINNED_ACTION = re.compile(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}")


def read_workflow() -> dict[str, Any]:
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    return workflow


def list_steps() -> list[dict[str, Any]]:
    steps = []
    for job in read_workflow()["jobs"].values():
        steps.extend(job["steps"])
    return steps


def list_run_commands() -> list[str]:
    commands = []
    for step in list_steps():
        if "run" in step:
            commands.append(step["run"])
    return commands


@pytest.mark.parametrize(
    "lane_command",
    ["scripts/ci/offline_lane.sh", "scripts/ci/core_only_lane.sh 3.12"],
    ids=["offline_lane", "core_only_lane"],
)
def test_workflow_runs_each_lane_script(lane_command: str) -> None:
    assert lane_command in list_run_commands()


def test_lane_scripts_exist_and_are_executable() -> None:
    lane_scripts = [
        REPOSITORY_ROOT / "scripts" / "ci" / "offline_lane.sh",
        REPOSITORY_ROOT / "scripts" / "ci" / "core_only_lane.sh",
    ]

    executable_scripts = []
    for lane_script in lane_scripts:
        if lane_script.is_file() and lane_script.stat().st_mode & 0o111:
            executable_scripts.append(lane_script)

    assert executable_scripts == lane_scripts


def test_offline_lane_runs_on_every_supported_python() -> None:
    offline_job = read_workflow()["jobs"]["offline-lane"]

    assert offline_job["strategy"]["matrix"]["python-version"] == ["3.11", "3.12"]


def test_workflow_starts_no_service_container() -> None:
    jobs_with_services = []
    for job_name, job in read_workflow()["jobs"].items():
        if "services" in job:
            jobs_with_services.append(job_name)

    assert jobs_with_services == []


def test_workflow_reads_no_secret_and_enables_no_live_test() -> None:
    workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "secrets." not in workflow_text
    assert "CVE_KGRAG_LIVE_TESTS" not in workflow_text


def test_workflow_token_can_only_read_the_repository() -> None:
    assert read_workflow()["permissions"] == {"contents": "read"}


def test_every_action_is_pinned_to_a_commit() -> None:
    unpinned_actions = []
    for step in list_steps():
        action = step.get("uses")
        if action is not None and PINNED_ACTION.fullmatch(action) is None:
            unpinned_actions.append(action)

    assert unpinned_actions == []
