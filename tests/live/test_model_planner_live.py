"""The configured model planner against its real endpoint. Opt-in only: these tests run
when ``VULNWITNESS_LIVE_TESTS=1`` is set, and then require the planner settings.

Run them with the key from your own shell, never with ``--showlocals``:

    VULNWITNESS_LIVE_TESTS=1 \\
    VULNWITNESS_PLANNER_ENABLED=true \\
    VULNWITNESS_PLANNER_BASE_URL=https://api.deepseek.com \\
    VULNWITNESS_PLANNER_MODEL_NAME=deepseek-flash \\
    VULNWITNESS_PLANNER_REASONING_EFFORT=none \\
    VULNWITNESS_PLANNER_API_KEY="$DEEPSEEK_API_KEY" \\
    uv run pytest tests/live -m live

Nothing here prints a reply's text.
"""

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field

import pytest
from pydantic import SecretStr

from tests.support.planners import EXAMPLE_PLANNING_INPUT
from tests.support.secrets import assert_secret_absent
from vulnwitness.adapter_discovery import discover_planner_setup
from vulnwitness.adapters.fixture.synthetic_fixture import default_fixture_dir, load_fixture_bundle
from vulnwitness.adapters.planner.http_transport import HttpAnswer, post_json
from vulnwitness.adapters.planner.openai_compatible import OpenAiCompatibleModelPort
from vulnwitness.application.planner_setup import ModelPlanning
from vulnwitness.composition import build_investigation_service, build_serving_data_plane
from vulnwitness.domain.investigation import InvestigationRequest
from vulnwitness.domain.planning import ModelReplyFailureDetail
from vulnwitness.domain.taxonomy import BackendStatus
from vulnwitness.domain.topic_context import QueryScope
from vulnwitness.settings import ModelPlannerSettings, load_settings

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("VULNWITNESS_LIVE_TESTS") != "1",
        reason="live tests run only with VULNWITNESS_LIVE_TESTS=1",
    ),
]
MISSING_SETTINGS = (
    "set VULNWITNESS_PLANNER_ENABLED, VULNWITNESS_PLANNER_BASE_URL, VULNWITNESS_PLANNER_MODEL_NAME "
    "and VULNWITNESS_PLANNER_API_KEY to run the live tests"
)


@dataclass(frozen=True)
class ConfiguredPlanner:
    settings: ModelPlannerSettings
    api_key: SecretStr


@pytest.fixture
def configured_planner() -> ConfiguredPlanner:
    """The planner settings of this shell; an opted-in run without them fails."""
    planner_settings = load_settings(os.environ).model_planner
    if planner_settings is None or planner_settings.api_key is None:
        pytest.fail(MISSING_SETTINGS)
    return ConfiguredPlanner(planner_settings, planner_settings.api_key)


@dataclass
class KeptAnswers:
    """Sends through ``post_json`` and keeps each answer, so a test can read the body."""

    answers: list[HttpAnswer | ModelReplyFailureDetail] = field(default_factory=list)

    def __call__(
        self, *, url: str, headers: Mapping[str, str], body: bytes, timeout_seconds: float
    ) -> HttpAnswer | ModelReplyFailureDetail:
        endpoint_answer = post_json(
            url=url, headers=headers, body=body, timeout_seconds=timeout_seconds
        )
        self.answers.append(endpoint_answer)
        return endpoint_answer


def test_installed_planner_answers_a_round_and_the_set_seals_without_the_key(
    configured_planner: ConfiguredPlanner,
) -> None:
    planner_setup = discover_planner_setup(configured_planner.settings)
    assert isinstance(planner_setup, ModelPlanning), "the planner adapter is not usable"
    service = build_investigation_service(
        build_serving_data_plane(load_fixture_bundle(default_fixture_dir())),
        planner_setup=planner_setup,
    )

    evidence_set = service.investigate(
        InvestigationRequest(query="5G-AKA", scope=QueryScope.IMPLEMENTATION_ONLY)
    )

    model_reply = evidence_set.trajectory.rounds[0].model_reply
    has_ok_reply = model_reply is not None and model_reply.status is BackendStatus.OK
    assert has_ok_reply, "round 1 recorded no successful reply"
    assert_secret_absent(
        evidence_set.model_dump_json(),
        configured_planner.api_key.get_secret_value(),
        "the evidence set",
    )


def test_reasoning_effort_none_turns_reasoning_off(
    configured_planner: ConfiguredPlanner,
) -> None:
    if configured_planner.settings.reasoning_effort != "none":
        pytest.skip("checks VULNWITNESS_PLANNER_REASONING_EFFORT=none only")
    kept_answers = KeptAnswers()
    model_port = OpenAiCompatibleModelPort(
        base_url=configured_planner.settings.base_url,
        model_name=configured_planner.settings.model_name,
        api_key=configured_planner.api_key,
        reasoning_effort="none",
        send_request=kept_answers,
    )

    model_reply = model_port.propose_plan(EXAMPLE_PLANNING_INPUT, timeout_seconds=10.0)

    endpoint_answer = kept_answers.answers[0]
    is_ok = model_reply.status is BackendStatus.OK and isinstance(endpoint_answer, HttpAnswer)
    assert is_ok, "the endpoint gave no successful answer"
    assert isinstance(endpoint_answer, HttpAnswer)
    message = json.loads(endpoint_answer.body)["choices"][0]["message"]
    is_reasoning_off = not message.get("reasoning_content")
    assert is_reasoning_off, "the endpoint reasoned despite effort none"
