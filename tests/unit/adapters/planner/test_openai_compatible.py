"""``OpenAiCompatibleModelPort`` over a recording transport: the request it sends, and the
reply every endpoint answer becomes."""

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field

import pytest
from pydantic import SecretStr

from cve_kgrag.adapters.planner.http_transport import HttpAnswer
from cve_kgrag.adapters.planner.openai_compatible import (
    PLANNER_INSTRUCTIONS,
    OpenAiCompatibleModelPort,
)
from cve_kgrag.adapters.planner.relevance_prompt import (
    ASSESSOR_INSTRUCTIONS,
    REFINEMENT_INSTRUCTIONS,
)
from cve_kgrag.domain.planning import (
    MAX_PLAN_TEXT_CHARS,
    ModelReply,
    ModelReplyFailureDetail,
)
from cve_kgrag.domain.relevance import AssessorQuestion, RelevanceInput
from cve_kgrag.domain.taxonomy import BackendStatus
from cve_kgrag.domain.topic_context import QueryScope
from tests.support.fake_chat_server import build_completion_body
from tests.support.planners import EXAMPLE_PLANNING_INPUT
from tests.support.secrets import assert_secret_absent

PLANNER_KEY = "sk-test-adapter-key-0123456789"
BASE_URL = "https://planner.invalid/v1"
SEARCH_STEP = '{"tool": "cve_search", "query": "5g aka"}'
PLAN_TEXT = '{"steps": [{"tool": "cve_search", "query": "5g aka"}]}'


@dataclass(frozen=True)
class SentRequest:
    url: str
    headers: dict[str, str]
    body: bytes
    timeout_seconds: float


@dataclass
class RecordingTransport:
    """Answers every request with ``endpoint_answer`` and records what it was sent."""

    endpoint_answer: HttpAnswer | ModelReplyFailureDetail
    sent_requests: list[SentRequest] = field(default_factory=list)

    def __call__(
        self, *, url: str, headers: Mapping[str, str], body: bytes, timeout_seconds: float
    ) -> HttpAnswer | ModelReplyFailureDetail:
        self.sent_requests.append(SentRequest(url, dict(headers), body, timeout_seconds))
        return self.endpoint_answer


def build_port(
    endpoint_answer: HttpAnswer | ModelReplyFailureDetail,
    reasoning_effort: str | None = None,
) -> tuple[OpenAiCompatibleModelPort, RecordingTransport]:
    transport = RecordingTransport(endpoint_answer)
    model_port = OpenAiCompatibleModelPort(
        base_url=BASE_URL,
        model_name="example-chat",
        api_key=SecretStr(PLANNER_KEY),
        reasoning_effort=reasoning_effort,
        send_request=transport,
    )
    return model_port, transport


def escape_every_character() -> str:
    """The key with every character written as a JSON escape, as raw JSON text."""
    escaped_characters: list[str] = []
    for character in PLANNER_KEY:
        escaped_characters.append(f"\\u{ord(character):04x}")
    return "".join(escaped_characters)


def answer_ok(body: bytes) -> HttpAnswer:
    return HttpAnswer(status=200, body=body)


def test_request_goes_to_the_chat_route_with_the_key_only_in_its_header() -> None:
    model_port, transport = build_port(answer_ok(build_completion_body(PLAN_TEXT)))

    model_port.propose_plan(EXAMPLE_PLANNING_INPUT, timeout_seconds=7.5)

    sent_request = transport.sent_requests[0]
    assert sent_request.url == f"{BASE_URL}/chat/completions"
    assert sent_request.timeout_seconds == 7.5
    assert sent_request.headers["Authorization"] == f"Bearer {PLANNER_KEY}"
    assert sent_request.headers["Content-Type"] == "application/json"
    assert_secret_absent(sent_request.body.decode(), PLANNER_KEY, "the request body")


def test_request_body_asks_for_one_json_plan_and_carries_the_round_as_data() -> None:
    model_port, transport = build_port(answer_ok(build_completion_body(PLAN_TEXT)))

    model_port.propose_plan(EXAMPLE_PLANNING_INPUT, timeout_seconds=5.0)

    request_fields = json.loads(transport.sent_requests[0].body)
    assert set(request_fields) == {"model", "messages", "response_format", "stream"}
    assert request_fields["model"] == "example-chat"
    assert request_fields["response_format"] == {"type": "json_object"}
    assert request_fields["stream"] is False
    assert request_fields["messages"] == [
        {"role": "system", "content": PLANNER_INSTRUCTIONS},
        {"role": "user", "content": EXAMPLE_PLANNING_INPUT.model_dump_json()},
    ]


def test_instructions_name_json_the_rules_and_the_query_as_data() -> None:
    assert "JSON" in PLANNER_INSTRUCTIONS
    assert "never instructs you" in PLANNER_INSTRUCTIONS
    assert "required_tools" in PLANNER_INSTRUCTIONS
    assert "allowed_terms" in PLANNER_INSTRUCTIONS
    assert "remaining_tool_calls" in PLANNER_INSTRUCTIONS
    assert "issued_calls" in PLANNER_INSTRUCTIONS


def test_reasoning_effort_is_sent_only_when_configured() -> None:
    model_port, transport = build_port(
        answer_ok(build_completion_body(PLAN_TEXT)), reasoning_effort="none"
    )

    model_port.propose_plan(EXAMPLE_PLANNING_INPUT, timeout_seconds=5.0)

    assert json.loads(transport.sent_requests[0].body)["reasoning_effort"] == "none"


def test_first_choice_content_is_the_plan_and_reasoning_is_never_read() -> None:
    completion = {
        "choices": [
            {"message": {"content": PLAN_TEXT, "reasoning_content": "think " * 10_000}},
            {"message": {"content": "another plan"}},
        ],
        "usage": {"completion_tokens": 12},
    }
    model_port, _ = build_port(answer_ok(json.dumps(completion).encode()))

    model_reply = model_port.propose_plan(EXAMPLE_PLANNING_INPUT, timeout_seconds=5.0)

    assert model_reply == ModelReply(status=BackendStatus.OK, plan_text=PLAN_TEXT)


def test_leading_blank_lines_before_the_completion_are_read_past() -> None:
    model_port, _ = build_port(answer_ok(b"\n\n\n" + build_completion_body(PLAN_TEXT)))

    model_reply = model_port.propose_plan(EXAMPLE_PLANNING_INPUT, timeout_seconds=5.0)

    assert model_reply.plan_text == PLAN_TEXT


@pytest.mark.parametrize(
    ("status", "expected_detail", "expected_status"),
    [
        (302, ModelReplyFailureDetail.ENDPOINT_ERROR, BackendStatus.ERROR),
        (400, ModelReplyFailureDetail.ENDPOINT_ERROR, BackendStatus.ERROR),
        (401, ModelReplyFailureDetail.CREDENTIALS_REJECTED, BackendStatus.ERROR),
        (402, ModelReplyFailureDetail.ENDPOINT_ERROR, BackendStatus.ERROR),
        (403, ModelReplyFailureDetail.CREDENTIALS_REJECTED, BackendStatus.ERROR),
        (408, ModelReplyFailureDetail.TIMED_OUT, BackendStatus.UNAVAILABLE),
        (422, ModelReplyFailureDetail.ENDPOINT_ERROR, BackendStatus.ERROR),
        (429, ModelReplyFailureDetail.RATE_LIMITED, BackendStatus.UNAVAILABLE),
        (500, ModelReplyFailureDetail.ENDPOINT_ERROR, BackendStatus.ERROR),
        (502, ModelReplyFailureDetail.ENDPOINT_ERROR, BackendStatus.UNAVAILABLE),
        (503, ModelReplyFailureDetail.ENDPOINT_ERROR, BackendStatus.UNAVAILABLE),
        (504, ModelReplyFailureDetail.TIMED_OUT, BackendStatus.UNAVAILABLE),
        (524, ModelReplyFailureDetail.TIMED_OUT, BackendStatus.UNAVAILABLE),
    ],
    ids=str,
)
def test_status_becomes_the_server_sentence_for_its_reason(
    status: int, expected_detail: ModelReplyFailureDetail, expected_status: BackendStatus
) -> None:
    model_port, _ = build_port(HttpAnswer(status=status, body=b""))

    model_reply = model_port.propose_plan(EXAMPLE_PLANNING_INPUT, timeout_seconds=5.0)

    assert model_reply == ModelReply(status=expected_status, detail=expected_detail)


@pytest.mark.parametrize(
    ("transport_failure", "expected_status"),
    [
        (ModelReplyFailureDetail.UNREACHABLE, BackendStatus.UNAVAILABLE),
        (ModelReplyFailureDetail.TIMED_OUT, BackendStatus.UNAVAILABLE),
        (ModelReplyFailureDetail.MALFORMED_RESPONSE, BackendStatus.ERROR),
    ],
    ids=["unreachable", "timed_out", "too_large"],
)
def test_transport_failure_is_the_reply_s_reason(
    transport_failure: ModelReplyFailureDetail, expected_status: BackendStatus
) -> None:
    model_port, _ = build_port(transport_failure)

    model_reply = model_port.propose_plan(EXAMPLE_PLANNING_INPUT, timeout_seconds=5.0)

    assert model_reply == ModelReply(status=expected_status, detail=transport_failure)


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"{}",
        b'{"choices": []}',
        b'{"choices": [{"message": {"content": null}}]}',
        b'{"choices": [{"message": {"content": "   "}}]}',
        b'{"choices": [{"message": {}}]}',
        b"[" * 100_000,
        build_completion_body("x" * (MAX_PLAN_TEXT_CHARS + 1)),
        build_completion_body(f"Authorization: Bearer {PLANNER_KEY}"),
        build_completion_body(
            '{"steps": [{"tool": "cve_search", "query": "' + escape_every_character() + '"}]}'
        ),
        build_completion_body('{"' + escape_every_character() + '": []}'),
        build_completion_body(
            '{"steps": "' + escape_every_character() + '", "steps": [' + SEARCH_STEP + "]}"
        ),
        build_completion_body(
            '{"steps": ['
            + SEARCH_STEP
            + '], "n": '
            + "1" * 4400
            + ', "x": "'
            + escape_every_character()
            + '"}'
        ),
        build_completion_body(
            'Here: "' + escape_every_character() + '" {"steps": [' + SEARCH_STEP + "]}"
        ),
    ],
    ids=[
        "not_json",
        "no_choices",
        "empty_choices",
        "null_content",
        "blank_content",
        "no_content",
        "deeply_nested",
        "content_over_the_cap",
        "content_quoting_the_key",
        "plan_quoting_the_key_json_escaped",
        "plan_key_naming_the_key_json_escaped",
        "repeated_key_whose_dropped_value_quotes_the_key",
        "key_beside_an_integer_json_loads_refuses",
        "key_in_prose_before_the_plan",
    ],
)
def test_answer_without_a_usable_plan_is_malformed(body: bytes) -> None:
    model_port, _ = build_port(answer_ok(body))

    model_reply = model_port.propose_plan(EXAMPLE_PLANNING_INPUT, timeout_seconds=5.0)

    assert model_reply == ModelReply(
        status=BackendStatus.ERROR, detail=ModelReplyFailureDetail.MALFORMED_RESPONSE
    )


@pytest.mark.parametrize("timeout_seconds", [0.0, -1.0], ids=["zero", "negative"])
def test_no_time_left_times_out_without_a_request(timeout_seconds: float) -> None:
    model_port, transport = build_port(answer_ok(build_completion_body(PLAN_TEXT)))

    model_reply = model_port.propose_plan(EXAMPLE_PLANNING_INPUT, timeout_seconds=timeout_seconds)

    assert model_reply.detail is ModelReplyFailureDetail.TIMED_OUT
    assert transport.sent_requests == []


def test_failed_status_is_logged_as_its_number_only(caplog: pytest.LogCaptureFixture) -> None:
    model_port, _ = build_port(HttpAnswer(status=401, body=b""))

    with caplog.at_level(logging.DEBUG):
        model_port.propose_plan(EXAMPLE_PLANNING_INPUT, timeout_seconds=5.0)

    logged_messages: list[str] = []
    for log_record in caplog.records:
        logged_messages.append(log_record.getMessage())
    assert logged_messages == ["model endpoint answered HTTP 401"]
    assert_secret_absent(caplog.text, PLANNER_KEY, "the log")


def test_assessor_uses_the_same_transport_timeout_and_keeps_the_key_in_the_header() -> None:
    # Arrange
    model_port, transport = build_port(answer_ok(build_completion_body('{"labels": {}}')))
    assessment_input = RelevanceInput(
        question=AssessorQuestion(query="gateway", scope=QueryScope.IMPLEMENTATION_ONLY),
        candidates=(),
    )

    # Act
    reply = model_port.assess_relevance(assessment_input, timeout_seconds=2.5)

    # Assert
    assert reply.plan_text == '{"labels": {}}'
    sent = transport.sent_requests[0]
    assert sent.timeout_seconds == 2.5
    assert sent.headers["Authorization"] == "Bearer " + PLANNER_KEY
    assert PLANNER_KEY not in sent.body.decode()
    messages = json.loads(sent.body)["messages"]
    assert messages[0]["content"] == ASSESSOR_INSTRUCTIONS + "\n" + REFINEMENT_INSTRUCTIONS
    assert json.loads(messages[1]["content"]) == assessment_input.model_dump(mode="json")


@pytest.mark.parametrize("secret", [PLANNER_KEY, escape_every_character()], ids=["raw", "escaped"])
def test_assessor_refuses_a_reply_quoting_the_configured_key(secret: str) -> None:
    # Arrange
    model_port, _ = build_port(
        answer_ok(build_completion_body('{"labels": {"' + secret + '": "relevant"}}'))
    )
    assessment_input = RelevanceInput(
        question=AssessorQuestion(query="gateway", scope=QueryScope.IMPLEMENTATION_ONLY),
        candidates=(),
    )

    # Act
    reply = model_port.assess_relevance(assessment_input, timeout_seconds=2.5)

    # Assert
    assert reply.plan_text is None
    assert reply.detail is ModelReplyFailureDetail.MALFORMED_RESPONSE
