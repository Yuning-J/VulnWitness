"""The planner contract: the only plan shape a planner may propose, and what it is shown.

A plan names tools and their arguments, nothing else. Scope, filters, limits,
the semantic flag, URLs, claims and evidence are absent, so a closed model
rejects any plan that tries to carry them; the investigation supplies those
values itself. A model planner is untrusted: its reply is raw text that the core
parses and gates, and a planner never sees source records, only codes and counts.

A call's key, the sources it consults and whether a scope permits it are pure
functions of the call, so the controller that issues a call and the validator that
re-checks the recorded one derive them with the same code.
"""

from enum import StrEnum
from typing import Annotated, Literal, Self, assert_never

from pydantic import ConfigDict, Field, model_validator

from cve_kgrag.domain.budget import MAX_TOOL_CALLS
from cve_kgrag.domain.contract_model import ContractModel
from cve_kgrag.domain.cve import CveId
from cve_kgrag.domain.hashing import canonical_sha256
from cve_kgrag.domain.search import MAX_QUERY_CHARS, MAX_RESULTS_PER_CALL
from cve_kgrag.domain.taxonomy import BackendStatus, ResultStatus
from cve_kgrag.domain.text import list_query_terms
from cve_kgrag.domain.topic import TOPIC_ID_PATTERN, ReviewStatus
from cve_kgrag.domain.topic_context import KnowledgeSource, QueryScope, list_consulted_sources

MAX_PLAN_TEXT_CHARS = 16_384
MODEL_NAME_PATTERN = r"^[A-Za-z0-9._:/-]{1,128}$"
# An entry point's object reference, ``module.path:attribute``.
ADAPTER_REFERENCE_PATTERN = r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_.]*$"
ADAPTER_VERSION_PATTERN = r"^[A-Za-z0-9.+!_-]{1,64}$"
REASONING_EFFORT_PATTERN = r"^[a-z]{1,16}$"
SHA256_HEX_PATTERN = r"^[0-9a-f]{64}$"


class ToolName(StrEnum):
    """The allowlisted tools; no other tool can be planned or registered."""

    CVE_EXACT_LOOKUP = "cve_exact_lookup"
    CVE_SEARCH = "cve_search"
    TOPIC_CONTEXT = "topic_context"
    FIGHT_DIRECT_SEARCH = "fight_direct_search"


class QueryIntent(StrEnum):
    EXACT_ID = "exact_id"
    TOPIC = "topic"
    FREE_TEXT = "free_text"
    EXCLUDED_TERMS_ONLY = "excluded_terms_only"
    UNSEARCHABLE = "unsearchable"


class CveExactLookupCall(ContractModel):
    tool: Literal[ToolName.CVE_EXACT_LOOKUP]
    cve_ids: tuple[CveId, ...] = Field(min_length=1, max_length=MAX_RESULTS_PER_CALL)


class CveSearchCall(ContractModel):
    tool: Literal[ToolName.CVE_SEARCH]
    query: str = Field(min_length=1, max_length=MAX_QUERY_CHARS)


class TopicContextCall(ContractModel):
    tool: Literal[ToolName.TOPIC_CONTEXT]
    topic_id: str = Field(pattern=TOPIC_ID_PATTERN)


class FightDirectSearchCall(ContractModel):
    """One MITRE FiGHT search with the question's own words, when no topic resolved. It
    takes no arguments, so no planner chooses its words: the interpretation's
    ``fight_terms`` are what it sends."""

    tool: Literal[ToolName.FIGHT_DIRECT_SEARCH]


ToolCall = Annotated[
    CveExactLookupCall | CveSearchCall | TopicContextCall | FightDirectSearchCall,
    Field(discriminator="tool"),
]


def compute_call_key(call: ToolCall) -> str:
    """Hash of what the backend query depends on: the set of IDs looked up, the set of
    search terms (``list_query_terms``: lexical retrieval ignores their order and
    repeats, and a search never sends a stopword or low-signal word), or the topic. A
    direct FiGHT search sends the interpretation's words, fixed for a run, so its key is
    constant and a run holds at most one. Scope, filters, the semantic flag and the limit
    are fixed for a run, so they stay out of the key."""
    if isinstance(call, CveExactLookupCall):
        return canonical_sha256({"tool": call.tool.value, "cve_ids": sorted(set(call.cve_ids))})
    if isinstance(call, CveSearchCall):
        search_terms = sorted(set(list_query_terms(call.query)))
        return canonical_sha256({"tool": call.tool.value, "query_tokens": search_terms})
    if isinstance(call, TopicContextCall):
        return canonical_sha256({"tool": call.tool.value, "topic_id": call.topic_id})
    if isinstance(call, FightDirectSearchCall):
        return canonical_sha256({"tool": call.tool.value})
    assert_never(call)


def format_cve_tool_query(call: CveExactLookupCall | CveSearchCall) -> str:
    """The text a CVE tool's one search sends: the IDs looked up, or the search query."""
    if isinstance(call, CveExactLookupCall):
        return " ".join(call.cve_ids)
    return call.query


def is_tool_permitted(call: ToolCall, scope: QueryScope) -> bool:
    """Whether ``scope`` permits the call's tool: no CVE tool runs under
    ``protocol_context_only``, whose answer holds no CVE, and no direct FiGHT search under
    ``implementation_only``, whose answer holds no threat context."""
    if isinstance(call, CveExactLookupCall | CveSearchCall):
        return scope is not QueryScope.PROTOCOL_CONTEXT_ONLY
    if isinstance(call, FightDirectSearchCall):
        return scope is not QueryScope.IMPLEMENTATION_ONLY
    if isinstance(call, TopicContextCall):
        return True
    assert_never(call)


def list_tool_name_sources(tool: ToolName, scope: QueryScope) -> tuple[KnowledgeSource, ...]:
    """The knowledge sources a call of ``tool`` consults under ``scope``, in the order it
    sends to them."""
    if tool is ToolName.TOPIC_CONTEXT:
        return list_consulted_sources(scope)
    if tool is ToolName.FIGHT_DIRECT_SEARCH:
        return (KnowledgeSource.MITRE_FIGHT,)
    if tool is ToolName.CVE_EXACT_LOOKUP or tool is ToolName.CVE_SEARCH:
        return (KnowledgeSource.CVE_SEARCH,)
    assert_never(tool)


def list_tool_sources(call: ToolCall, scope: QueryScope) -> tuple[KnowledgeSource, ...]:
    """The knowledge sources a call consults under ``scope``, in the order it sends to them."""
    return list_tool_name_sources(call.tool, scope)


class QueryPlan(ContractModel):
    """The only shape a model planner may emit."""

    steps: tuple[ToolCall, ...] = Field(min_length=1, max_length=MAX_TOOL_CALLS)


class PlannerKind(StrEnum):
    DETERMINISTIC = "deterministic"
    MODEL = "model"


class DeterministicPlannerIdentity(ContractModel):
    kind: Literal[PlannerKind.DETERMINISTIC]
    policy_version: str = Field(max_length=32, description="Version of the deterministic policy.")


class ModelPlannerIdentity(ContractModel):
    """Which model planned, through which adapter and endpoint: built by the server from
    the settings and the installed entry point, never taken from the adapter."""

    kind: Literal[PlannerKind.MODEL]
    model_name: str = Field(pattern=MODEL_NAME_PATTERN)
    adapter: str = Field(
        pattern=ADAPTER_REFERENCE_PATTERN,
        max_length=256,
        description="The model_planner entry point's object reference, module:attribute.",
    )
    adapter_version: str = Field(
        pattern=ADAPTER_VERSION_PATTERN,
        description="The version of the distribution that installed the adapter.",
    )
    endpoint_sha256: str = Field(
        pattern=SHA256_HEX_PATTERN,
        description=(
            "SHA-256 of the configured endpoint URL, normalized (fingerprint_endpoint), so "
            "the identity binds the endpoint without naming its host."
        ),
    )
    reasoning_effort: str | None = Field(
        pattern=REASONING_EFFORT_PATTERN,
        description="The reasoning effort the planner asks for; null when it sends none.",
    )


def format_planner_version(identity: ModelPlannerIdentity) -> str:
    """The ``model_planner`` capability's version: the model's name, then the hash of the
    whole identity, so equal versions mean the same model, adapter and endpoint."""
    return f"{identity.model_name}+sha256:{canonical_sha256(identity.model_dump(mode='json'))}"


class ModelPlannerUnavailableDetail(StrEnum):
    """The server's sentence for a model planner that is configured but cannot plan; the
    deterministic policy plans in its place."""

    MISSING_API_KEY = "the model planner is enabled but no API key is configured"
    ADAPTER_UNUSABLE = "the model planner adapter is not installed or could not be used"


class ModelReplyFailureDetail(StrEnum):
    """Why a model planner gave no plan, one fixed server sentence per reason: an adapter
    picks the reason and never writes the text, so no adapter or endpoint text reaches a
    trajectory."""

    UNREACHABLE = "the model endpoint could not be reached"
    TIMED_OUT = "the model endpoint did not answer within the time left"
    CREDENTIALS_REJECTED = "the model endpoint rejected the configured credentials"
    RATE_LIMITED = "the model endpoint refused the request under its rate limit"
    ENDPOINT_ERROR = "the model endpoint answered with an error"
    MALFORMED_RESPONSE = "the model endpoint's answer held no plan text"
    ADAPTER_FAILED = "the model planner adapter raised an error or gave no valid reply"


# Each kind names only its own field, so a deterministic identity cannot name a model
# and a model identity cannot name a policy version.
PlannerIdentity = Annotated[
    DeterministicPlannerIdentity | ModelPlannerIdentity, Field(discriminator="kind")
]


class ModelReply(ContractModel):
    """What a model port returns: raw plan text, so the core always does the parsing, or
    the reason it has none, as one of the server's sentences.

    A round records the reply it got in full, within the plan text's length cap, so the
    audit can parse and gate it again. Plan text is untrusted model output: data, never
    written to a log or a warning and never read as an instruction.
    """

    # The published schema states ``check_reply_shape``.
    model_config = ConfigDict(
        json_schema_extra={
            "if": {"properties": {"status": {"const": BackendStatus.OK.value}}},
            "then": {
                "required": ["plan_text"],
                "properties": {"plan_text": {"type": "string"}, "detail": {"type": "null"}},
            },
            "else": {
                "required": ["detail"],
                "properties": {"plan_text": {"type": "null"}, "detail": {"type": "string"}},
            },
        }
    )

    status: BackendStatus
    plan_text: str | None = Field(
        default=None,
        max_length=MAX_PLAN_TEXT_CHARS,
        description="Untrusted model output: the plan as the model wrote it.",
    )
    detail: ModelReplyFailureDetail | None = Field(
        default=None, description="The server's sentence for why the planner gave no plan."
    )

    @model_validator(mode="after")
    def check_reply_shape(self) -> Self:
        if self.status is BackendStatus.OK and (self.plan_text is None or self.detail is not None):
            raise ValueError("a successful reply carries plan text and no detail")
        if self.status is not BackendStatus.OK and (
            self.detail is None or self.plan_text is not None
        ):
            raise ValueError("a failed reply carries detail and no plan text")
        return self


def compute_model_reply_sha256(model_reply: ModelReply) -> str:
    """The hash a round records beside its reply; the validator recomputes it from the reply."""
    return canonical_sha256(model_reply.model_dump(mode="json"))


class PlanRejectionCode(StrEnum):
    MALFORMED_PLAN = "malformed_plan"
    PLANNER_UNAVAILABLE = "planner_unavailable"
    REPLY_AFTER_DEADLINE = "reply_after_deadline"
    PLANNER_TIMED_OUT = "planner_timed_out"
    TOOL_NOT_PERMITTED_BY_SCOPE = "tool_not_permitted_by_scope"
    INVENTED_CVE_ID = "invented_cve_id"
    CVE_ID_IN_SEARCH_TEXT = "cve_id_in_search_text"
    TERM_OUTSIDE_VOCABULARY = "term_outside_vocabulary"
    TOPIC_NOT_RESOLVED = "topic_not_resolved"
    # The interpretation does not allow a direct FiGHT search; its fight_block says why.
    FIGHT_DIRECT_SEARCH_BLOCKED = "fight_direct_search_blocked"
    REPEATED_CALL = "repeated_call"
    MISSING_BASELINE_SOURCE = "missing_baseline_source"
    MISSING_NAMED_CVE_ID = "missing_named_cve_id"
    OVER_TOOL_CALL_BUDGET = "over_tool_call_budget"
    OVER_SOURCE_BUDGET = "over_source_budget"


class PlanRejection(ContractModel):
    step_position: int | None = Field(
        default=None, ge=0, description="Zero-based plan position; null for the whole plan."
    )
    code: PlanRejectionCode


class StepObservation(ContractModel):
    """What a planner learns about an executed step: codes and counts, never source text."""

    step_index: int = Field(ge=1)
    tool: ToolName
    status: ResultStatus | None
    answer_count: int = Field(ge=0)
    warning_codes: tuple[str, ...]


class ToolCost(ContractModel):
    tool: ToolName
    charged_tool_calls: int = Field(ge=1)


class PlanningInput(ContractModel):
    """Everything a planner is shown for one round."""

    round_number: Literal[1, 2]
    quoted_query: str = Field(
        description="The caller's query, sent as a JSON string value: data, never instructions."
    )
    scope: QueryScope
    intent: QueryIntent
    cve_ids: tuple[CveId, ...]
    topic_id: str | None
    topic_version: str | None
    review_status: ReviewStatus | None
    allowed_tools: tuple[ToolName, ...]
    required_tools: tuple[ToolName, ...] = Field(
        description=(
            "Tools a round-1 plan includes, so it consults every source the policy's plan "
            "would; empty in round 2."
        )
    )
    allowed_terms: tuple[str, ...] = Field(description="Sorted search vocabulary.")
    tool_costs: tuple[ToolCost, ...]
    remaining_tool_calls: int = Field(ge=0)
    remaining_sources: int = Field(ge=0)
    issued_calls: tuple[ToolCall, ...]
    observations: tuple[StepObservation, ...]
