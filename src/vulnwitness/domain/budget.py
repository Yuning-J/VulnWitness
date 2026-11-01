"""Server hard caps; a caller may lower each one, never raise it.

A value above a cap is rejected, never clamped, so a caller always learns that it
asked for more than the server allows.
"""

from enum import StrEnum

from pydantic import Field

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.search import MAX_RESULTS_PER_CALL, JsonInteger
from vulnwitness.domain.topic_context import KnowledgeSource

MAX_ROUNDS = 2
MAX_TOOL_CALLS = 8
MAX_SOURCES = 4
MAX_WALL_TIME_SECONDS = 30
# The share of a run's wall-time budget one planner call may take, so a slow model leaves
# the run time to retrieve: 10 s of the default 30 s.
PLANNER_SHARE_OF_WALL_TIME = 1 / 3
MAX_CONTEXT_BYTES = 200_000


class InvestigationBudget(ContractModel):
    max_rounds: JsonInteger = Field(
        default=MAX_ROUNDS,
        ge=1,
        le=MAX_ROUNDS,
        description="Planning-and-retrieval rounds; callers may lower this cap, never raise it.",
    )
    max_tool_calls: JsonInteger = Field(
        default=MAX_TOOL_CALLS,
        ge=1,
        le=MAX_TOOL_CALLS,
        description=(
            "Backend queries, counting each search a topic_context call fans out to; "
            "callers may lower this cap, never raise it."
        ),
    )
    max_sources: JsonInteger = Field(
        default=MAX_SOURCES,
        ge=1,
        le=MAX_SOURCES,
        description="Distinct knowledge sources consulted; callers may lower, never raise.",
    )
    max_results_per_call: JsonInteger = Field(
        default=MAX_RESULTS_PER_CALL,
        ge=1,
        le=MAX_RESULTS_PER_CALL,
        description=(
            "Results each tool call returns and the answer keeps per section; "
            "callers may lower this cap, never raise it."
        ),
    )
    max_wall_time_seconds: JsonInteger = Field(
        default=MAX_WALL_TIME_SECONDS,
        ge=1,
        le=MAX_WALL_TIME_SECONDS,
        description=(
            "Elapsed time after which no planner or tool call starts and no late result is "
            "admitted; callers may lower this cap, never raise it."
        ),
    )
    max_context_bytes: JsonInteger = Field(
        default=MAX_CONTEXT_BYTES,
        ge=1,
        le=MAX_CONTEXT_BYTES,
        description=(
            "Canonical JSON bytes of tool responses admitted into the answer; "
            "callers may lower this cap, never raise it."
        ),
    )


class BudgetBreach(StrEnum):
    """The cap that stopped an investigation."""

    ROUNDS = "rounds"
    TOOL_CALLS = "tool_calls"
    SOURCES = "sources"
    WALL_TIME = "wall_time"
    CONTEXT_BYTES = "context_bytes"


class BudgetUsage(ContractModel):
    rounds: int = Field(ge=0, le=MAX_ROUNDS)
    tool_calls: int = Field(
        ge=0, le=MAX_TOOL_CALLS, description="Charged before each call and never refunded."
    )
    sources: tuple[KnowledgeSource, ...] = Field(
        max_length=MAX_SOURCES, description="Sources consulted, in first-consulted order."
    )
    planner_calls: int = Field(ge=0, le=MAX_ROUNDS)
    context_bytes: int = Field(
        ge=0, le=MAX_CONTEXT_BYTES, description="Bytes of admitted tool responses only."
    )
    breach: BudgetBreach | None = None
