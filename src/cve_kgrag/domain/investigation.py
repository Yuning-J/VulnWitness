"""Bounded investigation: the request, the replayable trajectory, the evidence set it
returns, and the rules that tie a stop reason to a status.

An investigation runs a fixed state machine (interpret, plan, retrieve, assess, at
most one refinement, validate, return) under the caps of ``InvestigationBudget``.
Its answer keeps implementation candidates (CVEs) and protocol threat context
(FiGHT) in separate sections, every claim is a fixed template citing evidence
anchors, and product applicability stays ``unknown`` because no verified
affectedness source is available to establish it.
"""

from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from operator import not_
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, JsonValue, StrictBool, model_validator
from pydantic.config import JsonDict

from cve_kgrag.domain.affectedness import AffectednessDetail, ApplicabilityStatus
from cve_kgrag.domain.budget import MAX_ROUNDS, MAX_TOOL_CALLS, BudgetUsage, InvestigationBudget
from cve_kgrag.domain.contract_model import ContractModel
from cve_kgrag.domain.cve import CveId, CveRecord
from cve_kgrag.domain.evidence import SHA256_PATTERN, Claim, EvidenceAnchor, EvidenceId
from cve_kgrag.domain.hashing import canonical_sha256
from cve_kgrag.domain.nvd_version_note import NvdVersionNote
from cve_kgrag.domain.planning import (
    ModelPlannerIdentity,
    ModelPlannerUnavailableDetail,
    ModelReply,
    PlannerIdentity,
    PlannerKind,
    PlanRejection,
    PlanRejectionCode,
    QueryIntent,
    ToolCall,
    ToolName,
    format_planner_version,
)
from cve_kgrag.domain.product_query import ProductQueryRequest
from cve_kgrag.domain.product_recognition import ProductRecognition
from cve_kgrag.domain.relevance import RelevanceAssessmentRecord, RelevanceLabel
from cve_kgrag.domain.result_prefix import PrefixAdmission
from cve_kgrag.domain.search import (
    MAX_QUERY_CHARS,
    MAX_RESULTS_PER_CALL,
    SCHEMA_VERSION,
    Candidate,
    QueryText,
    SchemaVersion,
    SearchFilters,
    SearchWarning,
    SearchWarningCode,
    SemanticUnavailableDetail,
)
from cve_kgrag.domain.taxonomy import ResultStatus, RetrievalChannel
from cve_kgrag.domain.threat_context import SnapshotCoverage, ThreatContextItem
from cve_kgrag.domain.timestamps import Timestamp
from cve_kgrag.domain.topic import RelevanceAssessment, RelevanceTier, TopicResolution
from cve_kgrag.domain.topic_context import (
    ANSWER_SOURCES_BY_SCOPE,
    KnowledgeSource,
    QueryScope,
    SourceOutcome,
    TopicContextWarning,
    TopicContextWarningCode,
    summarize_statuses,
)

INVESTIGATION_ID_PATTERN = r"^inv:[0-9a-f]{24}$"
MAX_TRANSITIONS = 16
ProductKind = Literal["vendor", "product", "purl", "product_version"]


class StopReason(StrEnum):
    SUFFICIENT = "sufficient"
    NO_EVIDENCE = "no_evidence"
    BUDGET_EXHAUSTED = "budget_exhausted"
    SOURCE_UNAVAILABLE = "source_unavailable"
    POLICY_BLOCKED = "policy_blocked"
    INVALID_EVIDENCE = "invalid_evidence"
    NEEDS_UNMET = "needs_unmet"


class InvestigationState(StrEnum):
    INTERPRET = "interpret"
    PLAN = "plan"
    RETRIEVE = "retrieve"
    ASSESS = "assess"
    REFINE = "refine"
    VALIDATE = "validate"
    RETURN = "return"


class DecisionBasis(StrEnum):
    """The observation a state transition was decided on."""

    QUERY_INTERPRETED = "query_interpreted"
    CVE_IDS_OUTSIDE_SCOPE = "cve_ids_outside_scope"
    CVE_IDS_OVER_LOOKUP_CAP = "cve_ids_over_lookup_cap"
    FILTERS_OUTSIDE_SCOPE = "filters_outside_scope"
    EXCLUDED_TERMS_ONLY = "excluded_terms_only"
    NO_SEARCHABLE_TERMS = "no_searchable_terms"
    PROTOCOL_SCOPE_NEEDS_TOPIC = "protocol_scope_needs_topic"
    PLAN_ACCEPTED = "plan_accepted"
    PLAN_OVER_BUDGET = "plan_over_budget"
    PLAN_REJECTED_BY_POLICY = "plan_rejected_by_policy"
    STEPS_FINISHED = "steps_finished"
    EVIDENCE_INVALID = "evidence_invalid"
    BUDGET_BREACHED = "budget_breached"
    ANSWER_SOURCE_FAILED = "answer_source_failed"
    AFFECTEDNESS_UNAVAILABLE = "affectedness_unavailable"
    ANSWER_FOUND = "answer_found"
    NEEDS_OPEN = "needs_open"
    NO_REFINEMENT_AVAILABLE = "no_refinement_available"
    ROUND_CAP_REACHED = "round_cap_reached"
    NEEDS_OPEN_AFTER_REFINEMENT = "needs_open_after_refinement"
    ANSWER_VALIDATED = "answer_validated"


# Every path ends validate -> return; refine is entered at most once (validator).
ALLOWED_TRANSITIONS: frozenset[tuple[InvestigationState, InvestigationState]] = frozenset(
    {
        (InvestigationState.INTERPRET, InvestigationState.PLAN),
        (InvestigationState.INTERPRET, InvestigationState.VALIDATE),
        (InvestigationState.PLAN, InvestigationState.RETRIEVE),
        (InvestigationState.PLAN, InvestigationState.VALIDATE),
        (InvestigationState.RETRIEVE, InvestigationState.ASSESS),
        (InvestigationState.ASSESS, InvestigationState.REFINE),
        (InvestigationState.ASSESS, InvestigationState.VALIDATE),
        (InvestigationState.REFINE, InvestigationState.RETRIEVE),
        (InvestigationState.REFINE, InvestigationState.VALIDATE),
        (InvestigationState.VALIDATE, InvestigationState.RETURN),
    }
)


class StateTransition(ContractModel):
    from_state: InvestigationState
    to_state: InvestigationState
    basis: DecisionBasis


class InvestigationRequest(ContractModel):
    """An investigation question. The scope has no default: the caller must choose it."""

    query: QueryText
    scope: QueryScope
    filters: SearchFilters = Field(
        default_factory=SearchFilters,
        description=(
            "Constrain every CVE tool call; vendors, products and purls are the product context."
        ),
    )
    semantic: StrictBool = Field(
        default=False, description="Also run the optional semantic channel for CVE searches."
    )
    budget: InvestigationBudget = Field(default_factory=InvestigationBudget)


class FightBlockReason(StrEnum):
    """Why the query's words may not be sent to FiGHT without a reviewed topic, checked in
    this order: a topic resolved, so its card's terms reach FiGHT; the query names an
    excluded term; it names a CVE ID; or one of its search terms the registry reads alone
    as a topic or an excluded term."""

    TOPIC_RESOLVED = "topic_resolved"
    EXCLUDED_TERM = "excluded_term"
    CVE_ID_NAMED = "cve_id_named"
    TERM_READS_AS_TOPIC = "term_reads_as_topic"


class FightBlock(ContractModel):
    reason: FightBlockReason
    subject: str = Field(
        description=(
            "The first matched topic ID, the first excluded term, the first CVE ID, or the "
            "search term the registry reads as a topic or excluded term."
        )
    )


class Interpretation(ContractModel):
    product_recognition: ProductRecognition | None = Field(default=None, exclude_if=not_)
    ambiguous_product_names: tuple[str, ...] = Field(default=(), exclude_if=not_)
    intent: QueryIntent
    normalized_query: str
    cve_ids: tuple[CveId, ...]
    search_terms: tuple[str, ...] = Field(
        description=(
            "Query tokens without CVE IDs, words that read together as a CVE ID, "
            "stopwords, the low-signal words cve and cves, tokens of excluded terms, "
            "and version spans attached to recognized product names."
        )
    )
    fight_terms: tuple[str, ...] = Field(
        description=(
            "The words a direct FiGHT search sends: all of search_terms when fight_block is "
            "null, else none; never a subset."
        )
    )
    fight_block: FightBlock | None = Field(
        description=(
            "Why the search terms may not be sent to FiGHT without a reviewed topic; null "
            "when they may."
        )
    )
    resolution: TopicResolution
    affectedness_mentions: tuple[str, ...] = Field(
        description=(
            "Each product and version the query asks affectedness of, as 'word version': a "
            "whole vendor or product name a stored record carries as affected or of unknown "
            "status, followed by a dotted version, in a query holding an affectedness word."
        )
    )


def list_version_mentions(
    affectedness_mentions: Sequence[str], recognition: ProductRecognition | None
) -> tuple[str, ...]:
    """NVD annotation subjects, without adding affectedness evidence needs."""
    mentions = list(affectedness_mentions)
    if recognition is not None and recognition.request.version is not None:
        mention = f"{recognition.name} {recognition.request.version}"
        if mention not in mentions:
            mentions.append(mention)
    return tuple(mentions)


class StepReason(StrEnum):
    QUERY_CVE_IDS = "query_cve_ids"
    QUERY_TERMS = "query_terms"
    RECOGNIZED_PRODUCT = "recognized_product"
    REVIEWED_TOPIC = "reviewed_topic"
    TOPIC_AFTER_UNKNOWN_IDS = "topic_after_unknown_ids"
    TOPIC_AFTER_LITERAL_MISS = "topic_after_literal_miss"
    TOPIC_FOR_OPEN_NEED = "topic_for_open_need"
    QUERY_TERMS_FOR_OPEN_NEED = "query_terms_for_open_need"
    QUERY_TERMS_FIGHT = "query_terms_fight"
    RELEVANCE_GAP_SEARCH = "relevance_gap_search"
    MODEL_PROPOSAL = "model_proposal"


# The tool and round of each step the deterministic policy plans, by its reason; a model
# planner's step has the reason ``model_proposal`` and may be any tool in either round.
POLICY_STEP_TOOL_AND_ROUND: dict[StepReason, tuple[ToolName, int]] = {
    StepReason.QUERY_CVE_IDS: (ToolName.CVE_EXACT_LOOKUP, 1),
    StepReason.QUERY_TERMS: (ToolName.CVE_SEARCH, 1),
    StepReason.RECOGNIZED_PRODUCT: (ToolName.PRODUCT_QUERY, 1),
    StepReason.REVIEWED_TOPIC: (ToolName.TOPIC_CONTEXT, 1),
    StepReason.TOPIC_AFTER_UNKNOWN_IDS: (ToolName.TOPIC_CONTEXT, 2),
    StepReason.TOPIC_AFTER_LITERAL_MISS: (ToolName.TOPIC_CONTEXT, 2),
    StepReason.TOPIC_FOR_OPEN_NEED: (ToolName.TOPIC_CONTEXT, 2),
    StepReason.QUERY_TERMS_FOR_OPEN_NEED: (ToolName.CVE_SEARCH, 2),
    StepReason.QUERY_TERMS_FIGHT: (ToolName.FIGHT_DIRECT_SEARCH, 1),
    StepReason.RELEVANCE_GAP_SEARCH: (ToolName.CVE_SEARCH, 2),
}


class StepAdmission(StrEnum):
    """Whether a step's result entered the answer.

    ``admitted_prefix``: the longest whole-result prefix fits the remaining byte cap.
    ``timed_out``: the call had not returned at the deadline and was abandoned, so the
    step has no response; ``discarded_after_deadline``: it returned, but at or after
    the deadline.
    """

    ADMITTED = "admitted"
    ADMITTED_PREFIX = "admitted_prefix"
    DISCARDED_AFTER_DEADLINE = "discarded_after_deadline"
    DISCARDED_OVER_CONTEXT_BUDGET = "discarded_over_context_budget"
    REJECTED_INVALID_EVIDENCE = "rejected_invalid_evidence"
    TIMED_OUT = "timed_out"


ADMITTED_ADMISSIONS = frozenset({StepAdmission.ADMITTED, StepAdmission.ADMITTED_PREFIX})


# Admissions of a step that has no tool response to record.
RESPONSELESS_ADMISSIONS = frozenset(
    {StepAdmission.REJECTED_INVALID_EVIDENCE, StepAdmission.TIMED_OUT}
)
# The list fields a step fills from its tool response; a responseless step leaves them empty.
RESPONSE_LIST_FIELDS = (
    "channels_executed",
    "source_outcomes",
    "search_warnings",
    "topic_warnings",
    "answer_ids",
    "evidence_ids",
)


def describe_step_payload_shape() -> JsonDict:
    """``ToolStep.check_payload_matches_admission`` as JSON Schema: a responseless step
    carries nothing from a response, and any other step records its status and hash."""
    responseless_admissions: list[JsonValue] = []
    for admission in StepAdmission:
        if admission in RESPONSELESS_ADMISSIONS:
            responseless_admissions.append(admission.value)
    empty_payload_properties: JsonDict = {
        "status": {"type": "null"},
        "result_sha256": {"type": "null"},
        "context_bytes": {"const": 0},
    }
    for field_name in RESPONSE_LIST_FIELDS:
        empty_payload_properties[field_name] = {"maxItems": 0}
    response_shape: JsonDict = {
        "if": {"properties": {"admission": {"enum": responseless_admissions}}},
        "then": {"properties": empty_payload_properties},
        "else": {
            "required": ["status", "result_sha256"],
            "properties": {
                "status": {"not": {"type": "null"}},
                "result_sha256": {"type": "string"},
            },
        },
    }
    return {
        "allOf": [
            response_shape,
            {
                "if": {"properties": {"admission": {"const": "admitted_prefix"}}},
                "then": {
                    "required": ["prefix_admission"],
                    "properties": {"prefix_admission": {"not": {"type": "null"}}},
                },
                "else": {"properties": {"prefix_admission": {"type": "null"}}},
            },
        ]
    }


class CveBackendRequest(ContractModel):
    """One CVE search a step sent: an exact lookup, a search or a topic's template search."""

    source: Literal[KnowledgeSource.CVE_SEARCH]
    query: str = Field(min_length=1, max_length=MAX_QUERY_CHARS)
    product_query: ProductQueryRequest | None = Field(default=None, exclude_if=not_)
    limit: int = Field(ge=1, le=MAX_RESULTS_PER_CALL)


class FightBackendRequest(ContractModel):
    """The FiGHT search a step sent: a topic's names, aliases and entities, or the
    interpretation's fight_terms."""

    source: Literal[KnowledgeSource.MITRE_FIGHT]
    terms: tuple[str, ...] = Field(min_length=1)
    limit: int = Field(ge=1, le=MAX_RESULTS_PER_CALL)


BackendRequest = Annotated[CveBackendRequest | FightBackendRequest, Field(discriminator="source")]


class ToolStep(ContractModel):
    """One executed call; a prefix admission records a compact byte-and-count witness."""

    model_config = ConfigDict(json_schema_extra=describe_step_payload_shape())

    step_index: int = Field(ge=1)
    round_number: Literal[1, 2]
    call: ToolCall = Field(description="Sanitized by construction: only allowlisted arguments.")
    reason: StepReason
    planned_by: PlannerKind
    call_key: str = Field(
        pattern=SHA256_PATTERN,
        description=(
            "Hash of what the call's backend query depends on, recomputed from the call; "
            "unique in a run."
        ),
    )
    backend_requests: tuple[BackendRequest, ...] = Field(
        min_length=1,
        description=(
            "Every search the call sends to a knowledge source, in order, with its limit; "
            "a topic_context call fans out to several, and a fight_direct_search call sends "
            "one FiGHT search of the interpretation's fight_terms."
        ),
    )
    charged_tool_calls: int = Field(ge=1, description="One per backend request.")
    sources: tuple[KnowledgeSource, ...] = Field(min_length=1)
    admission: StepAdmission
    status: ResultStatus | None
    channels_executed: tuple[RetrievalChannel, ...]
    source_outcomes: tuple[SourceOutcome, ...]
    search_warnings: tuple[SearchWarning, ...]
    topic_warnings: tuple[TopicContextWarning, ...]
    answer_ids: tuple[str, ...] = Field(description="CVE and FiGHT technique IDs returned.")
    evidence_ids: tuple[EvidenceId, ...]
    result_sha256: str | None = Field(
        default=None,
        pattern=SHA256_PATTERN,
        description=(
            "The response or retained prefix's sealed hash; null when its evidence was invalid "
            "or the call timed out."
        ),
    )
    context_bytes: int = Field(
        ge=0,
        description="Canonical JSON bytes of the admitted response, or full discarded response.",
    )
    prefix_admission: PrefixAdmission | None = Field(
        default=None,
        description=(
            "For admitted_prefix: original digest, per-list counts, charged and next-result bytes."
        ),
    )

    @model_validator(mode="after")
    def check_payload_matches_admission(self) -> Self:
        if (self.admission is StepAdmission.ADMITTED_PREFIX) != (self.prefix_admission is not None):
            raise ValueError("exactly an admitted_prefix step records prefix_admission")
        is_responseless = self.admission in RESPONSELESS_ADMISSIONS
        has_payload = bool(
            self.status is not None
            or self.result_sha256 is not None
            or self.context_bytes
            or any(getattr(self, field_name) for field_name in RESPONSE_LIST_FIELDS)
        )
        if is_responseless and has_payload:
            raise ValueError(
                "a step rejected for invalid evidence or timed out carries nothing from a response"
            )
        if not is_responseless and (self.status is None or self.result_sha256 is None):
            raise ValueError("a step whose response was valid records its status and hash")
        return self


class PlannerOutcome(StrEnum):
    """How a round's plan was chosen.

    ``deterministic``: no model planner is configured, so the policy planned the round.
    ``model_accepted``: the model's plan passed the gate and runs. ``model_rejected`` and
    ``model_unavailable``: the model's reply failed the gate or carried no plan, so the
    round falls back to the policy's plan. ``model_reply_after_deadline`` and
    ``model_timed_out``: the model replied at or after the deadline, or not at all, so
    nothing runs. ``model_skipped_at_deadline``: a model is configured, but the deadline
    had passed before the round was planned, so it was never consulted.
    ``model_not_consulted``: a model is configured, but the policy planned round 1 without
    calling it. Either the question is free text (no CVE ID, no resolved topic), which the
    policy plans alone with the question's search terms as its baseline, or the policy's
    own round-1 plan is over the source budget, which no round-1 model plan can meet since
    it must consult the policy's sources. The round runs the policy's plan, or records the
    policy plan's rejections and runs nothing.
    Every outcome but ``deterministic``, ``model_timed_out``, ``model_skipped_at_deadline``
    and ``model_not_consulted`` has a reply, which the round records.
    """

    DETERMINISTIC = "deterministic"
    MODEL_ACCEPTED = "model_accepted"
    MODEL_REJECTED = "model_rejected"
    MODEL_UNAVAILABLE = "model_unavailable"
    MODEL_REPLY_AFTER_DEADLINE = "model_reply_after_deadline"
    MODEL_TIMED_OUT = "model_timed_out"
    MODEL_SKIPPED_AT_DEADLINE = "model_skipped_at_deadline"
    MODEL_NOT_CONSULTED = "model_not_consulted"


# Outcomes of a round whose model planner was called; each is one planner call.
CONSULTED_MODEL_OUTCOMES = frozenset(
    {
        PlannerOutcome.MODEL_ACCEPTED,
        PlannerOutcome.MODEL_REJECTED,
        PlannerOutcome.MODEL_UNAVAILABLE,
        PlannerOutcome.MODEL_REPLY_AFTER_DEADLINE,
        PlannerOutcome.MODEL_TIMED_OUT,
    }
)
PLANNER_OUTCOMES_BY_KIND: dict[PlannerKind, frozenset[PlannerOutcome]] = {
    PlannerKind.DETERMINISTIC: frozenset({PlannerOutcome.DETERMINISTIC}),
    PlannerKind.MODEL: CONSULTED_MODEL_OUTCOMES
    | {PlannerOutcome.MODEL_SKIPPED_AT_DEADLINE, PlannerOutcome.MODEL_NOT_CONSULTED},
}
# Outcomes of a round the policy planned: its steps are the policy's, and a rejection it
# records is the gate's verdict on the policy's own plan.
POLICY_PLANNED_OUTCOMES = frozenset(
    {PlannerOutcome.DETERMINISTIC, PlannerOutcome.MODEL_NOT_CONSULTED}
)
# Outcomes of a round whose model reply was rejected: each records at least one rejection.
REJECTED_MODEL_OUTCOMES = frozenset(
    {
        PlannerOutcome.MODEL_REJECTED,
        PlannerOutcome.MODEL_UNAVAILABLE,
        PlannerOutcome.MODEL_REPLY_AFTER_DEADLINE,
        PlannerOutcome.MODEL_TIMED_OUT,
    }
)
# Outcomes of a round whose model planner gave a reply, which the round records.
REPLIED_MODEL_OUTCOMES = CONSULTED_MODEL_OUTCOMES - {PlannerOutcome.MODEL_TIMED_OUT}
# The rejection such a round records first, where its outcome fixes it.
FIRST_REJECTION_BY_OUTCOME: dict[PlannerOutcome, PlanRejectionCode] = {
    PlannerOutcome.MODEL_UNAVAILABLE: PlanRejectionCode.PLANNER_UNAVAILABLE,
    PlannerOutcome.MODEL_REPLY_AFTER_DEADLINE: PlanRejectionCode.REPLY_AFTER_DEADLINE,
    PlannerOutcome.MODEL_TIMED_OUT: PlanRejectionCode.PLANNER_TIMED_OUT,
}
FIXED_FIRST_REJECTION_CODES = frozenset(FIRST_REJECTION_BY_OUTCOME.values())
# Codes only the gate's reading of a model reply produces, never the policy's own plan:
# the policy's round-1 plan looks every named CVE ID up, and round 2 runs only after a
# round-1 plan that did, so no policy plan owes a lookup.
MODEL_REPLY_REJECTION_CODES = frozenset(
    {
        PlanRejectionCode.MALFORMED_PLAN,
        PlanRejectionCode.PLANNER_UNAVAILABLE,
        PlanRejectionCode.REPLY_AFTER_DEADLINE,
        PlanRejectionCode.PLANNER_TIMED_OUT,
        PlanRejectionCode.MISSING_BASELINE_SOURCE,
        PlanRejectionCode.MISSING_NAMED_CVE_ID,
    }
)


def list_enum_values(members: Iterable[StrEnum]) -> list[JsonValue]:
    """The members' values, sorted, for a JSON Schema ``enum``."""
    values: list[str] = []
    for member in members:
        values.append(member.value)
    sorted_values: list[JsonValue] = []
    for value in sorted(values):
        sorted_values.append(value)
    return sorted_values


def require_outcome_in(outcomes: Iterable[PlannerOutcome]) -> JsonDict:
    """JSON Schema ``if`` clause: the round's planner outcome is one of ``outcomes``."""
    return {"properties": {"planner_outcome": {"enum": list_enum_values(outcomes)}}}


def describe_round_shape() -> JsonDict:
    """The validator's single-round rules (``find_model_reply_violations`` and
    ``find_rejection_violations``) as JSON Schema: a round records the reply and its hash
    exactly when the model replied; a rejected model reply records its rejections, the
    outcome's fixed one first; every other round records none, except a policy plan the
    gate rejected, which a ``deterministic`` or ``model_not_consulted`` round that runs
    nothing records, and never a code only a model reply produces. A
    ``model_not_consulted`` round uses a policy plan."""
    no_rejections: JsonDict = {"properties": {"rejections": {"maxItems": 0}}}
    rules: list[JsonValue] = [
        {
            "if": require_outcome_in(REPLIED_MODEL_OUTCOMES),
            "then": {
                "required": ["model_reply", "model_reply_sha256"],
                "properties": {
                    "model_reply": {"not": {"type": "null"}},
                    "model_reply_sha256": {"type": "string"},
                },
            },
            "else": {
                "properties": {
                    "model_reply": {"type": "null"},
                    "model_reply_sha256": {"type": "null"},
                }
            },
        },
        {
            "if": require_outcome_in(REJECTED_MODEL_OUTCOMES),
            "then": {"properties": {"rejections": {"minItems": 1}}},
            "else": {
                "properties": {
                    "rejections": {
                        "items": {
                            "properties": {
                                "code": {
                                    "not": {"enum": list_enum_values(MODEL_REPLY_REJECTION_CODES)}
                                }
                            }
                        }
                    }
                }
            },
        },
        {
            "if": require_outcome_in({PlannerOutcome.MODEL_REJECTED}),
            "then": {
                "properties": {
                    "rejections": {
                        "prefixItems": [
                            {
                                "properties": {
                                    "code": {
                                        "not": {
                                            "enum": list_enum_values(FIXED_FIRST_REJECTION_CODES)
                                        }
                                    }
                                }
                            }
                        ]
                    }
                }
            },
        },
        {
            "if": require_outcome_in(
                set(PlannerOutcome) - REJECTED_MODEL_OUTCOMES - POLICY_PLANNED_OUTCOMES
            ),
            "then": no_rejections,
        },
        {
            "if": {
                "required": ["accepted_plan"],
                "properties": {
                    "planner_outcome": {"enum": list_enum_values(POLICY_PLANNED_OUTCOMES)},
                    "accepted_plan": {"minItems": 1},
                },
            },
            "then": no_rejections,
        },
    ]
    for planner_outcome, first_code in FIRST_REJECTION_BY_OUTCOME.items():
        rules.append(
            {
                "if": require_outcome_in({planner_outcome}),
                "then": {
                    "properties": {
                        "rejections": {
                            "prefixItems": [{"properties": {"code": {"const": first_code.value}}}]
                        }
                    }
                },
            }
        )
    return {"allOf": rules}


class RoundRecord(ContractModel):
    relevance_assessment: RelevanceAssessmentRecord | None = Field(default=None, exclude_if=not_)

    model_config = ConfigDict(json_schema_extra=describe_round_shape())

    round_number: Literal[1, 2]
    planner_outcome: PlannerOutcome
    rejections: tuple[PlanRejection, ...] = Field(
        description="The model plan's rejections, then those of the deterministic plan it fell "
        "back to."
    )
    model_reply: ModelReply | None = Field(
        default=None,
        description=(
            "The model's reply as the port returned it, a plan or a typed failure; recorded "
            "exactly when the model replied, in time or not. The decision-path audit parses "
            "and gates a reply received in time again; a reply received after the deadline "
            "is recorded but never parsed."
        ),
    )
    model_reply_sha256: str | None = Field(
        default=None,
        pattern=SHA256_PATTERN,
        description=(
            "Hash of model_reply; the validator recomputes it from the reply and rejects a "
            "mismatch."
        ),
    )
    accepted_plan: tuple[ToolCall, ...]
    executed_step_indices: tuple[int, ...]


class RankingConfiguration(ContractModel):
    rrf_k: int = Field(ge=1)
    relevance_tier_order: tuple[RelevanceTier, ...]
    merge_rule: Literal["named_then_tier_then_product_match_then_lexical_then_step_then_tool_rank"]


def describe_trajectory_shape() -> JsonDict:
    """The validator's planner-kind rules as JSON Schema: each round records an outcome
    its planner kind records, and a step is planned by the model only where a round could
    accept the model's plan."""
    rules: list[JsonValue] = []
    for planner_kind in PlannerKind:
        planner_outcomes = PLANNER_OUTCOMES_BY_KIND[planner_kind]
        step_planners = [PlannerKind.DETERMINISTIC]
        if PlannerOutcome.MODEL_ACCEPTED in planner_outcomes:
            step_planners.append(PlannerKind.MODEL)
        rules.append(
            {
                "if": {
                    "properties": {
                        "planner": {"properties": {"kind": {"const": planner_kind.value}}}
                    }
                },
                "then": {
                    "properties": {
                        "rounds": {"items": require_outcome_in(planner_outcomes)},
                        "steps": {
                            "items": {
                                "properties": {
                                    "planned_by": {"enum": list_enum_values(step_planners)}
                                }
                            }
                        },
                    }
                },
            }
        )
    rules.append(
        {
            "if": {
                "properties": {
                    "rounds": {
                        "contains": {
                            "properties": {
                                "round_number": {"const": 2},
                                "planner_outcome": {
                                    "const": PlannerOutcome.MODEL_NOT_CONSULTED.value
                                },
                            }
                        }
                    }
                }
            },
            "then": {
                "properties": {
                    "rounds": {
                        "prefixItems": [
                            {
                                "required": ["relevance_assessment"],
                                "properties": {
                                    "relevance_assessment": {
                                        "type": "object",
                                        "properties": {"accepted_search": {"type": "object"}},
                                    }
                                },
                            }
                        ]
                    }
                }
            },
        }
    )
    return {"allOf": rules}


class Trajectory(ContractModel):
    """Everything needed to replay the run's decisions; nothing time-dependent."""

    model_config = ConfigDict(json_schema_extra=describe_trajectory_shape())

    planner: PlannerIdentity
    ranking: RankingConfiguration
    randomness: Literal["none"] = "none"
    transitions: tuple[StateTransition, ...] = Field(max_length=MAX_TRANSITIONS)
    rounds: tuple[RoundRecord, ...] = Field(max_length=MAX_ROUNDS)
    steps: tuple[ToolStep, ...] = Field(max_length=MAX_TOOL_CALLS)
    budget_used: BudgetUsage
    evidence_ids: tuple[EvidenceId, ...]


class StepTiming(ContractModel):
    step_index: int = Field(ge=1)
    started_offset_ms: int = Field(ge=0, description="Milliseconds after the run started.")
    duration_ms: int = Field(ge=0)


class RunTimings(ContractModel):
    """Measured times; validated, but excluded from ``result_sha256``."""

    started_at: Timestamp
    wall_time_ms: int = Field(ge=0)
    planner_durations_ms: tuple[int, ...]
    steps: tuple[StepTiming, ...]


class SourceCapabilityState(StrEnum):
    AVAILABLE = "available"
    NOT_CONFIGURED = "not_configured"
    UNAVAILABLE = "unavailable"


class FightUnavailableDetail(StrEnum):
    """The server's sentence for an unavailable ``mitre_fight`` capability."""

    NOT_PINNED = "no pinned FiGHT snapshot is served"


CapabilitySubject = KnowledgeSource | Literal["semantic_channel", "model_planner"]
# Every evidence set describes each subject once, in this order.
CAPABILITY_SUBJECTS: tuple[CapabilitySubject, ...] = (
    KnowledgeSource.CVE_SEARCH,
    KnowledgeSource.MITRE_FIGHT,
    KnowledgeSource.AFFECTEDNESS,
    "semantic_channel",
    "model_planner",
)
# How a published field holding ``source_capabilities`` states their order.
CAPABILITY_ORDER_DESCRIPTION = (
    f"{', '.join(str(subject) for subject in CAPABILITY_SUBJECTS[:-1])} and "
    f"{CAPABILITY_SUBJECTS[-1]}, once each and in that order."
)
# The states a deployment can report for each subject: the CVE fixture is always loaded,
# no adapter is verified to serve affectedness (ADR 0003), and an enabled semantic channel
# or a configured model planner that cannot serve is unavailable (ADR 0004).
CAPABILITY_STATES_BY_SUBJECT: dict[CapabilitySubject, frozenset[SourceCapabilityState]] = {
    KnowledgeSource.CVE_SEARCH: frozenset({SourceCapabilityState.AVAILABLE}),
    KnowledgeSource.MITRE_FIGHT: frozenset(
        {SourceCapabilityState.AVAILABLE, SourceCapabilityState.UNAVAILABLE}
    ),
    KnowledgeSource.AFFECTEDNESS: frozenset({SourceCapabilityState.UNAVAILABLE}),
    "semantic_channel": frozenset(SourceCapabilityState),
    "model_planner": frozenset(SourceCapabilityState),
}
# Subjects that name what they serve when available: the CVE fixture, the FiGHT snapshot
# and the planner's model.
VERSIONED_CAPABILITY_SUBJECTS: frozenset[CapabilitySubject] = frozenset(
    {KnowledgeSource.CVE_SEARCH, KnowledgeSource.MITRE_FIGHT, "model_planner"}
)
# The server's sentences an unavailable capability of each subject gives; a subject that is
# never unavailable gives none.
UNAVAILABLE_DETAILS_BY_SUBJECT: dict[CapabilitySubject, tuple[StrEnum, ...]] = {
    KnowledgeSource.CVE_SEARCH: (),
    KnowledgeSource.MITRE_FIGHT: tuple(FightUnavailableDetail),
    KnowledgeSource.AFFECTEDNESS: tuple(AffectednessDetail),
    "semantic_channel": tuple(SemanticUnavailableDetail),
    "model_planner": tuple(ModelPlannerUnavailableDetail),
}


def describe_capability_field(field_name: str, is_named_when_available: bool) -> JsonDict:
    """JSON Schema setting ``field_name`` exactly when the capability is available and its
    subject names one."""
    if not is_named_when_available:
        return {"properties": {field_name: {"type": "null"}}}
    return {
        "if": {"properties": {"state": {"const": SourceCapabilityState.AVAILABLE.value}}},
        "then": {"required": [field_name], "properties": {field_name: {"not": {"type": "null"}}}},
        "else": {"properties": {field_name: {"type": "null"}}},
    }


def describe_unavailable_detail() -> JsonDict:
    """JSON Schema setting ``detail`` exactly when the capability is unavailable."""
    return {
        "if": {"properties": {"state": {"const": SourceCapabilityState.UNAVAILABLE.value}}},
        "then": {"required": ["detail"], "properties": {"detail": {"type": "string"}}},
        "else": {"properties": {"detail": {"type": "null"}}},
    }


def describe_subject_details(subject: CapabilitySubject) -> JsonDict:
    """JSON Schema limiting ``detail`` to the sentences ``subject`` gives when unavailable."""
    subject_details: list[JsonValue] = []
    for unavailable_detail in UNAVAILABLE_DETAILS_BY_SUBJECT[subject]:
        subject_details.append(unavailable_detail.value)
    subject_details.append(None)
    return {"properties": {"detail": {"enum": subject_details}}}


def describe_capability_shape() -> JsonDict:
    """The validator's per-capability shape rules as JSON Schema: each subject reports one
    of its states, with a version and a coverage exactly where that state names one, and a
    detail, one of the subject's sentences, exactly when it is unavailable."""
    subject_rules: list[JsonValue] = []
    for subject in CAPABILITY_SUBJECTS:
        subject_states: list[JsonValue] = []
        for state in SourceCapabilityState:
            if state in CAPABILITY_STATES_BY_SUBJECT[subject]:
                subject_states.append(state.value)
        subject_rules.append(
            {
                "if": {"properties": {"source": {"const": str(subject)}}},
                "then": {
                    "properties": {"state": {"enum": subject_states}},
                    "allOf": [
                        describe_capability_field(
                            "version", subject in VERSIONED_CAPABILITY_SUBJECTS
                        ),
                        describe_capability_field(
                            "coverage", subject == KnowledgeSource.MITRE_FIGHT
                        ),
                        describe_subject_details(subject),
                    ],
                },
            }
        )
    subject_rules.append(describe_unavailable_detail())
    return {"allOf": subject_rules}


def pin_capability_order(field_schema: JsonDict) -> None:
    """JSON Schema for ``source_capabilities``: one capability per subject, in
    ``CAPABILITY_SUBJECTS`` order."""
    capability_schema = field_schema["items"]
    subject_slots: list[JsonValue] = []
    for subject in CAPABILITY_SUBJECTS:
        subject_slots.append(
            {"allOf": [capability_schema, {"properties": {"source": {"const": str(subject)}}}]}
        )
    field_schema["prefixItems"] = subject_slots
    field_schema["minItems"] = len(CAPABILITY_SUBJECTS)
    field_schema["items"] = False


class SourceCapability(ContractModel):
    """The validator checks every capability's shape, which the published schema states."""

    model_config = ConfigDict(json_schema_extra=describe_capability_shape())

    source: CapabilitySubject
    state: SourceCapabilityState
    version: str | None = Field(
        default=None,
        max_length=256,
        description="Set exactly for an available cve_search, mitre_fight or model_planner.",
    )
    coverage: SnapshotCoverage | None = Field(
        default=None, description="Set exactly for an available mitre_fight."
    )
    detail: (
        FightUnavailableDetail
        | AffectednessDetail
        | SemanticUnavailableDetail
        | ModelPlannerUnavailableDetail
        | None
    ) = Field(
        default=None,
        description=(
            "The server's sentence for why the source is unavailable; set exactly for an "
            "unavailable capability."
        ),
    )


def describe_planner_capability(
    planner: PlannerIdentity, unavailable_detail: ModelPlannerUnavailableDetail | None = None
) -> SourceCapability:
    """The ``model_planner`` capability of a service whose trajectories record ``planner``:
    available with the model's version (``format_planner_version``); for the deterministic
    policy, unavailable with
    ``unavailable_detail`` when a configured model planner cannot plan, otherwise not
    configured."""
    if isinstance(planner, ModelPlannerIdentity):
        return SourceCapability(
            source="model_planner",
            state=SourceCapabilityState.AVAILABLE,
            version=format_planner_version(planner),
        )
    if unavailable_detail is not None:
        return SourceCapability(
            source="model_planner",
            state=SourceCapabilityState.UNAVAILABLE,
            detail=unavailable_detail,
        )
    return SourceCapability(source="model_planner", state=SourceCapabilityState.NOT_CONFIGURED)


def find_planner_unavailable_detail(
    source_capabilities: Sequence[SourceCapability],
) -> ModelPlannerUnavailableDetail | None:
    """Why the configured model planner could not plan, as the ``model_planner`` capability
    states it; ``None`` when it is available or not configured."""
    for capability in source_capabilities:
        if capability.source == "model_planner" and isinstance(
            capability.detail, ModelPlannerUnavailableDetail
        ):
            return capability.detail
    return None


def find_affectedness_detail(source_capabilities: Sequence[SourceCapability]) -> AffectednessDetail:
    """Why affectedness is unavailable: the detail of the ``affectedness`` capability, which
    every well-formed capability list holds, unavailable and so with one of the
    ``AffectednessDetail`` sentences. Raises ``ValueError`` for a list without one."""
    for capability in source_capabilities:
        if capability.source == KnowledgeSource.AFFECTEDNESS and isinstance(
            capability.detail, AffectednessDetail
        ):
            return capability.detail
    raise ValueError("the capabilities describe no unavailable affectedness source")


class ApplicabilityBasis(StrEnum):
    """Why a product's applicability has its status, one fixed sentence per reason, so no
    basis can claim a verdict the status does not carry."""

    NO_VERIFIED_AFFECTEDNESS_SOURCE = (
        "No verified affectedness source is available, so whether this product is affected "
        "is unknown; neither a CVE match nor threat context establishes it."
    )


class ProductApplicability(ContractModel):
    product_kind: ProductKind
    product: str = Field(min_length=1, max_length=512)
    status: ApplicabilityStatus
    basis: ApplicabilityBasis


class InvestigationCandidate(ContractModel):
    relevance_label: RelevanceLabel | None = Field(default=None, exclude_if=not_)

    rank: int = Field(ge=1)
    candidate: Candidate
    relevance: RelevanceAssessment | None = Field(
        description=(
            "Relevance to the resolved topic; null when no topic resolved, or for a CVE the "
            "caller named by ID that does not relate to the topic."
        )
    )
    found_by_steps: tuple[int, ...] = Field(min_length=1)
    nvd_version_notes: tuple[NvdVersionNote, ...] | None = Field(
        default=None,
        exclude_if=not_,
        min_length=1,
        description=(
            "One annotation per affectedness mention, in mention order; omitted without "
            "mentions. Numeric dot segments compare with missing trailing zeros; only "
            "exact conditions can match non-numeric versions by trimmed string equality. "
            "These notes do not evaluate configuration, environment or affectedness. "
            "The evidence-set validator recomputes each note from the candidate record."
        ),
    )


class ExcludedInvestigationCandidate(ContractModel):
    candidate: InvestigationCandidate
    reason: str = Field(min_length=1)


class EvidenceNeedKind(StrEnum):
    NAMED_CVE = "named_cve"
    IMPLEMENTATION_CVES = "implementation_cves"
    PROTOCOL_CONTEXT = "protocol_context"
    AFFECTEDNESS = "affectedness"


class NeedOutcome(StrEnum):
    """Whether a need was met. ``found``: the evidence was reached through an exact
    correspondence or a reviewed mapping, an exact lookup that returned the named CVE or the
    reviewed topic call that returned evidence for the resolved topic; it does not prove the
    answer sufficient. ``matches_unassessed``: a pending-review topic or a search on the
    question's own words returned matches whose relevance the run did not assess; it says
    nothing about whether relevant evidence exists. ``unsupported``: no tool can serve it
    for this interpretation.
    ``not_evaluated``: no admitted step of a tool that serves it has a result, so whether it
    is met cannot yet be judged. ``not_evaluated``, ``not_found`` and
    ``matches_unassessed`` are open; ``source_unavailable`` and ``unsupported`` are final."""

    FOUND = "found"
    MATCHES_UNASSESSED = "matches_unassessed"
    NOT_FOUND = "not_found"
    SOURCE_UNAVAILABLE = "source_unavailable"
    UNSUPPORTED = "unsupported"
    NOT_EVALUATED = "not_evaluated"


class EvidenceNeed(ContractModel):
    """One kind of evidence the request asks for, and whether the run met it."""

    kind: EvidenceNeedKind
    subject: str | None = Field(
        description=(
            "The CVE ID for named_cve, the product for affectedness, none for the other kinds."
        )
    )
    outcome: NeedOutcome


class CoverageAssessment(ContractModel):
    answer_sources: tuple[KnowledgeSource, ...]
    source_outcomes: tuple[SourceOutcome, ...] = Field(
        description="One per answer source a step consulted or the answer required."
    )
    refinement_applied: bool
    basis: DecisionBasis = Field(description="The observation the final stop was decided on.")
    needs: tuple[EvidenceNeed, ...] = Field(
        description=(
            "What the request asks for, derived from the request and its interpretation, never "
            "from labelled cases, each with the outcome the admitted steps and the answer give; "
            "sufficient only when every need is found."
        )
    )


class InvestigationWarningCode(StrEnum):
    PRODUCT_NAME_AMBIGUOUS = "product_name_ambiguous"
    EXCLUDED_TERM = "excluded_term"
    TOPIC_NOT_RESOLVED = "topic_not_resolved"
    TOPIC_PENDING_REVIEW = "topic_pending_review"
    TOPIC_FAMILY_SCOPE = "topic_family_scope"
    NO_SEARCHABLE_TERMS = "no_searchable_terms"
    APPLICABILITY_UNKNOWN = "applicability_unknown"
    MODEL_PLAN_REJECTED = "model_plan_rejected"
    EVIDENCE_DISCARDED = "evidence_discarded"
    EVIDENCE_PREFIX_OMITTED = "evidence_prefix_omitted"
    UNRELATED_CANDIDATES_DROPPED = "unrelated_candidates_dropped"
    ANSWER_TRUNCATED = "answer_truncated"
    RESULT_LIMIT_REACHED = "result_limit_reached"
    TERM_NOT_INDEXED = "term_not_indexed"


class InvestigationWarning(ContractModel):
    """What the run could not do or left out. ``answer_truncated`` counts, each once, the
    items the adopted steps knew and the answer does not list: the CVEs they kept (a CVE
    the caller named always kept), those the topic step kept and left out at its limit
    included, less the CVEs the answer lists, plus the techniques the step that searched
    FiGHT (a topic step or a direct FiGHT search) matched and did not list.
    ``evidence_prefix_omitted`` names a step and the count its context budget omitted;
    topic truncation warnings include admission omissions, and search-limit warnings
    describe the original retrieval. ``answer_truncated`` excludes context-budget omissions.
    ``unrelated_candidates_dropped`` counts search-step candidates the
    relevance rule removed, never one ``answer_truncated`` counts.
    ``result_limit_reached`` names ``max_results_per_call`` once when a CVE search of an
    adopted step warned it reached that limit, so more matches may exist; it never counts
    them. It covers only searches whose CVEs can be in the answer, so a
    ``protocol_context_only`` run never raises it. ``term_not_indexed`` names, once each, a
    search term an adopted step warned no CVE record (or, for a direct FiGHT search, no
    technique) holds; the step's own warning says which source.
    ``topic_family_scope`` explains that the matched GTP alias retrieves the whole
    family, including GTP-C and GTP-U."""

    code: InvestigationWarningCode
    subject: str


def build_prefix_omitted_warning(step_index: int, prefix: PrefixAdmission) -> InvestigationWarning:
    """Name the step and the exact number of returned entries its byte prefix omitted."""
    omitted_count = sum(count.omitted for count in prefix.counts)
    return InvestigationWarning(
        code=InvestigationWarningCode.EVIDENCE_PREFIX_OMITTED,
        subject=f"step {step_index}: {omitted_count} results omitted",
    )


def reaches_result_limit(step: ToolStep) -> bool:
    """Whether the step's CVE search, or one of its topic's card searches, warned that it
    reached its limit."""
    return any(
        warning.code is SearchWarningCode.RESULT_LIMIT_REACHED for warning in step.search_warnings
    ) or any(
        warning.code is TopicContextWarningCode.RESULT_LIMIT_REACHED
        for warning in step.topic_warnings
    )


def list_unindexed_terms(steps: Sequence[ToolStep]) -> list[str]:
    """Each term the steps warned ``term_not_indexed`` about, a CVE search's or a direct
    FiGHT search's, once, in the order first warned."""
    warned_terms: list[str] = []
    for step in steps:
        for search_warning in step.search_warnings:
            if search_warning.code is SearchWarningCode.TERM_NOT_INDEXED:
                warned_terms.append(search_warning.subject)
        for topic_warning in step.topic_warnings:
            if topic_warning.code is TopicContextWarningCode.TERM_NOT_INDEXED:
                warned_terms.append(topic_warning.subject)
    unindexed_terms: list[str] = []
    for warned_term in warned_terms:
        if warned_term not in unindexed_terms:
            unindexed_terms.append(warned_term)
    return unindexed_terms


def list_step_notices(
    adopted_steps: Sequence[ToolStep], request: InvestigationRequest
) -> list[InvestigationWarning]:
    """What the answer repeats from the steps it was assembled from, so a reader sees it
    without the trajectory: ``result_limit_reached`` naming ``max_results_per_call`` when
    one of them reached its limit, then one ``term_not_indexed`` per unindexed term.

    A ``protocol_context_only`` answer lists no CVE, and its only CVE searches are a topic
    card's (the gate refuses CVE tools under that scope), so a limit they reached hides
    nothing the answer could list: the topic step keeps its own warning and the answer
    raises none."""
    step_notices: list[InvestigationWarning] = []
    lists_cves = request.scope is not QueryScope.PROTOCOL_CONTEXT_ONLY
    if lists_cves and any(map(reaches_result_limit, adopted_steps)):
        step_notices.append(
            InvestigationWarning(
                code=InvestigationWarningCode.RESULT_LIMIT_REACHED,
                subject=str(request.budget.max_results_per_call),
            )
        )
    for unindexed_term in list_unindexed_terms(adopted_steps):
        step_notices.append(
            InvestigationWarning(
                code=InvestigationWarningCode.TERM_NOT_INDEXED, subject=unindexed_term
            )
        )
    return step_notices


STATUSES_BY_STOP_REASON: dict[StopReason, frozenset[ResultStatus]] = {
    StopReason.SUFFICIENT: frozenset({ResultStatus.OK}),
    StopReason.NO_EVIDENCE: frozenset({ResultStatus.NO_MATCH}),
    StopReason.SOURCE_UNAVAILABLE: frozenset(
        {
            ResultStatus.PARTIAL,
            ResultStatus.SOURCE_UNAVAILABLE,
            ResultStatus.BACKEND_ERROR,
            ResultStatus.INCOMPLETE_INDEX,
        }
    ),
    StopReason.BUDGET_EXHAUSTED: frozenset({ResultStatus.PARTIAL}),
    StopReason.POLICY_BLOCKED: frozenset({ResultStatus.POLICY_BLOCKED}),
    StopReason.INVALID_EVIDENCE: frozenset({ResultStatus.BACKEND_ERROR}),
    StopReason.NEEDS_UNMET: frozenset({ResultStatus.PARTIAL}),
}


def describe_evidence_set_shape() -> JsonDict:
    """The validator's single-set rules as JSON Schema: the stop reason fixes the statuses
    the set may report (``STATUSES_BY_STOP_REASON``), and the requested and applied scope
    are both the request's scope."""
    rules: list[JsonValue] = []
    for stop_reason, statuses in STATUSES_BY_STOP_REASON.items():
        rules.append(
            {
                "if": {"properties": {"stop_reason": {"const": stop_reason.value}}},
                "then": {"properties": {"status": {"enum": list_enum_values(statuses)}}},
            }
        )
    for scope in QueryScope:
        scope_value: JsonDict = {"const": scope.value}
        rules.append(
            {
                "if": {"properties": {"request": {"properties": {"scope": scope_value}}}},
                "then": {
                    "properties": {"requested_scope": scope_value, "applied_scope": scope_value}
                },
            }
        )
    return {"allOf": rules}


class KnowledgeEvidenceSet(ContractModel):
    model_config = ConfigDict(json_schema_extra=describe_evidence_set_shape())

    schema_version: SchemaVersion = SCHEMA_VERSION
    investigation_id: str = Field(
        pattern=INVESTIGATION_ID_PATTERN,
        description=(
            "Derived from the schema version and the request; the server re-derives it and "
            "rejects a mismatch."
        ),
    )
    request: InvestigationRequest
    normalized_query: str
    requested_scope: QueryScope
    applied_scope: QueryScope
    interpretation: Interpretation
    status: ResultStatus
    stop_reason: StopReason
    implementation_candidates: tuple[InvestigationCandidate, ...] = Field(
        description="CVE candidates; empty under protocol_context_only."
    )
    excluded_implementation_candidates: tuple[ExcludedInvestigationCandidate, ...] = Field(
        description="CVEs kept out of a protocol_context_only answer, with the reason."
    )
    protocol_context: tuple[ThreatContextItem, ...] = Field(
        description="FiGHT threat context; empty under implementation_only."
    )
    product_applicability: tuple[ProductApplicability, ...]
    claims: tuple[Claim, ...] = Field(description="Ordered by claim_id.")
    evidence: tuple[EvidenceAnchor, ...] = Field(description="Ordered by evidence_id.")
    coverage: CoverageAssessment
    warnings: tuple[InvestigationWarning, ...]
    source_capabilities: tuple[SourceCapability, ...] = Field(
        description=(
            "What the deployment that ran the investigation serves: "
            f"{CAPABILITY_ORDER_DESCRIPTION} The server rejects capabilities other than its "
            "own deployment's, or ones that disagree with the run."
        ),
        json_schema_extra=pin_capability_order,
    )
    trajectory: Trajectory
    timings: RunTimings
    result_sha256: str = Field(
        pattern=SHA256_PATTERN,
        description=(
            "SHA-256 of the canonical JSON of this set without this field and timings; the "
            "server recomputes it and rejects a mismatch."
        ),
    )

    def compute_result_sha256(self) -> str:
        """Equal requests over equal data hash equally, whenever and however fast they ran."""
        return canonical_sha256(self.model_dump(mode="json", exclude={"result_sha256", "timings"}))

    def has_answer(self) -> bool:
        """Excluded candidates are context for a protocol answer, never the answer itself."""
        return bool(self.implementation_candidates or self.protocol_context)


def format_implementation_claim_id(cve_id: str) -> str:
    return f"cve:{cve_id}"


def format_threat_context_claim_id(technique_id: str) -> str:
    return f"fight:{technique_id}"


def format_implementation_statement(cve_id: str) -> str:
    return (
        f"{cve_id} is a CVE record of an implementation vulnerability; "
        "it does not establish a protocol-design flaw."
    )


def format_threat_context_statement(item: ThreatContextItem) -> str:
    """The claim about one technique, from its ID and status only: its name is source text,
    which a claim, a server sentence, never carries."""
    return (
        f"MITRE FiGHT lists {item.technique_id} as {item.status.value} protocol threat "
        "context; it is not formal proof."
    )


def list_record_evidence_ids(
    record: CveRecord, anchors_by_id: Mapping[str, EvidenceAnchor]
) -> tuple[str, ...]:
    """The record's evidence IDs whose anchor is about the record itself: what its claim cites.

    An ID without an anchor in ``anchors_by_id`` is left out; the anchor checks report it.
    """
    record_evidence_ids: list[str] = []
    for evidence_id in record.evidence_ids:
        anchor = anchors_by_id.get(evidence_id)
        if anchor is not None and anchor.authoritative_record_id == record.cve_id:
            record_evidence_ids.append(evidence_id)
    return tuple(record_evidence_ids)


def has_product_context(filters: SearchFilters) -> bool:
    return bool(filters.vendors or filters.products or filters.purls)


def list_named_products(
    filters: SearchFilters, affectedness_mentions: Sequence[str]
) -> list[tuple[ProductKind, str]]:
    """The product context: each named vendor, product and purl, in that order, then each
    product version the query asks affectedness of."""
    named_products: list[tuple[ProductKind, str]] = []
    for vendor in filters.vendors:
        named_products.append(("vendor", vendor))
    for product in filters.products:
        named_products.append(("product", product))
    for purl in filters.purls:
        named_products.append(("purl", purl))
    for affectedness_mention in affectedness_mentions:
        named_products.append(("product_version", affectedness_mention))
    return named_products


def list_answer_sources(
    scope: QueryScope, filters: SearchFilters, affectedness_mentions: Sequence[str]
) -> tuple[KnowledgeSource, ...]:
    """Sources whose results form the answer, in enum order.

    Product context, from filters or a product version the query asks affectedness of,
    makes affectedness an answer source, except under ``protocol_context_only``, which
    never answers about products.
    """
    scope_sources = set(ANSWER_SOURCES_BY_SCOPE[scope])
    has_products = has_product_context(filters) or bool(affectedness_mentions)
    if has_products and scope is not QueryScope.PROTOCOL_CONTEXT_ONLY:
        scope_sources.add(KnowledgeSource.AFFECTEDNESS)
    answer_sources: list[KnowledgeSource] = []
    for source in KnowledgeSource:
        if source in scope_sources:
            answer_sources.append(source)
    return tuple(answer_sources)


def derive_investigation_id(request: InvestigationRequest) -> str:
    """Content-derived: identical requests under one schema version share an ID."""
    identity = {"schema_version": SCHEMA_VERSION, "request": request.model_dump(mode="json")}
    return "inv:" + canonical_sha256(identity)[:24]


def decide_investigation_status(
    stop_reason: StopReason, has_answer: bool, answer_statuses: Iterable[ResultStatus]
) -> ResultStatus:
    """The status for a stop; otherwise decided over the answer sources' outcomes."""
    if stop_reason is StopReason.POLICY_BLOCKED:
        return ResultStatus.POLICY_BLOCKED
    if stop_reason is StopReason.INVALID_EVIDENCE:
        return ResultStatus.BACKEND_ERROR
    if stop_reason in (StopReason.BUDGET_EXHAUSTED, StopReason.NEEDS_UNMET):
        return ResultStatus.PARTIAL
    return summarize_statuses(answer_statuses, has_answer)
