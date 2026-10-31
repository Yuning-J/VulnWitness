"""The controller's planning and stop decisions, as pure functions of a run's recorded
observations.

The controller decides with these functions while it runs, and the decision-path
audit re-derives a sealed set's decisions with the same functions over what the set
records, so a decision has one implementation and the audit cannot drift from it. A
round's plan is one of them: given the model's reply the round records, the plan the
round runs, its planner outcome, rejections, warning, stop and breach follow from the
request, the topic registry and the steps issued before it.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from cve_kgrag.application.investigation_policy import PlannedStep, list_calls
from cve_kgrag.application.investigation_warnings import build_model_plan_rejected_warning
from cve_kgrag.application.plan_gate import (
    PlanContext,
    build_plan_context,
    canonicalize_call,
    find_plan_rejections,
    list_plan_sources,
    parse_plan_text,
)
from cve_kgrag.domain.budget import BudgetBreach
from cve_kgrag.domain.evidence_needs import (
    has_affectedness_need,
    has_unmet_need_beyond_affectedness,
)
from cve_kgrag.domain.investigation import (
    ADMITTED_ADMISSIONS,
    FIRST_REJECTION_BY_OUTCOME,
    DecisionBasis,
    EvidenceNeed,
    Interpretation,
    InvestigationRequest,
    InvestigationWarning,
    NeedOutcome,
    PlannerOutcome,
    StepAdmission,
    StepReason,
    StopReason,
    ToolStep,
    list_answer_sources,
)
from cve_kgrag.domain.planning import (
    ModelReply,
    PlannerKind,
    PlanRejection,
    PlanRejectionCode,
    QueryIntent,
)
from cve_kgrag.domain.topic import ProtocolTopic
from cve_kgrag.domain.topic_context import SERVED_STATUSES, KnowledgeSource
from cve_kgrag.topics.registry import TopicRegistry

Stop = tuple[StopReason, DecisionBasis]
DEADLINE_STOP: Stop = (StopReason.BUDGET_EXHAUSTED, DecisionBasis.BUDGET_BREACHED)
ROUND_CAP_STOP: Stop = (StopReason.BUDGET_EXHAUSTED, DecisionBasis.ROUND_CAP_REACHED)
PLAN_OVER_BUDGET_STOP: Stop = (StopReason.BUDGET_EXHAUSTED, DecisionBasis.PLAN_OVER_BUDGET)
BUDGET_REJECTION_CODES = frozenset(
    {PlanRejectionCode.OVER_TOOL_CALL_BUDGET, PlanRejectionCode.OVER_SOURCE_BUDGET}
)
# A step whose result stays out of the answer for a cap: retrieving it breached that cap.
CAP_BREACH_ADMISSIONS = frozenset(
    {
        StepAdmission.DISCARDED_AFTER_DEADLINE,
        StepAdmission.DISCARDED_OVER_CONTEXT_BUDGET,
        StepAdmission.TIMED_OUT,
    }
)


@dataclass(frozen=True)
class RoundPlan:
    """Everything planning a round decides: the steps it runs, who planned them, the outcome
    and rejections it records with the model's reply, the warning a rejected reply raises,
    and the stop and breach when the round runs nothing."""

    planned_steps: tuple[PlannedStep, ...]
    planned_by: PlannerKind
    planner_outcome: PlannerOutcome
    rejections: tuple[PlanRejection, ...]
    model_reply: ModelReply | None
    warnings: tuple[InvestigationWarning, ...]
    stop: Stop | None
    breach: BudgetBreach | None


@dataclass(frozen=True)
class ModelProposal:
    """What a model reply amounts to once parsed and gated: its steps when accepted, else
    why it was rejected."""

    planned_steps: tuple[PlannedStep, ...]
    planner_outcome: PlannerOutcome
    rejections: tuple[PlanRejection, ...]


def decide_open_stop(needs: Sequence[EvidenceNeed], has_answer: bool, basis: DecisionBasis) -> Stop:
    """The stop with a need left open and no call to meet it: ``needs_unmet`` with an
    answer, else honest ``no_evidence``, unless the unavailable affectedness source was
    needed to answer at all."""
    if has_answer and has_unmet_need_beyond_affectedness(needs):
        return StopReason.NEEDS_UNMET, basis
    if has_affectedness_need(needs):
        return StopReason.SOURCE_UNAVAILABLE, basis
    return StopReason.NO_EVIDENCE, basis


def decide_rejected_plan_stop(rejections: Sequence[PlanRejection]) -> Stop:
    """The stop when the gate rejects the policy's own plan: over budget is a breach; any
    other rejection is a defect, blocked rather than run."""
    rejection_codes: set[PlanRejectionCode] = set()
    for rejection in rejections:
        rejection_codes.add(rejection.code)
    if not rejection_codes <= BUDGET_REJECTION_CODES:
        return StopReason.POLICY_BLOCKED, DecisionBasis.PLAN_REJECTED_BY_POLICY
    return PLAN_OVER_BUDGET_STOP


def decide_over_budget_breach(rejections: Sequence[PlanRejection]) -> BudgetBreach:
    """The cap a plan the gate rejected as over budget breached: tool calls before sources."""
    if any(rejection.code is PlanRejectionCode.OVER_TOOL_CALL_BUDGET for rejection in rejections):
        return BudgetBreach.TOOL_CALLS
    return BudgetBreach.SOURCES


def decide_assessment(
    request: InvestigationRequest,
    interpretation: Interpretation,
    steps: Sequence[ToolStep],
    is_breached: bool,
    needs: Sequence[EvidenceNeed],
    has_answer: bool,
) -> Stop | None:
    """The stop the steps so far justify, or ``None`` when a need is still open.

    In order: a step's evidence failed integrity, a cap was breached, an admitted step
    saw an answer source fail, every need was met, then an answer whose only unmet needs
    are the unavailable affectedness source's.
    """
    if any(step.admission is StepAdmission.REJECTED_INVALID_EVIDENCE for step in steps):
        return StopReason.INVALID_EVIDENCE, DecisionBasis.EVIDENCE_INVALID
    if is_breached:
        return StopReason.BUDGET_EXHAUSTED, DecisionBasis.BUDGET_BREACHED
    answer_sources = list_answer_sources(
        request.scope, request.filters, interpretation.affectedness_mentions
    )
    for step in steps:
        if step.admission not in ADMITTED_ADMISSIONS:
            continue
        for step_outcome in step.source_outcomes:
            is_answer_source = step_outcome.source in answer_sources
            if is_answer_source and step_outcome.status not in SERVED_STATUSES:
                return StopReason.SOURCE_UNAVAILABLE, DecisionBasis.ANSWER_SOURCE_FAILED
    if all(need.outcome is NeedOutcome.FOUND for need in needs):
        return StopReason.SUFFICIENT, DecisionBasis.ANSWER_FOUND
    if has_answer and not has_unmet_need_beyond_affectedness(needs):
        return StopReason.SOURCE_UNAVAILABLE, DecisionBasis.AFFECTEDNESS_UNAVAILABLE
    return None


def decide_refinement_stop(
    request: InvestigationRequest,
    refinement_steps: Sequence[PlannedStep],
    needs: Sequence[EvidenceNeed],
    has_answer: bool,
) -> Stop | None:
    """The stop on entering refine, or ``None`` when round 2 is planned.

    Round 2 is planned only for the policy's refinement, a call that serves an open need;
    without one the run stops, and a configured model is not consulted. Under
    ``max_rounds`` 1 a refinement breaches the round cap.
    """
    if not refinement_steps:
        return decide_open_stop(needs, has_answer, DecisionBasis.NO_REFINEMENT_AVAILABLE)
    if request.budget.max_rounds == 1:
        return ROUND_CAP_STOP
    return None


def read_model_reply(
    model_reply: ModelReply, plan_context: PlanContext, topic_registry: TopicRegistry
) -> ModelProposal:
    """``model_unavailable`` for a failed reply, ``model_rejected`` for plan text that is not
    a ``QueryPlan`` or that the gate rejects, else ``model_accepted`` with each call in
    canonical form."""
    # A failed reply carries detail and no plan text (``ModelReply`` enforces it).
    if model_reply.plan_text is None:
        unavailable_rejection = PlanRejection(code=PlanRejectionCode.PLANNER_UNAVAILABLE)
        return ModelProposal((), PlannerOutcome.MODEL_UNAVAILABLE, (unavailable_rejection,))
    query_plan = parse_plan_text(model_reply.plan_text)
    if query_plan is None:
        malformed_rejection = PlanRejection(code=PlanRejectionCode.MALFORMED_PLAN)
        return ModelProposal((), PlannerOutcome.MODEL_REJECTED, (malformed_rejection,))
    rejections = find_plan_rejections(query_plan.steps, plan_context, topic_registry)
    if rejections:
        return ModelProposal((), PlannerOutcome.MODEL_REJECTED, tuple(rejections))
    model_steps: list[PlannedStep] = []
    for call in query_plan.steps:
        model_steps.append(PlannedStep(canonicalize_call(call), StepReason.MODEL_PROPOSAL))
    return ModelProposal(tuple(model_steps), PlannerOutcome.MODEL_ACCEPTED, ())


def find_policy_plan_rejections(
    request: InvestigationRequest,
    interpretation: Interpretation,
    topic: ProtocolTopic | None,
    issued_steps: Sequence[ToolStep],
    policy_steps: Sequence[PlannedStep],
    topic_registry: TopicRegistry,
) -> tuple[PlanRejection, ...]:
    """What the gate rejects in the policy's plan, in the context the issued steps leave."""
    return tuple(
        find_plan_rejections(
            list_calls(policy_steps),
            build_plan_context(request, interpretation, topic, issued_steps, None),
            topic_registry,
        )
    )


def is_model_consultable(
    round_number: int, intent: QueryIntent, policy_rejections: Sequence[PlanRejection]
) -> bool:
    """Whether a configured model may plan the round.

    Not for free text (``QueryIntent.FREE_TEXT``: no kept CVE ID, no resolved topic), in
    any round: the policy plans free text alone, with the question's search terms as its
    baseline. That is product policy, not a completeness or sufficiency guarantee and not
    a safety rule. Nor round 1 when the policy's own plan is over the source budget, since
    a round-1 model plan must consult the policy's sources. A plan over the tool-call
    budget does not decide it: a model may reach the same sources with fewer calls (one
    search instead of a topic's template searches), and in round 2 it may propose any
    cheaper call."""
    if intent is QueryIntent.FREE_TEXT:
        return False
    is_over_source_budget = any(
        rejection.code is PlanRejectionCode.OVER_SOURCE_BUDGET for rejection in policy_rejections
    )
    return not (round_number == 1 and is_over_source_budget)


def choose_round_plan(
    request: InvestigationRequest,
    interpretation: Interpretation,
    topic: ProtocolTopic | None,
    issued_steps: Sequence[ToolStep],
    round_number: int,
    policy_steps: Sequence[PlannedStep],
    model_reply: ModelReply | None,
    consults_model: bool,
    topic_registry: TopicRegistry,
) -> RoundPlan:
    """The plan of a round planned before the deadline, from the model's reply when the
    model was consulted (``None`` when no model is configured).

    The model's plan runs when it passes the gate in the context the issued steps leave,
    with round 1's baseline sources. Otherwise the round falls back to the policy's plan,
    gated in the same context without a baseline; the round records the reply's
    rejections, then the policy plan's. A rejected policy plan runs nothing and stops as
    ``decide_rejected_plan_stop`` says. The policy's plan is never empty: round 1 plans a
    call for every intent that reaches planning, and round 2 is planned only for one. A
    configured model (``consults_model``) the round may not consult
    (``is_model_consultable``) is not consulted, whatever reply the round records: the
    round is the policy's, recorded ``model_not_consulted`` with no reply.
    """
    policy_rejections = find_policy_plan_rejections(
        request, interpretation, topic, issued_steps, policy_steps, topic_registry
    )
    model_rejections: tuple[PlanRejection, ...] = ()
    planner_outcome = PlannerOutcome.DETERMINISTIC
    warnings: tuple[InvestigationWarning, ...] = ()
    if consults_model and not is_model_consultable(
        round_number, interpretation.intent, policy_rejections
    ):
        planner_outcome = PlannerOutcome.MODEL_NOT_CONSULTED
        model_reply = None
    elif model_reply is not None:
        baseline_sources: frozenset[KnowledgeSource] | None = None
        if round_number == 1:
            baseline_sources = list_plan_sources(list_calls(policy_steps), request.scope)
        model_plan_context = build_plan_context(
            request, interpretation, topic, issued_steps, baseline_sources
        )
        proposal = read_model_reply(model_reply, model_plan_context, topic_registry)
        if proposal.planner_outcome is PlannerOutcome.MODEL_ACCEPTED:
            return RoundPlan(
                planned_steps=proposal.planned_steps,
                planned_by=PlannerKind.MODEL,
                planner_outcome=proposal.planner_outcome,
                rejections=(),
                model_reply=model_reply,
                warnings=(),
                stop=None,
                breach=None,
            )
        planner_outcome = proposal.planner_outcome
        model_rejections = proposal.rejections
        if planner_outcome is PlannerOutcome.MODEL_REJECTED:
            warnings = (build_model_plan_rejected_warning(round_number, model_rejections),)
    planned_steps = tuple(policy_steps)
    stop: Stop | None = None
    breach: BudgetBreach | None = None
    if policy_rejections:
        planned_steps = ()
        stop = decide_rejected_plan_stop(policy_rejections)
        if stop == PLAN_OVER_BUDGET_STOP:
            breach = decide_over_budget_breach(policy_rejections)
    return RoundPlan(
        planned_steps=planned_steps,
        planned_by=PlannerKind.DETERMINISTIC,
        planner_outcome=planner_outcome,
        rejections=model_rejections + policy_rejections,
        model_reply=model_reply,
        warnings=warnings,
        stop=stop,
        breach=breach,
    )


def plan_deadline_round(
    planner_outcome: PlannerOutcome, model_reply: ModelReply | None
) -> RoundPlan:
    """The plan of a round the deadline stopped: before planning (``deterministic`` without
    a model, ``model_skipped_at_deadline`` with one), before the model replied
    (``model_timed_out``), or with a reply that came too late (``model_reply_after_deadline``,
    whose reply the round still records). Nothing runs, and ``wall_time`` is the breach."""
    rejections: tuple[PlanRejection, ...] = ()
    rejection_code = FIRST_REJECTION_BY_OUTCOME.get(planner_outcome)
    if rejection_code is not None:
        rejections = (PlanRejection(code=rejection_code),)
    planned_by = PlannerKind.MODEL
    if planner_outcome is PlannerOutcome.DETERMINISTIC:
        planned_by = PlannerKind.DETERMINISTIC
    return RoundPlan(
        planned_steps=(),
        planned_by=planned_by,
        planner_outcome=planner_outcome,
        rejections=rejections,
        model_reply=model_reply,
        warnings=(),
        stop=DEADLINE_STOP,
        breach=BudgetBreach.WALL_TIME,
    )
