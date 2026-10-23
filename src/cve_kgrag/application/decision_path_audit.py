"""The decision-path audit: re-derives every decision a sealed knowledge evidence set
records, from its request, the topic registry and its own recorded observations, with
the controller's own decision functions, and rejects a set whose record says otherwise.

``validate_knowledge_evidence_set`` checks that a set's parts agree with one another.
A holder who rewrites a decision everywhere it shows (the interpretation, or a call
with its call key, accepted plan and backend request) and reseals the set passes that
check. This audit instead recomputes what the controller decides and requires the
record to say exactly that:

- the interpretation is the one ``interpret_request`` gives the request under this
  registry: intent, normalized query, CVE IDs, search terms, and the resolution, with
  every match's topic ID, version, content hash and review status and every excluded
  term;
- the run stops before planning exactly when ``find_interpretation_stop`` says so, for
  its reason;
- every round planned before the deadline is the one ``choose_round_plan`` gives over
  the model reply the round records, the policy's plan for that round
  (``plan_first_round``, or ``plan_refinement`` over round 1's recorded steps) and the
  gate's context rebuilt from the steps issued before the round
  (``build_plan_context``). The recorded reply is parsed and gated again, so the
  planner outcome, the rejections in order (the reply's, then the policy plan's), the
  accepted plan in canonical form, each step's planner and reason, the stop when the
  round runs nothing and the cap it breached are exactly the re-derived ones. A reply
  the gate rejects cannot be relabelled ``model_accepted``, a failed reply cannot be
  relabelled at all, and an accepted plan cannot be swapped for another the gate would
  also accept;
- a round the deadline stopped records the rejection its outcome fixes
  (``plan_deadline_round``) and runs nothing;
- every assess and refine decision is the one ``decide_assessment`` and
  ``decide_refinement_stop`` give over the recorded steps, so the transitions, the
  number of rounds and the stop reason are exactly the re-derived ones;
- the breach is the cap the decisions name: ``wall_time`` for the deadline, the
  call or source cap a rejected policy plan overran (``decide_over_budget_breach``),
  ``rounds`` for the round cap, and ``context_bytes`` for a step discarded over it;
- every step's backend requests are the ones its call sends under the request and
  the registry's card (``list_backend_requests``), so its charge, which the
  validator ties to them, and the remaining budget the gate is re-run with are too;
- the warnings the interpretation and the decisions give
  (``list_interpretation_warnings``, one ``model_plan_rejected`` per model reply the
  gate rejects, naming its re-derived codes, one ``evidence_discarded`` per step a cap
  kept out) are exactly the ones recorded, in order;
- the coverage's source outcomes are ``aggregate_source_outcomes`` over the admitted
  steps' outcomes, the answer and the set's ``affectedness`` capability detail;
- the trajectory's ranking is the one this code applies (``describe_ranking``), and a
  deterministic planner is the policy these decisions come from
  (``describe_deterministic_planner``), so neither can name another configuration.

The audit runs after ``validate_knowledge_evidence_set`` and relies on what that
established: rounds numbered from 1, each step in its round and running the leading
calls of the round's accepted plan, a model reply recorded exactly when the model
replied, with its own hash, one outcome per source for each step that got a
response, byte admissions that follow ``max_context_bytes``, a charge of one tool call
per backend request, every answer item returned by an admitted step, and a well-formed
list of capabilities, whose unavailable ``affectedness`` names a detail.

Limits. The audit trusts the observations a set records: each step's status,
outcomes, answer IDs, bytes and admission, and the answer assembled from them. It
proves the decisions follow from them; replay (``replay_evidence_set``) runs the
controller again against the sources and proves the observations, the decisions taken
on them and the ``unrelated_candidates_dropped`` and ``answer_truncated`` counts,
which come from the responses the set does not carry, are what the sources give
now. The audit proves the set consistent with itself, not that the model sent the
reply it records: whoever reseals the set can rewrite the reply, its hash, the plan
and the steps together, and only an authenticated seal over the whole set could
detect that. The deadline is measured, not decided: a round recording a deadline
outcome (``model_timed_out``, ``model_reply_after_deadline``,
``model_skipped_at_deadline``, or a ``deterministic`` round that records neither a
plan nor a rejection) is read as one the deadline stopped, which the validator ties
to a ``wall_time`` breach. Whether round 1 alone found an answer is
read from the final answer: an item is kept or dropped on its own, never because of
another step, so round 1's items stay in the answer unless the result cap cut them
for higher-tier round-2 items.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field

from cve_kgrag.application.investigation_answer import (
    aggregate_source_outcomes,
    describe_ranking,
    list_decision_warnings,
)
from cve_kgrag.application.investigation_decisions import (
    CAP_BREACH_ADMISSIONS,
    ROUND_CAP_STOP,
    RoundPlan,
    Stop,
    choose_round_plan,
    decide_assessment,
    decide_refinement_stop,
    decide_stop_without_answer,
    plan_deadline_round,
)
from cve_kgrag.application.investigation_policy import (
    PlannedStep,
    describe_deterministic_planner,
    find_interpretation_stop,
    find_resolved_topic,
    interpret_request,
    list_calls,
    plan_first_round,
    plan_refinement,
)
from cve_kgrag.application.investigation_tools import list_backend_requests
from cve_kgrag.application.investigation_warnings import (
    build_evidence_discarded_warning,
    list_interpretation_warnings,
)
from cve_kgrag.domain.budget import BudgetBreach
from cve_kgrag.domain.investigation import (
    DecisionBasis,
    Interpretation,
    InvestigationState,
    InvestigationWarning,
    KnowledgeEvidenceSet,
    PlannerOutcome,
    RoundRecord,
    StateTransition,
    StepAdmission,
    StopReason,
    ToolStep,
    find_affectedness_detail,
    list_answer_sources,
)
from cve_kgrag.domain.investigation_validation import (
    DEADLINE_ADMISSIONS,
    DEADLINE_PLANNER_OUTCOMES,
)
from cve_kgrag.domain.planning import (
    DeterministicPlannerIdentity,
    PlannerKind,
    PlanRejection,
    TopicContextCall,
)
from cve_kgrag.domain.topic import ProtocolTopic
from cve_kgrag.domain.validation import EvidenceValidationError
from cve_kgrag.topics.registry import TopicRegistry


@dataclass
class DerivedPath:
    """The path the controller's decisions give over a recorded run, built as the audit
    walks it, with what the walk found the record contradicting."""

    transitions: list[StateTransition] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    # The planning and retrieval warnings the decisions raise, in the order they arise.
    warnings: list[InvestigationWarning] = field(default_factory=list)
    planned_rounds: int = 0
    stop: Stop | None = None
    breach: BudgetBreach | None = None
    # Set when the record lacks a round the decisions plan, so the walk cannot go on.
    is_abandoned: bool = False

    def move(
        self, from_state: InvestigationState, to_state: InvestigationState, basis: DecisionBasis
    ) -> None:
        self.transitions.append(
            StateTransition(from_state=from_state, to_state=to_state, basis=basis)
        )

    def end(self, from_state: InvestigationState, stop: Stop) -> None:
        _, basis = stop
        self.move(from_state, InvestigationState.VALIDATE, basis)
        self.move(
            InvestigationState.VALIDATE, InvestigationState.RETURN, DecisionBasis.ANSWER_VALIDATED
        )
        self.stop = stop

    def has_ended(self) -> bool:
        return self.stop is not None or self.is_abandoned


def list_steps_before(steps: Sequence[ToolStep], round_number: int) -> list[ToolStep]:
    earlier_steps: list[ToolStep] = []
    for step in steps:
        if step.round_number < round_number:
            earlier_steps.append(step)
    return earlier_steps


def list_round_steps(steps: Sequence[ToolStep], round_number: int) -> list[ToolStep]:
    round_steps: list[ToolStep] = []
    for step in steps:
        if step.round_number == round_number:
            round_steps.append(step)
    return round_steps


def require_round_record(
    evidence_set: KnowledgeEvidenceSet, round_number: int, path: DerivedPath
) -> RoundRecord | None:
    """The record of a round the decisions plan; without one, the walk is abandoned."""
    for round_record in evidence_set.trajectory.rounds:
        if round_record.round_number == round_number:
            return round_record
    path.violations.append(
        f"the controller's decisions plan round {round_number}, but the run records no such round"
    )
    path.is_abandoned = True
    return None


def find_retrieval_breach(
    round_record: RoundRecord, round_steps: Sequence[ToolStep]
) -> BudgetBreach | None:
    """The cap retrieving the round's plan breached: ``wall_time`` when a step ran into the
    deadline or the deadline came before the plan's next call, ``context_bytes`` when a
    step was discarded over the byte cap. A step rejected for invalid evidence also leaves
    calls unrun, but breaches nothing."""
    for step in round_steps:
        if step.admission in DEADLINE_ADMISSIONS:
            return BudgetBreach.WALL_TIME
        if step.admission is StepAdmission.DISCARDED_OVER_CONTEXT_BUDGET:
            return BudgetBreach.CONTEXT_BYTES
    if len(round_steps) == len(round_record.accepted_plan):
        return None
    stopped_on_step = bool(round_steps) and round_steps[-1].admission is not StepAdmission.ADMITTED
    if stopped_on_step:
        return None
    return BudgetBreach.WALL_TIME


def has_round_one_answer(evidence_set: KnowledgeEvidenceSet) -> bool:
    """Whether round 1's admitted steps found an answer item: an implementation candidate
    one of them found, or a threat-context item one of them returned."""
    round_one_step_indices: set[int] = set()
    round_one_answer_ids: set[str] = set()
    for step in evidence_set.trajectory.steps:
        if step.round_number == 1 and step.admission is StepAdmission.ADMITTED:
            round_one_step_indices.add(step.step_index)
            round_one_answer_ids.update(step.answer_ids)
    for investigation_candidate in evidence_set.implementation_candidates:
        if round_one_step_indices.intersection(investigation_candidate.found_by_steps):
            return True
    return any(item.technique_id in round_one_answer_ids for item in evidence_set.protocol_context)


def describe_rejections(rejections: Sequence[PlanRejection]) -> str:
    """Each rejection's code, with the plan position it names; never any planner text."""
    described_rejections: list[str] = []
    for rejection in rejections:
        if rejection.step_position is None:
            described_rejections.append(rejection.code.value)
        else:
            described_rejections.append(f"{rejection.code} at {rejection.step_position}")
    return "[" + ", ".join(described_rejections) + "]"


def find_round_plan_violations(
    round_record: RoundRecord, round_steps: Sequence[ToolStep], round_plan: RoundPlan
) -> list[str]:
    """The round records exactly what the controller's decisions give it: the planner
    outcome, the rejections in order, the accepted plan, and each step's planner and
    reason."""
    violations: list[str] = []
    round_number = round_record.round_number
    if round_record.planner_outcome is not round_plan.planner_outcome:
        violations.append(
            f"round {round_number} is {round_record.planner_outcome}, but the controller's "
            f"decisions over its recorded reply give {round_plan.planner_outcome}"
        )
    if round_record.rejections != round_plan.rejections:
        violations.append(
            f"round {round_number} records the rejections "
            f"{describe_rejections(round_record.rejections)}, but the gate gives "
            f"{describe_rejections(round_plan.rejections)}"
        )
    if round_record.accepted_plan != tuple(list_calls(round_plan.planned_steps)):
        violations.append(
            f"round {round_number} accepts another plan than the controller's decisions choose"
        )
    for step, planned_step in zip(round_steps, round_plan.planned_steps, strict=False):
        if step.planned_by is not round_plan.planned_by:
            violations.append(
                f"step {step.step_index} is planned by {step.planned_by}, but the controller's "
                f"decisions give {round_plan.planned_by}"
            )
        if step.reason is not planned_step.reason:
            violations.append(
                f"step {step.step_index}'s reason is {step.reason}, but the controller's "
                f"decisions give {planned_step.reason}"
            )
    return violations


def is_stopped_before_planning(round_record: RoundRecord) -> bool:
    """Whether the deadline stopped the round before it was planned. The deadline is
    measured, not decided: a ``deterministic`` round that records neither a plan nor a
    rejection is read as one the deadline stopped, which the validator ties to a
    ``wall_time`` breach. The policy's plan is never empty in a deterministic round, so
    no other ``deterministic`` round records neither."""
    if round_record.planner_outcome in DEADLINE_PLANNER_OUTCOMES:
        return True
    is_deterministic = round_record.planner_outcome is PlannerOutcome.DETERMINISTIC
    return is_deterministic and not round_record.accepted_plan and not round_record.rejections


def derive_round(
    path: DerivedPath,
    evidence_set: KnowledgeEvidenceSet,
    round_record: RoundRecord,
    policy_steps: Sequence[PlannedStep],
    from_state: InvestigationState,
    topic: ProtocolTopic | None,
    topic_registry: TopicRegistry,
) -> None:
    """Walk one round: re-derive its plan from the model reply it records, then either end
    the path on the stop the round causes or move on to assess."""
    round_number = round_record.round_number
    path.planned_rounds += 1
    if is_stopped_before_planning(round_record):
        round_plan = plan_deadline_round(round_record.planner_outcome, round_record.model_reply)
    else:
        round_plan = choose_round_plan(
            evidence_set.request,
            evidence_set.interpretation,
            topic,
            list_steps_before(evidence_set.trajectory.steps, round_number),
            round_number,
            policy_steps,
            round_record.model_reply,
            topic_registry,
        )
    round_steps = list_round_steps(evidence_set.trajectory.steps, round_number)
    path.violations.extend(find_round_plan_violations(round_record, round_steps, round_plan))
    path.warnings.extend(round_plan.warnings)
    if round_plan.breach is not None:
        path.breach = round_plan.breach
    if round_plan.stop is not None:
        path.end(from_state, round_plan.stop)
        return
    for step in round_steps:
        if step.admission in CAP_BREACH_ADMISSIONS:
            path.warnings.append(build_evidence_discarded_warning(step.step_index, step.admission))
    path.move(from_state, InvestigationState.RETRIEVE, DecisionBasis.PLAN_ACCEPTED)
    path.move(InvestigationState.RETRIEVE, InvestigationState.ASSESS, DecisionBasis.STEPS_FINISHED)


def derive_decision_path(
    evidence_set: KnowledgeEvidenceSet, topic: ProtocolTopic | None, topic_registry: TopicRegistry
) -> DerivedPath:
    """The controller's walk over the recorded run: each decision recomputed from what
    was observed before it."""
    request = evidence_set.request
    interpretation = evidence_set.interpretation
    steps = evidence_set.trajectory.steps
    path = DerivedPath()
    interpretation_stop = find_interpretation_stop(request, interpretation)
    if interpretation_stop is not None:
        path.end(InvestigationState.INTERPRET, interpretation_stop)
        return path
    path.move(
        InvestigationState.INTERPRET, InvestigationState.PLAN, DecisionBasis.QUERY_INTERPRETED
    )

    round_one = require_round_record(evidence_set, 1, path)
    if round_one is None:
        return path
    derive_round(
        path,
        evidence_set,
        round_one,
        plan_first_round(request, interpretation),
        InvestigationState.PLAN,
        topic,
        topic_registry,
    )
    if path.has_ended():
        return path
    round_one_steps = list_round_steps(steps, 1)
    path.breach = find_retrieval_breach(round_one, round_one_steps)
    stop = decide_assessment(
        request, round_one_steps, path.breach is not None, has_round_one_answer(evidence_set)
    )
    if stop is not None:
        path.end(InvestigationState.ASSESS, stop)
        return path
    path.move(
        InvestigationState.ASSESS, InvestigationState.REFINE, DecisionBasis.NO_ANSWER_REFINABLE
    )

    refinement_steps = plan_refinement(interpretation, round_one_steps)
    consults_model = evidence_set.trajectory.planner.kind is PlannerKind.MODEL
    stop = decide_refinement_stop(request, refinement_steps, consults_model)
    if stop == ROUND_CAP_STOP:
        path.breach = BudgetBreach.ROUNDS
    if stop is not None:
        path.end(InvestigationState.REFINE, stop)
        return path
    round_two = require_round_record(evidence_set, 2, path)
    if round_two is None:
        return path
    derive_round(
        path,
        evidence_set,
        round_two,
        refinement_steps,
        InvestigationState.REFINE,
        topic,
        topic_registry,
    )
    if path.has_ended():
        return path
    path.breach = find_retrieval_breach(round_two, list_round_steps(steps, 2))
    stop = decide_assessment(request, steps, path.breach is not None, evidence_set.has_answer())
    if stop is None:
        stop = decide_stop_without_answer(request, DecisionBasis.NO_ANSWER_AFTER_REFINEMENT)
    path.end(InvestigationState.ASSESS, stop)
    return path


def list_interpretation_differences(
    recorded: Interpretation, interpretation: Interpretation
) -> list[str]:
    """The interpretation fields whose recorded value differs from the re-derived one."""
    differing_fields: list[str] = []
    for field_name in Interpretation.model_fields:
        if getattr(recorded, field_name) != getattr(interpretation, field_name):
            differing_fields.append(field_name)
    return differing_fields


def describe_transition(transition: StateTransition) -> str:
    return f"{transition.from_state} -> {transition.to_state} ({transition.basis})"


def find_transition_violations(
    derived_transitions: Sequence[StateTransition], recorded_transitions: Sequence[StateTransition]
) -> list[str]:
    """The first recorded transition that is not the derived one, if any."""
    for position, (derived, recorded) in enumerate(
        zip(derived_transitions, recorded_transitions, strict=False), start=1
    ):
        if derived != recorded:
            return [
                f"transition {position} is {describe_transition(recorded)}, but the "
                f"controller's decisions give {describe_transition(derived)}"
            ]
    if len(derived_transitions) != len(recorded_transitions):
        return [
            f"the run records {len(recorded_transitions)} transitions, but the controller's "
            f"decisions give {len(derived_transitions)}"
        ]
    return []


def find_issued_request_violations(
    evidence_set: KnowledgeEvidenceSet, topic_registry: TopicRegistry
) -> list[str]:
    """Every step records the backend requests its call sends under the request and the
    registry's card."""
    violations: list[str] = []
    request = evidence_set.request
    for step in evidence_set.trajectory.steps:
        call = step.call
        if isinstance(call, TopicContextCall) and topic_registry.get_topic(call.topic_id) is None:
            violations.append(
                f"step {step.step_index} explores a topic this registry does not hold"
            )
            continue
        if step.backend_requests != list_backend_requests(call, request, topic_registry):
            violations.append(
                f"step {step.step_index} records other backend requests than its call sends "
                "under the request and the registry's card"
            )
    return violations


def list_warning_codes(warnings: Sequence[InvestigationWarning]) -> list[str]:
    warning_codes: list[str] = []
    for warning in warnings:
        warning_codes.append(warning.code.value)
    return warning_codes


def find_warning_violations(
    recorded_warnings: Sequence[InvestigationWarning],
    derived_warnings: Sequence[InvestigationWarning],
) -> list[str]:
    """How the decision warnings the run records differ from those its interpretation and
    decisions give: their codes when those differ, otherwise each warning, counted from 1,
    whose subject differs. No subject is described: a recorded one is text the set's author
    chose, and a derived one can repeat the request's query."""
    recorded_codes = list_warning_codes(recorded_warnings)
    derived_codes = list_warning_codes(derived_warnings)
    if recorded_codes != derived_codes:
        return [
            f"the run records the warnings [{', '.join(recorded_codes)}], but its "
            f"interpretation and decisions give other warnings: [{', '.join(derived_codes)}]"
        ]
    violations: list[str] = []
    for warning_number, recorded_warning in enumerate(recorded_warnings, start=1):
        if recorded_warning.subject != derived_warnings[warning_number - 1].subject:
            violations.append(
                f"the run's decision warning {warning_number} ({recorded_warning.code.value}) "
                "has another subject than its interpretation and decisions give"
            )
    return violations


def find_coverage_violations(evidence_set: KnowledgeEvidenceSet) -> list[str]:
    """The coverage's source outcomes summarize the admitted steps' outcomes and the
    answer; an ``invalid_evidence`` run returns nothing, so no step counts toward them."""
    request = evidence_set.request
    steps = evidence_set.trajectory.steps
    admitted_steps: list[ToolStep] = []
    if evidence_set.stop_reason is not StopReason.INVALID_EVIDENCE:
        for step in steps:
            if step.admission is StepAdmission.ADMITTED:
                admitted_steps.append(step)
    source_outcomes = aggregate_source_outcomes(
        list_answer_sources(request.scope, request.filters),
        admitted_steps,
        evidence_set.implementation_candidates,
        evidence_set.protocol_context,
        ran_any_step=bool(steps),
        affectedness_detail=find_affectedness_detail(evidence_set.source_capabilities),
    )
    if evidence_set.coverage.source_outcomes != source_outcomes:
        return ["coverage.source_outcomes do not summarize the admitted steps' outcomes"]
    return []


def find_configuration_violations(evidence_set: KnowledgeEvidenceSet) -> list[str]:
    """The trajectory names the ranking this code applies and, for a deterministic
    planner, the policy version whose decisions the audit re-derives. A model planner
    names no policy version (``ModelPlannerIdentity`` has no such field), and the
    validator's ``model_planner`` capability check binds its model to the deployment's."""
    trajectory = evidence_set.trajectory
    violations: list[str] = []
    if trajectory.ranking != describe_ranking():
        violations.append("the trajectory's ranking is not the one this code applies")
    planner = trajectory.planner
    deterministic_planner = describe_deterministic_planner()
    if isinstance(planner, DeterministicPlannerIdentity) and planner != deterministic_planner:
        violations.append(
            f"the planner names a policy other than {deterministic_planner.policy_version}, "
            "the one whose decisions the audit re-derives"
        )
    return violations


def find_decision_path_violations(
    evidence_set: KnowledgeEvidenceSet, topic_registry: TopicRegistry
) -> list[str]:
    violations = find_configuration_violations(evidence_set)
    interpretation = interpret_request(evidence_set.request, topic_registry)
    differing_fields = list_interpretation_differences(evidence_set.interpretation, interpretation)
    if differing_fields:
        # Every later decision derives from the interpretation, so none can be checked.
        for field_name in differing_fields:
            violations.append(
                f"interpretation.{field_name} is not the one the request gives under this "
                "topic registry"
            )
        return violations
    topic = find_resolved_topic(interpretation, topic_registry)
    violations.extend(find_issued_request_violations(evidence_set, topic_registry))
    violations.extend(find_coverage_violations(evidence_set))
    path = derive_decision_path(evidence_set, topic, topic_registry)
    violations.extend(path.violations)
    if path.is_abandoned or path.stop is None:
        return violations
    trajectory = evidence_set.trajectory
    violations.extend(find_transition_violations(path.transitions, trajectory.transitions))
    stop_reason, _ = path.stop
    if stop_reason is not evidence_set.stop_reason:
        violations.append(
            f"the run stops {evidence_set.stop_reason}, but the controller's decisions give "
            f"{stop_reason}"
        )
    if path.planned_rounds != len(trajectory.rounds):
        violations.append(
            f"the run records {len(trajectory.rounds)} rounds, but the controller's decisions "
            f"plan {path.planned_rounds}"
        )
    if trajectory.budget_used.breach is not path.breach:
        violations.append(
            f"the run names the breach {trajectory.budget_used.breach}, but the controller's "
            f"decisions breach {path.breach}"
        )
    derived_warnings = list_interpretation_warnings(
        evidence_set.request, interpretation, topic, ran_any_step=bool(trajectory.steps)
    )
    derived_warnings.extend(path.warnings)
    # The answer's own warnings follow from the responses, which only replay sees.
    recorded_warnings = list_decision_warnings(evidence_set.warnings)
    violations.extend(find_warning_violations(recorded_warnings, derived_warnings))
    return violations


def audit_decision_path(evidence_set: KnowledgeEvidenceSet, topic_registry: TopicRegistry) -> None:
    """Raise ``EvidenceValidationError`` if the set records a decision the controller would
    not have made: run it after ``validate_knowledge_evidence_set``, on any set the
    service seals or is handed back."""
    violations = find_decision_path_violations(evidence_set, topic_registry)
    if violations:
        raise EvidenceValidationError(violations)
