"""Bounded investigation: one explicit state machine over the allowlisted tools.

``interpret -> plan -> retrieve -> assess -> (refine -> retrieve -> assess) -> validate
-> return``. Round 1 always runs its plan; what it observes (unknown IDs, a literal
miss, a failed source, a breached cap, an answer) decides whether one refinement
round runs and what it calls. There is no loop over rounds, every call is charged
before it runs against caps of at most eight backend queries, and the deadline is
checked before every planner and tool call, so every path ends at
``validate -> return``. Every planner and tool call runs under the call runner, which
gives control back at the deadline even when the call has not returned, and no other
adapter method runs during a request: the planner's identity is built by discovery
before the service is. So a blocking adapter cannot hold the run past its wall-time cap.

An optional model planner only proposes a ``QueryPlan``. Its reply passes the same
gate as the deterministic plan; a rejected or failed reply falls back to the
deterministic plan, and the planner never sees source text or writes a fact. The
round records the reply as the port returned it, so the decision-path audit parses
and gates it again; the reply is never logged or quoted in a warning.
"""

from collections.abc import Callable, Sequence
from functools import partial
from typing import Literal

from cve_kgrag.application.budget_ledger import BudgetLedger
from cve_kgrag.application.deadline_checkpoint import DeadlineCheckpoint, DeadlineMoment
from cve_kgrag.application.decision_path_audit import audit_decision_path
from cve_kgrag.application.investigation_answer import (
    assemble_answer,
    assemble_returned_answer,
    describe_ranking,
    list_admitted_executions,
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
from cve_kgrag.application.investigation_deployment import InvestigationDeployment
from cve_kgrag.application.investigation_policy import (
    CVE_TOOL_COST,
    PlannedStep,
    count_tool_calls,
    find_interpretation_stop,
    find_resolved_topic,
    interpret_request,
    list_allowed_terms,
    list_calls,
    plan_first_round,
    plan_refinement,
)
from cve_kgrag.application.investigation_run import InvestigationRun
from cve_kgrag.application.investigation_tools import (
    ABANDONED_CALL_EXECUTION,
    build_tool_step,
    issue_step,
)
from cve_kgrag.application.investigation_warnings import (
    build_evidence_discarded_warning,
    list_interpretation_warnings,
)
from cve_kgrag.application.planner_setup import (
    ModelPlanning,
    PlannerSetup,
    describe_setup_capability,
    describe_setup_planner,
)
from cve_kgrag.application.threaded_call_runner import CallTimedOut
from cve_kgrag.domain.budget import PLANNER_SHARE_OF_WALL_TIME, BudgetBreach
from cve_kgrag.domain.hashing import UNSEALED_SHA256
from cve_kgrag.domain.investigation import (
    DecisionBasis,
    InvestigationRequest,
    InvestigationState,
    KnowledgeEvidenceSet,
    PlannerOutcome,
    RoundRecord,
    RunTimings,
    SourceCapability,
    StepAdmission,
    StepTiming,
    StopReason,
    ToolStep,
    Trajectory,
    derive_investigation_id,
    find_affectedness_detail,
)
from cve_kgrag.domain.investigation_validation import validate_knowledge_evidence_set
from cve_kgrag.domain.planning import (
    ModelReply,
    ModelReplyFailureDetail,
    PlanningInput,
    StepObservation,
    ToolCall,
    ToolCost,
    ToolName,
    TopicContextCall,
    compute_model_reply_sha256,
    list_tool_name_sources,
)
from cve_kgrag.domain.taxonomy import BackendStatus
from cve_kgrag.domain.topic_context import QueryScope
from cve_kgrag.ports.planning import ModelPort
from cve_kgrag.topics.registry import TopicRegistry

RoundNumber = Literal[1, 2]
# The reply a round records for a planner still running when its share of the run ended.
PLANNER_CAP_REPLY = ModelReply(
    status=BackendStatus.UNAVAILABLE, detail=ModelReplyFailureDetail.TIMED_OUT
)


def to_milliseconds(seconds: float) -> int:
    return round(seconds * 1000)


def read_planner_seconds_left(ledger: BudgetLedger, planner_cap_ends_at: float) -> float:
    """The seconds a planner call has left: the run's, and never past its share of the run
    (``PLANNER_SHARE_OF_WALL_TIME``), which ends at ``planner_cap_ends_at`` on the run's
    clock."""
    return min(ledger.remaining_seconds(), planner_cap_ends_at - ledger.elapsed_seconds())


def list_required_tools(
    round_number: RoundNumber, policy_steps: Sequence[PlannedStep]
) -> tuple[ToolName, ...]:
    """The tools of the policy's round-1 plan, in plan order and once each: a round-1 model
    plan that includes them consults every source the gate requires of it (its baseline).
    Round 2 has no baseline, so none."""
    if round_number != 1:
        return ()
    required_tools: list[ToolName] = []
    for policy_step in policy_steps:
        if policy_step.call.tool not in required_tools:
            required_tools.append(policy_step.call.tool)
    return tuple(required_tools)


def observe_step(step: ToolStep) -> StepObservation:
    """What a planner is shown of an executed step: its tool, status, answer count and
    warning codes, never source text."""
    warning_codes: list[str] = []
    for search_warning in step.search_warnings:
        warning_codes.append(search_warning.code.value)
    for topic_warning in step.topic_warnings:
        warning_codes.append(topic_warning.code.value)
    return StepObservation(
        step_index=step.step_index,
        tool=step.call.tool,
        status=step.status,
        answer_count=len(step.answer_ids),
        warning_codes=tuple(warning_codes),
    )


def build_planning_input(
    run: InvestigationRun,
    round_number: RoundNumber,
    topic_registry: TopicRegistry,
    required_tools: tuple[ToolName, ...],
) -> PlanningInput:
    """What a planner sees: the quoted query, codes, counts, the vocabulary, the tools the
    budgets allow and those a round-1 plan includes, never source records."""
    interpretation = run.interpretation
    scope = run.request.scope
    tool_costs: list[ToolCost] = []
    if scope is not QueryScope.PROTOCOL_CONTEXT_ONLY:
        if interpretation.cve_ids:
            tool_costs.append(
                ToolCost(tool=ToolName.CVE_EXACT_LOOKUP, charged_tool_calls=CVE_TOOL_COST)
            )
        tool_costs.append(ToolCost(tool=ToolName.CVE_SEARCH, charged_tool_calls=CVE_TOOL_COST))
    topic_match = (
        interpretation.resolution.matches[0] if interpretation.resolution.matches else None
    )
    if topic_match is not None:
        topic_call = TopicContextCall(tool=ToolName.TOPIC_CONTEXT, topic_id=topic_match.topic_id)
        tool_costs.append(
            ToolCost(
                tool=ToolName.TOPIC_CONTEXT,
                charged_tool_calls=count_tool_calls(topic_call, scope, topic_registry),
            )
        )
    # A tool that alone would consult more sources than the run may is never offered.
    budget = run.request.budget
    affordable_costs: list[ToolCost] = []
    allowed_tools: list[ToolName] = []
    for tool_cost in tool_costs:
        consulted_sources = set(run.ledger.sources_used)
        consulted_sources.update(list_tool_name_sources(tool_cost.tool, scope))
        if len(consulted_sources) <= budget.max_sources:
            affordable_costs.append(tool_cost)
            allowed_tools.append(tool_cost.tool)
    issued_calls: list[ToolCall] = []
    observations: list[StepObservation] = []
    for step in run.steps:
        issued_calls.append(step.call)
        observations.append(observe_step(step))
    # A required tool the budget leaves no room for is not asked for: no plan could hold it.
    affordable_required_tools: list[ToolName] = []
    for required_tool in required_tools:
        if required_tool in allowed_tools:
            affordable_required_tools.append(required_tool)
    return PlanningInput(
        round_number=round_number,
        quoted_query=run.request.query,
        scope=scope,
        intent=interpretation.intent,
        cve_ids=interpretation.cve_ids,
        topic_id=topic_match.topic_id if topic_match else None,
        topic_version=topic_match.topic_version if topic_match else None,
        review_status=topic_match.review_status if topic_match else None,
        allowed_tools=tuple(allowed_tools),
        required_tools=tuple(affordable_required_tools),
        allowed_terms=tuple(sorted(list_allowed_terms(interpretation, run.topic))),
        tool_costs=tuple(affordable_costs),
        remaining_tool_calls=run.ledger.remaining_tool_calls(),
        remaining_sources=max(0, budget.max_sources - len(run.ledger.sources_used)),
        issued_calls=tuple(issued_calls),
        observations=tuple(observations),
    )


def describe_service_capabilities(
    deployment: InvestigationDeployment, planner_setup: PlannerSetup
) -> tuple[SourceCapability, ...]:
    """What a service running ``planner_setup`` over ``deployment`` serves: the deployment's
    capabilities, then the ``model_planner`` capability describing ``planner_setup``. Every
    set the service seals reports exactly these."""
    return (*deployment.source_capabilities, describe_setup_capability(planner_setup))


class InvestigationService:
    """Bounded investigation: interpret, round 1, at most one refinement round, validate.

    There is no loop over rounds; every path ends in validate -> return. Its planning
    and stop decisions are the pure functions of ``investigation_decisions``. Raises
    ``EvidenceValidationError`` rather than return a set that breaks an invariant
    (``validate_knowledge_evidence_set``) or records a decision the audit does not
    re-derive (``audit_decision_path``): a violation is a controller defect, never a
    result.

    ``planner_setup`` is the planner: a model's port with the identity discovery built for
    it, which every trajectory records, or the deterministic policy. A request only calls
    the model port's ``propose_plan``, and only under the deployment's call runner. Every
    set reports the deployment's ``source_capabilities`` followed by the ``model_planner``
    capability describing ``planner_setup`` (``describe_service_capabilities``), and final
    validation requires exactly those. A required affectedness source is reported
    unavailable with the deployment's ``affectedness`` capability detail.

    ``reach_checkpoint`` is told each point where the run checks the deadline, just before
    it reads the clock there (``deadline_checkpoint``): ``ignore_checkpoint`` for a
    measured run, or a replay clock that puts a recorded deadline back where it fell.
    """

    def __init__(
        self,
        deployment: InvestigationDeployment,
        planner_setup: PlannerSetup,
        reach_checkpoint: Callable[[DeadlineCheckpoint], None],
    ) -> None:
        self._topic_registry = deployment.topic_registry
        self._tool_executor = deployment.tool_executor
        self._source_capabilities = describe_service_capabilities(deployment, planner_setup)
        self._affectedness_detail = find_affectedness_detail(deployment.source_capabilities)
        self._pinned_fight_snapshot = deployment.pinned_fight_snapshot
        self._evidence_catalog = deployment.evidence_catalog
        self._call_runner = deployment.call_runner
        self._wall_clock = deployment.wall_clock
        self._monotonic_clock = deployment.monotonic_clock
        self._planner_identity = describe_setup_planner(planner_setup)
        self._model_port: ModelPort | None = None
        if isinstance(planner_setup, ModelPlanning):
            self._model_port = planner_setup.model_port
        self._reach_checkpoint = reach_checkpoint

    def describe_capabilities(self) -> tuple[SourceCapability, ...]:
        """What this service serves (``describe_service_capabilities``)."""
        return self._source_capabilities

    def investigate(self, request: InvestigationRequest) -> KnowledgeEvidenceSet:
        interpretation = interpret_request(request, self._topic_registry)
        run = InvestigationRun(
            request=request,
            interpretation=interpretation,
            topic=find_resolved_topic(interpretation, self._topic_registry),
            ledger=BudgetLedger(request.budget, self._monotonic_clock, self._monotonic_clock()),
            started_at=self._wall_clock(),
        )
        stop_reason, basis = self._decide_stop(run)
        run.move(InvestigationState.VALIDATE, basis)
        return self._seal(run, stop_reason, basis)

    def _decide_stop(self, run: InvestigationRun) -> Stop:
        interpretation_stop = find_interpretation_stop(run.request, run.interpretation)
        if interpretation_stop is not None:
            return interpretation_stop
        run.move(InvestigationState.PLAN, DecisionBasis.QUERY_INTERPRETED)
        stop = self._run_round(run, 1, plan_first_round(run.request, run.interpretation))
        if stop is not None:
            return stop
        stop = self._assess(run)
        if stop is not None:
            return stop
        run.move(InvestigationState.REFINE, DecisionBasis.NO_ANSWER_REFINABLE)
        stop = self._refine(run)
        if stop is not None:
            return stop
        stop = self._assess(run)
        if stop is not None:
            return stop
        return decide_stop_without_answer(run.request, DecisionBasis.NO_ANSWER_AFTER_REFINEMENT)

    def _run_round(
        self,
        run: InvestigationRun,
        round_number: RoundNumber,
        policy_steps: list[PlannedStep],
    ) -> Stop | None:
        """Plan and retrieve one round; a stop when the round could not run its plan."""
        run.ledger.rounds_used += 1
        round_plan = self._plan_round(run, round_number, policy_steps)
        if round_plan.breach is not None:
            run.ledger.record_breach(round_plan.breach)
        run.warnings.extend(round_plan.warnings)
        executed_step_indices: list[int] = []
        if round_plan.stop is None:
            run.move(InvestigationState.RETRIEVE, DecisionBasis.PLAN_ACCEPTED)
            executed_step_indices = self._retrieve(run, round_number, round_plan)
            run.move(InvestigationState.ASSESS, DecisionBasis.STEPS_FINISHED)
        model_reply_sha256: str | None = None
        if round_plan.model_reply is not None:
            model_reply_sha256 = compute_model_reply_sha256(round_plan.model_reply)
        run.rounds.append(
            RoundRecord(
                round_number=round_number,
                planner_outcome=round_plan.planner_outcome,
                rejections=round_plan.rejections,
                model_reply=round_plan.model_reply,
                model_reply_sha256=model_reply_sha256,
                accepted_plan=tuple(list_calls(round_plan.planned_steps)),
                executed_step_indices=tuple(executed_step_indices),
            )
        )
        return round_plan.stop

    def _plan_round(
        self,
        run: InvestigationRun,
        round_number: RoundNumber,
        policy_steps: list[PlannedStep],
    ) -> RoundPlan:
        """The model's plan when it passes the gate, else the gated policy plan
        (``choose_round_plan``).

        Past the deadline no plan is chosen: neither the planner nor any step may start, and
        a configured model planner is recorded as not consulted (``model_skipped_at_deadline``).
        A planner that has not replied by the deadline is abandoned (``model_timed_out``); a
        reply that lands at or after it is recorded but never read
        (``model_reply_after_deadline``). A planner call gets at most its share of the run's
        wall time (``PLANNER_SHARE_OF_WALL_TIME``); one still running when that share ends,
        or one whose reply lands at or after it, with the run in time, is recorded as
        ``PLANNER_CAP_REPLY``, a failed reply, so the round falls back to the policy
        (``model_unavailable``) and replay, answering from the record, takes the same path.
        """
        ledger = run.ledger
        self._reach_checkpoint(DeadlineCheckpoint(round_number, None, DeadlineMoment.BEFORE_START))
        if ledger.is_out_of_time():
            if self._model_port is None:
                return plan_deadline_round(PlannerOutcome.DETERMINISTIC, None)
            return plan_deadline_round(PlannerOutcome.MODEL_SKIPPED_AT_DEADLINE, None)
        model_reply: ModelReply | None = None
        if self._model_port is not None:
            planning_input = build_planning_input(
                run,
                round_number,
                self._topic_registry,
                list_required_tools(round_number, policy_steps),
            )
            started_seconds = ledger.elapsed_seconds()
            planner_cap_ends_at = started_seconds + (
                run.request.budget.max_wall_time_seconds * PLANNER_SHARE_OF_WALL_TIME
            )
            planner_seconds_left = partial(read_planner_seconds_left, ledger, planner_cap_ends_at)
            self._reach_checkpoint(
                DeadlineCheckpoint(round_number, None, DeadlineMoment.DURING_CALL)
            )
            planner_call_outcome = self._call_runner.run(
                partial(
                    self._model_port.propose_plan,
                    planning_input,
                    timeout_seconds=planner_seconds_left(),
                ),
                planner_seconds_left,
            )
            # A call that outlived its share of the run, with the run still in time, is a
            # planner that timed out: the round falls back, as it does for any failed reply.
            if isinstance(planner_call_outcome, CallTimedOut) and not ledger.is_out_of_time():
                planner_call_outcome = PLANNER_CAP_REPLY
            if not isinstance(planner_call_outcome, CallTimedOut):
                self._reach_checkpoint(
                    DeadlineCheckpoint(round_number, None, DeadlineMoment.AT_FINISH)
                )
            finished_seconds = ledger.elapsed_seconds()
            ledger.planner_calls += 1
            run.planner_durations_ms.append(
                to_milliseconds(finished_seconds) - to_milliseconds(started_seconds)
            )
            if isinstance(planner_call_outcome, CallTimedOut):
                return plan_deadline_round(PlannerOutcome.MODEL_TIMED_OUT, None)
            if ledger.is_past_deadline(finished_seconds):
                return plan_deadline_round(
                    PlannerOutcome.MODEL_REPLY_AFTER_DEADLINE, planner_call_outcome
                )
            # A reply that lands at or after the end of the planner's share, with the run in
            # time, is not read either: the share bounds the call, not only its waiting.
            if finished_seconds >= planner_cap_ends_at:
                planner_call_outcome = PLANNER_CAP_REPLY
            model_reply = planner_call_outcome
        return choose_round_plan(
            run.request,
            run.interpretation,
            run.topic,
            run.steps,
            round_number,
            policy_steps,
            model_reply,
            self._topic_registry,
        )

    def _retrieve(
        self, run: InvestigationRun, round_number: RoundNumber, round_plan: RoundPlan
    ) -> list[int]:
        """Run the plan's steps in order; the first failed, late, timed-out or oversized result
        stops it."""
        request = run.request
        ledger = run.ledger
        executed_step_indices: list[int] = []
        for planned_step in round_plan.planned_steps:
            step_index = len(run.steps) + 1
            self._reach_checkpoint(
                DeadlineCheckpoint(round_number, step_index, DeadlineMoment.BEFORE_START)
            )
            if ledger.is_out_of_time():
                ledger.record_breach(BudgetBreach.WALL_TIME)
                break
            call = planned_step.call
            issued_step = issue_step(
                step_index,
                round_number,
                call,
                planned_step.reason,
                round_plan.planned_by,
                request,
                self._topic_registry,
            )
            ledger.charge(issued_step.charged_tool_calls, issued_step.sources)
            started_seconds = ledger.elapsed_seconds()
            self._reach_checkpoint(
                DeadlineCheckpoint(round_number, step_index, DeadlineMoment.DURING_CALL)
            )
            call_outcome = self._call_runner.run(
                partial(self._tool_executor.execute, call, request), ledger.remaining_seconds
            )
            if not isinstance(call_outcome, CallTimedOut):
                self._reach_checkpoint(
                    DeadlineCheckpoint(round_number, step_index, DeadlineMoment.AT_FINISH)
                )
            finished_seconds = ledger.elapsed_seconds()
            if isinstance(call_outcome, CallTimedOut):
                ledger.record_breach(BudgetBreach.WALL_TIME)
                execution = ABANDONED_CALL_EXECUTION
                admission = StepAdmission.TIMED_OUT
            elif call_outcome.integrity_violations:
                execution = call_outcome
                admission = StepAdmission.REJECTED_INVALID_EVIDENCE
            else:
                execution = call_outcome
                admission = ledger.decide_admission(execution.context_bytes, finished_seconds)
            run.steps.append(build_tool_step(issued_step, admission, execution))
            run.executions.append(execution)
            started_offset_ms = to_milliseconds(started_seconds)
            run.step_timings.append(
                StepTiming(
                    step_index=issued_step.step_index,
                    started_offset_ms=started_offset_ms,
                    duration_ms=to_milliseconds(finished_seconds) - started_offset_ms,
                )
            )
            executed_step_indices.append(issued_step.step_index)
            if admission in CAP_BREACH_ADMISSIONS:
                run.warnings.append(
                    build_evidence_discarded_warning(issued_step.step_index, admission)
                )
            if admission is not StepAdmission.ADMITTED:
                break
        return executed_step_indices

    def _assess(self, run: InvestigationRun) -> Stop | None:
        """The stop the observations so far justify, or ``None`` when nothing answered yet."""
        answer = assemble_answer(
            run.request.scope,
            run.topic,
            list_admitted_executions(run.steps, run.executions),
            run.request.budget.max_results_per_call,
        )
        return decide_assessment(
            run.request, run.steps, run.ledger.breach is not None, answer.has_answer()
        )

    def _refine(self, run: InvestigationRun) -> Stop | None:
        """Run the refinement round; ``None`` once it ran and needs assessing."""
        refinement_steps = plan_refinement(run.interpretation, run.list_round_steps(1))
        stop = decide_refinement_stop(run.request, refinement_steps, self._model_port is not None)
        if stop == ROUND_CAP_STOP:
            run.ledger.record_breach(BudgetBreach.ROUNDS)
        if stop is not None:
            return stop
        return self._run_round(run, 2, refinement_steps)

    def _seal(
        self, run: InvestigationRun, stop_reason: StopReason, basis: DecisionBasis
    ) -> KnowledgeEvidenceSet:
        request = run.request
        returned_answer = assemble_returned_answer(
            request,
            run.topic,
            run.steps,
            run.executions,
            stop_reason,
            basis,
            self._affectedness_detail,
        )
        answer = returned_answer.answer
        warnings = list_interpretation_warnings(
            request, run.interpretation, run.topic, ran_any_step=bool(run.steps)
        )
        warnings.extend(run.warnings)
        warnings.extend(returned_answer.warnings)

        evidence_ids: list[str] = []
        for anchor in answer.evidence:
            evidence_ids.append(anchor.evidence_id)
        run.move(InvestigationState.RETURN, DecisionBasis.ANSWER_VALIDATED)
        trajectory = Trajectory(
            planner=self._planner_identity,
            ranking=describe_ranking(),
            transitions=tuple(run.transitions),
            rounds=tuple(run.rounds),
            steps=tuple(run.steps),
            budget_used=run.ledger.summarize_usage(),
            evidence_ids=tuple(evidence_ids),
        )
        evidence_set_draft = KnowledgeEvidenceSet(
            investigation_id=derive_investigation_id(request),
            request=request,
            normalized_query=run.interpretation.normalized_query,
            requested_scope=request.scope,
            applied_scope=request.scope,
            interpretation=run.interpretation,
            status=returned_answer.status,
            stop_reason=stop_reason,
            implementation_candidates=answer.implementation_candidates,
            excluded_implementation_candidates=answer.excluded_candidates,
            protocol_context=answer.protocol_context,
            product_applicability=returned_answer.product_applicability,
            claims=returned_answer.claims,
            evidence=answer.evidence,
            coverage=returned_answer.coverage,
            warnings=tuple(warnings),
            source_capabilities=self._source_capabilities,
            trajectory=trajectory,
            timings=RunTimings(
                started_at=run.started_at,
                wall_time_ms=to_milliseconds(run.ledger.elapsed_seconds()),
                planner_durations_ms=tuple(run.planner_durations_ms),
                steps=tuple(run.step_timings),
            ),
            result_sha256=UNSEALED_SHA256,
        )
        evidence_set = evidence_set_draft.model_copy(
            update={"result_sha256": evidence_set_draft.compute_result_sha256()}
        )
        validate_knowledge_evidence_set(
            evidence_set,
            self._pinned_fight_snapshot,
            self._evidence_catalog,
            self._source_capabilities,
        )
        audit_decision_path(evidence_set, self._topic_registry)
        return evidence_set
