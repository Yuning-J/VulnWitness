"""Replay of a sealed knowledge evidence set: run the controller again for the recorded
request against the deployment, with the run's recorded external inputs put back, and
name every part of the recorded set that differs from the set the controller seals now.

The validator proves a set consistent with itself and with the deployment's catalog,
and the decision-path audit proves its decisions follow from the observations it
records. Neither sees a tool response, so a holder who rewrites a step's summary and
everything built from it, keeping the real response hash, passes both. Replay binds the
whole set to the responses by producing it again with ``InvestigationService``, the
controller itself, so there is one implementation of planning, admission, assessment,
refinement, stop, breach, answer assembly, coverage and warnings, and replay cannot
drift from it. The replayed run plans from the replayed observations: when a source now
answers differently, the stop, rounds and transitions follow what it answers now, not
what the record says happened next.

A run has two external inputs besides its sources, and replay puts both back:

- the model's replies: a model-planned set is re-planned through ``RecordedModelPort``,
  which answers each round with the reply that round records, so the controller parses
  and gates exactly the recorded replies again; a round the record holds no reply for
  is answered as a planner that gave no valid reply, so its round differs;
- the deadline, which is measured, never decided: ``ReplayClock`` moves the clock past
  the deadline at the checkpoint where the recorded run found it
  (``find_deadline_checkpoint``), so the controller's own checks reproduce a skipped,
  timed-out or late planner, a step that never started, a timed-out call or a late
  result there, and nowhere else.

Prefix replay executes each tool against the deployment's complete source responses,
before the controller applies context admission. It recomputes the original digest,
exact counts, canonical admitted charge and next-result increment. The compact witness
in the evidence set never supplies or replaces a source response.

The replay is itself bounded by the recorded request's ``max_wall_time_seconds``,
measured on the deployment's monotonic clock: every tool call runs under the
deployment's call runner, which gives control back when that time is up. A replay that
runs into that deadline before the recorded one compared nothing and reports
``ReplayTimedOut``, never an empty list of differences.
"""

from collections.abc import Sequence
from dataclasses import dataclass, replace

from cve_kgrag.application.deadline_checkpoint import find_deadline_checkpoint
from cve_kgrag.application.investigate import InvestigationService
from cve_kgrag.application.investigation_deployment import InvestigationDeployment
from cve_kgrag.application.planner_setup import DeterministicPlanning, ModelPlanning, PlannerSetup
from cve_kgrag.application.recorded_model_port import RecordedModelPort
from cve_kgrag.application.replay_clock import ReplayClock
from cve_kgrag.domain.budget import BudgetBreach
from cve_kgrag.domain.contract_model import ContractModel
from cve_kgrag.domain.investigation import (
    KnowledgeEvidenceSet,
    ToolStep,
    find_planner_unavailable_detail,
)
from cve_kgrag.domain.planning import ModelPlannerIdentity

# The step part named when a step exists in only one of the two trajectories.
WHOLE_STEP_PART = "step"
# Set fields not compared whole: ``timings`` is measured, ``result_sha256`` hashes every
# compared part, and ``coverage`` and ``trajectory`` are compared part by part.
SET_FIELDS_NOT_COMPARED_WHOLE = frozenset({"timings", "result_sha256", "coverage", "trajectory"})
# Trajectory fields compared part by part: each step's fields, and each budget figure.
TRAJECTORY_FIELDS_NOT_COMPARED_WHOLE = frozenset({"steps", "budget_used"})


@dataclass(frozen=True)
class ReplayDifference:
    """A recorded part that differs from the one the replayed run gives: the field ``part``
    of step ``step_index`` (``step`` when the step exists in only one of the two runs), or,
    when ``step_index`` is ``None``, the set-level ``part`` (a dotted path such as
    ``coverage.source_outcomes``). It never carries a response's or reply's text."""

    step_index: int | None
    part: str


@dataclass(frozen=True)
class ReplayCompleted:
    """The replay ran to its end: ``differences`` names every recorded part the replayed run
    gives differently, steps first, and is empty when the two sets agree in everything
    but their timings."""

    differences: tuple[ReplayDifference, ...]


@dataclass(frozen=True)
class ReplayTimedOut:
    """The replay ran into its own wall-time deadline before the point where the recorded
    run found one, so its set is incomplete and nothing was compared."""


ReplayOutcome = ReplayCompleted | ReplayTimedOut


def find_field_differences(
    part_prefix: str,
    recorded_part: ContractModel,
    replayed_part: ContractModel,
    skipped_fields: frozenset[str],
) -> list[ReplayDifference]:
    """Every field of a set-level part, except ``skipped_fields``, whose recorded value is
    not the replayed one, named ``part_prefix`` plus the field."""
    differences: list[ReplayDifference] = []
    for field_name in type(recorded_part).model_fields:
        if field_name in skipped_fields:
            continue
        if getattr(recorded_part, field_name) != getattr(replayed_part, field_name):
            differences.append(ReplayDifference(None, part_prefix + field_name))
    return differences


def find_step_differences(
    recorded_steps: Sequence[ToolStep], replayed_steps: Sequence[ToolStep]
) -> list[ReplayDifference]:
    """Every field of every step whose recorded value is not the replayed one, and every
    step only one of the two runs issued."""
    differences: list[ReplayDifference] = []
    for step_position in range(max(len(recorded_steps), len(replayed_steps))):
        step_index = step_position + 1
        if step_position >= len(recorded_steps) or step_position >= len(replayed_steps):
            differences.append(ReplayDifference(step_index, WHOLE_STEP_PART))
            continue
        recorded_step = recorded_steps[step_position]
        replayed_step = replayed_steps[step_position]
        for field_name in ToolStep.model_fields:
            if getattr(recorded_step, field_name) != getattr(replayed_step, field_name):
                differences.append(ReplayDifference(step_index, field_name))
    return differences


def find_set_differences(
    recorded_set: KnowledgeEvidenceSet, replayed_set: KnowledgeEvidenceSet
) -> list[ReplayDifference]:
    """Every part of ``recorded_set`` that differs from ``replayed_set``: its steps, then its
    set-level fields, trajectory fields, budget figures and coverage, never its timings."""
    recorded_trajectory = recorded_set.trajectory
    replayed_trajectory = replayed_set.trajectory
    differences = find_step_differences(recorded_trajectory.steps, replayed_trajectory.steps)
    differences.extend(
        find_field_differences("", recorded_set, replayed_set, SET_FIELDS_NOT_COMPARED_WHOLE)
    )
    differences.extend(
        find_field_differences(
            "trajectory.",
            recorded_trajectory,
            replayed_trajectory,
            TRAJECTORY_FIELDS_NOT_COMPARED_WHOLE,
        )
    )
    differences.extend(
        find_field_differences(
            "trajectory.budget_used.",
            recorded_trajectory.budget_used,
            replayed_trajectory.budget_used,
            frozenset(),
        )
    )
    differences.extend(
        find_field_differences(
            "coverage.", recorded_set.coverage, replayed_set.coverage, frozenset()
        )
    )
    return differences


def replay_evidence_set(
    evidence_set: KnowledgeEvidenceSet, deployment: InvestigationDeployment
) -> ReplayOutcome:
    """Run the controller again for ``evidence_set``'s request against ``deployment``, with
    the recorded model replies and deadline point put back, and compare the two sets.

    ``deployment`` is the one the set is checked against: its sources, catalog, FiGHT pin,
    capabilities, call runner and clocks, as the composition root wires them. The replay
    plans with the recorded planner, so the service it runs describes that planner in its
    ``model_planner`` capability, with the recorded reason a configured model planner could
    not plan; every other capability is the deployment's.

    Run it after ``validate_knowledge_evidence_set`` and ``audit_decision_path`` have
    accepted the set; it relies on them. Raises ``EvidenceValidationError`` when the
    replayed set fails the checks the controller runs at seal, as the controller does.
    """
    request = evidence_set.request
    planner = evidence_set.trajectory.planner
    replay_clock = ReplayClock(
        deployment.monotonic_clock,
        request.budget.max_wall_time_seconds,
        find_deadline_checkpoint(evidence_set),
    )
    planner_setup: PlannerSetup
    if isinstance(planner, ModelPlannerIdentity):
        planner_setup = ModelPlanning(planner, RecordedModelPort(evidence_set.trajectory.rounds))
    else:
        planner_setup = DeterministicPlanning(
            find_planner_unavailable_detail(evidence_set.source_capabilities)
        )
    replay_deployment = replace(deployment, monotonic_clock=replay_clock.read)
    service = InvestigationService(replay_deployment, planner_setup, replay_clock.reach)
    replayed_set = service.investigate(request)
    has_found_deadline = replayed_set.trajectory.budget_used.breach is BudgetBreach.WALL_TIME
    if has_found_deadline and not replay_clock.has_reached_recorded_deadline:
        return ReplayTimedOut()
    return ReplayCompleted(tuple(find_set_differences(evidence_set, replayed_set)))
