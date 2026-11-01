"""The points where the controller checks the wall-time deadline.

Running into the deadline is measured, never decided: whether a planner or tool call
finished in time depends on the clock, not on anything a set records. The controller
announces each point to its injected ``reach_checkpoint`` just before it reads the
clock there. A measured run ignores the announcement (``ignore_checkpoint``); a replay
moves its clock past the deadline at the point where the recorded run found it
(``find_deadline_checkpoint``), so the controller's own checks reproduce the recorded
deadline outcome.
"""

from dataclasses import dataclass
from enum import StrEnum

from vulnwitness.domain.budget import BudgetBreach
from vulnwitness.domain.investigation import KnowledgeEvidenceSet, PlannerOutcome, StepAdmission


class DeadlineMoment(StrEnum):
    # The check before the planner or a step may start.
    BEFORE_START = "before_start"
    # The call runner's wait for the planner or the tool call.
    DURING_CALL = "during_call"
    # The finish time a planner reply or tool result is admitted by. Announced only for a
    # call that returned: a call the runner abandoned found the deadline during the call.
    AT_FINISH = "at_finish"


@dataclass(frozen=True)
class DeadlineCheckpoint:
    """A point where the controller checks the deadline: round ``round_number``'s planner
    when ``step_index`` is ``None``, else step ``step_index``."""

    round_number: int
    step_index: int | None
    moment: DeadlineMoment
    is_assessor: bool = False


# Where the planner of a round recording each deadline outcome found the deadline.
DEADLINE_MOMENT_BY_PLANNER_OUTCOME = {
    PlannerOutcome.MODEL_SKIPPED_AT_DEADLINE: DeadlineMoment.BEFORE_START,
    PlannerOutcome.MODEL_TIMED_OUT: DeadlineMoment.DURING_CALL,
    PlannerOutcome.MODEL_REPLY_AFTER_DEADLINE: DeadlineMoment.AT_FINISH,
}
# Where a step recording each deadline admission found the deadline.
DEADLINE_MOMENT_BY_ADMISSION = {
    StepAdmission.TIMED_OUT: DeadlineMoment.DURING_CALL,
    StepAdmission.DISCARDED_AFTER_DEADLINE: DeadlineMoment.AT_FINISH,
}


def ignore_checkpoint(checkpoint: DeadlineCheckpoint) -> None:
    """A measured run's clock moves on its own, so reaching a checkpoint changes nothing."""


def find_deadline_checkpoint(evidence_set: KnowledgeEvidenceSet) -> DeadlineCheckpoint | None:
    """The checkpoint at which the recorded run found the deadline, or ``None`` when it never
    did.

    Finding the deadline ends the run with ``wall_time`` as its breach, and every other
    breach ends it first, so a run found the deadline exactly when ``wall_time`` is its
    breach, and at the last checkpoint it reached: its last round's planner when that
    round records a deadline outcome or no plan (a deterministic round planned past the
    deadline), else its last step when that step records a deadline admission, else the
    start of the step after it. Relies on the set having passed validation.
    """
    trajectory = evidence_set.trajectory
    if trajectory.budget_used.breach is not BudgetBreach.WALL_TIME or not trajectory.rounds:
        return None
    last_round = trajectory.rounds[-1]
    round_number = last_round.round_number
    assessment = last_round.relevance_assessment
    if assessment is not None and assessment.deadline is not None:
        return DeadlineCheckpoint(
            round_number, None, DeadlineMoment(assessment.deadline), is_assessor=True
        )
    planner_moment = DEADLINE_MOMENT_BY_PLANNER_OUTCOME.get(last_round.planner_outcome)
    if planner_moment is not None:
        return DeadlineCheckpoint(round_number, None, planner_moment)
    if not last_round.accepted_plan:
        return DeadlineCheckpoint(round_number, None, DeadlineMoment.BEFORE_START)
    next_step_index = len(trajectory.steps) + 1
    if last_round.executed_step_indices:
        last_step = trajectory.steps[last_round.executed_step_indices[-1] - 1]
        step_moment = DEADLINE_MOMENT_BY_ADMISSION.get(last_step.admission)
        if step_moment is not None:
            return DeadlineCheckpoint(round_number, last_step.step_index, step_moment)
    return DeadlineCheckpoint(round_number, next_step_index, DeadlineMoment.BEFORE_START)
