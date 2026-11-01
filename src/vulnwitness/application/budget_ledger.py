"""Per-run accounting of the investigation budget against an injected monotonic clock.

Tool calls are charged before the call and never refunded, so failed, late,
timed-out and invalid calls stay charged. Wall time is checked before each call, the
call runner waits for a call only until ``remaining_seconds`` reaches zero, and a
result that still finishes at or after the deadline is discarded.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from vulnwitness.domain.budget import BudgetBreach, BudgetUsage, InvestigationBudget
from vulnwitness.domain.investigation import StepAdmission
from vulnwitness.domain.topic_context import KnowledgeSource


@dataclass
class BudgetLedger:
    budget: InvestigationBudget
    monotonic_clock: Callable[[], float]
    started_at_seconds: float
    rounds_used: int = 0
    tool_calls_used: int = 0
    sources_used: list[KnowledgeSource] = field(default_factory=list)
    context_bytes_admitted: int = 0
    planner_calls: int = 0
    breach: BudgetBreach | None = None

    def elapsed_seconds(self) -> float:
        return self.monotonic_clock() - self.started_at_seconds

    def remaining_seconds(self) -> float:
        return max(0.0, self.budget.max_wall_time_seconds - self.elapsed_seconds())

    def is_past_deadline(self, elapsed_seconds: float) -> bool:
        """Reaching the deadline exactly counts as past it: nothing may start or land there."""
        return elapsed_seconds >= self.budget.max_wall_time_seconds

    def is_out_of_time(self) -> bool:
        return self.is_past_deadline(self.elapsed_seconds())

    def remaining_tool_calls(self) -> int:
        return self.budget.max_tool_calls - self.tool_calls_used

    def charge(self, charged_tool_calls: int, sources: Sequence[KnowledgeSource]) -> None:
        """Charge a call before it runs; the charge stands whatever the call returns."""
        self.tool_calls_used += charged_tool_calls
        for source in sources:
            if source not in self.sources_used:
                self.sources_used.append(source)

    def decide_admission(
        self, context_bytes: int, finished_seconds: float, *, is_prefix: bool = False
    ) -> StepAdmission:
        """Charge the admitted response bytes; a whole-result prefix is not a breach.

        ``finished_seconds`` is the elapsed time the step's own timing records, so the
        admission and the recorded finish time cannot disagree.
        """
        if self.is_past_deadline(finished_seconds):
            self.record_breach(BudgetBreach.WALL_TIME)
            return StepAdmission.DISCARDED_AFTER_DEADLINE
        if self.context_bytes_admitted + context_bytes > self.budget.max_context_bytes:
            self.record_breach(BudgetBreach.CONTEXT_BYTES)
            return StepAdmission.DISCARDED_OVER_CONTEXT_BUDGET
        self.context_bytes_admitted += context_bytes
        return StepAdmission.ADMITTED_PREFIX if is_prefix else StepAdmission.ADMITTED

    def record_breach(self, breach: BudgetBreach) -> None:
        """The first breach stops the run, so it is the one reported."""
        if self.breach is None:
            self.breach = breach

    def summarize_usage(self) -> BudgetUsage:
        return BudgetUsage(
            rounds=self.rounds_used,
            tool_calls=self.tool_calls_used,
            sources=tuple(self.sources_used),
            planner_calls=self.planner_calls,
            context_bytes=self.context_bytes_admitted,
            breach=self.breach,
        )
