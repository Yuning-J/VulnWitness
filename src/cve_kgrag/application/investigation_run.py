"""The per-request mutable record of one investigation, like ``ChannelLog`` for a search."""

from dataclasses import dataclass, field
from datetime import datetime

from cve_kgrag.application.budget_ledger import BudgetLedger
from cve_kgrag.application.investigation_tools import ToolExecution
from cve_kgrag.domain.investigation import (
    DecisionBasis,
    EvidenceNeed,
    Interpretation,
    InvestigationRequest,
    InvestigationState,
    InvestigationWarning,
    RoundRecord,
    StateTransition,
    StepTiming,
    ToolStep,
)
from cve_kgrag.domain.topic import ProtocolTopic


@dataclass
class InvestigationRun:
    request: InvestigationRequest
    interpretation: Interpretation
    topic: ProtocolTopic | None
    ledger: BudgetLedger
    started_at: datetime
    state: InvestigationState = InvestigationState.INTERPRET
    transitions: list[StateTransition] = field(default_factory=list)
    rounds: list[RoundRecord] = field(default_factory=list)
    steps: list[ToolStep] = field(default_factory=list)
    executions: list[ToolExecution] = field(default_factory=list)
    step_timings: list[StepTiming] = field(default_factory=list)
    planner_durations_ms: list[int] = field(default_factory=list)
    # Warnings raised while planning and retrieving, in the order they arose.
    warnings: list[InvestigationWarning] = field(default_factory=list)
    # The latest assessment's needs and whether its answer held an item; refine reads them.
    needs: tuple[EvidenceNeed, ...] = ()
    has_answer: bool = False

    def move(self, to_state: InvestigationState, basis: DecisionBasis) -> None:
        """Record a transition; whether it is legal is the final validator's decision."""
        self.transitions.append(
            StateTransition(from_state=self.state, to_state=to_state, basis=basis)
        )
        self.state = to_state

    def list_round_steps(self, round_number: int) -> list[ToolStep]:
        round_steps: list[ToolStep] = []
        for step in self.steps:
            if step.round_number == round_number:
                round_steps.append(step)
        return round_steps
