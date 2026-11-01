"""The planner a model may provide; the deterministic policy needs no port."""

from typing import Protocol

from vulnwitness.domain.planning import ModelReply, PlanningInput
from vulnwitness.domain.relevance import RelevanceInput


class ModelPort(Protocol):
    """An untrusted planner: it proposes, the core decides.

    The port says nothing about itself: which model, adapter and endpoint plan is the
    identity the server builds from the settings and the installed entry point
    (``ModelPlanning.identity``), recorded in every trajectory the port plans.
    """

    def propose_plan(self, planning_input: PlanningInput, timeout_seconds: float) -> ModelReply:
        """Raw QueryPlan JSON, or a failed reply naming one ``ModelReplyFailureDetail``;
        never raises.

        Returns within ``timeout_seconds``: the core stops waiting at the run's deadline
        and abandons the call, but only the adapter can end its own request.
        """
        ...

    def assess_relevance(
        self, assessment_input: RelevanceInput, timeout_seconds: float
    ) -> ModelReply:
        """Raw relevance JSON or a typed failure, under the planner's transport rules."""
        ...
