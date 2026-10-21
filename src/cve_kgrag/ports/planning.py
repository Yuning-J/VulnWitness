"""The planner a model may provide; the deterministic policy needs no port."""

from typing import Protocol

from cve_kgrag.domain.planning import ModelReply, PlanningInput


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
