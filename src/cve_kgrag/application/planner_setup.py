"""The planner an investigation service runs: a model behind its port, or the deterministic
policy, which plans alone or in place of a configured model planner that cannot plan."""

from dataclasses import dataclass

from cve_kgrag.application.investigation_policy import describe_deterministic_planner
from cve_kgrag.domain.investigation import SourceCapability, describe_planner_capability
from cve_kgrag.domain.planning import (
    ModelPlannerIdentity,
    ModelPlannerUnavailableDetail,
    PlannerIdentity,
)
from cve_kgrag.ports.planning import ModelPort


@dataclass(frozen=True)
class ModelPlanning:
    """A model planner: ``identity`` names the model, adapter and endpoint that
    ``model_port`` plans through, as discovery built it from the settings and the installed
    entry point, and every trajectory it plans records it."""

    identity: ModelPlannerIdentity
    model_port: ModelPort


@dataclass(frozen=True)
class DeterministicPlanning:
    """The deterministic policy; ``unavailable_detail`` says why a configured model planner
    cannot plan, and is ``None`` when no model planner is configured."""

    unavailable_detail: ModelPlannerUnavailableDetail | None = None


PlannerSetup = ModelPlanning | DeterministicPlanning


def describe_setup_planner(planner_setup: PlannerSetup) -> PlannerIdentity:
    """The planner every trajectory of a service running ``planner_setup`` records."""
    if isinstance(planner_setup, ModelPlanning):
        return planner_setup.identity
    return describe_deterministic_planner()


def describe_setup_capability(planner_setup: PlannerSetup) -> SourceCapability:
    """The ``model_planner`` capability every set of a service running ``planner_setup``
    reports."""
    if isinstance(planner_setup, ModelPlanning):
        return describe_planner_capability(planner_setup.identity)
    return describe_planner_capability(
        describe_deterministic_planner(), planner_setup.unavailable_detail
    )
