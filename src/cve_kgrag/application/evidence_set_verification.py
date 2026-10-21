"""Verification of a knowledge evidence set handed back by a consumer: the validator, the
decision-path audit and replay, run against the deployment and the planners of the
configuration the set is checked against.

The service runs the first two on every set it seals; replay needs the deployment's
sources, so it runs only here and in tests. Together they bind a set's structure and
catalog content, its capabilities, its decisions and its recorded observations to what
that configuration serves (ADR 0002 §12, ADR 0003 §10, ADR 0004).
"""

from collections.abc import Sequence

from cve_kgrag.application.decision_path_audit import audit_decision_path
from cve_kgrag.application.investigation_deployment import InvestigationDeployment
from cve_kgrag.application.trajectory_replay import ReplayOutcome, replay_evidence_set
from cve_kgrag.domain.investigation import KnowledgeEvidenceSet, SourceCapability
from cve_kgrag.domain.investigation_validation import validate_knowledge_evidence_set


def verify_evidence_set(
    evidence_set: KnowledgeEvidenceSet,
    deployment: InvestigationDeployment,
    accepted_planner_capabilities: Sequence[SourceCapability],
) -> ReplayOutcome:
    """Validate ``evidence_set`` against ``deployment`` and one of the
    ``accepted_planner_capabilities``, audit its decision path, then replay it on
    ``deployment``, in that order.

    ``accepted_planner_capabilities`` are the ``model_planner`` capabilities the verifying
    configuration's services can report (at least one), so a set naming a planner that
    configuration does not run is rejected rather than taken at its word. The set must
    report the deployment's capabilities followed by its own ``model_planner`` capability
    when that is one of them, as a service requires at seal; a set reporting any other
    planner is checked against the first accepted one, and the validator names the
    difference. Raises ``EvidenceValidationError`` when the validator or the audit rejects
    the set, or when the replayed set fails the checks the controller runs at seal;
    otherwise returns the replay's outcome, whose ``ReplayCompleted.differences`` is empty
    only when the deployment's sources give back the recorded set.
    """
    expected_planner_capability = accepted_planner_capabilities[0]
    for recorded_capability in evidence_set.source_capabilities:
        if recorded_capability in accepted_planner_capabilities:
            expected_planner_capability = recorded_capability
    validate_knowledge_evidence_set(
        evidence_set,
        deployment.pinned_fight_snapshot,
        deployment.evidence_catalog,
        (*deployment.source_capabilities, expected_planner_capability),
    )
    audit_decision_path(evidence_set, deployment.topic_registry)
    return replay_evidence_set(evidence_set, deployment)
