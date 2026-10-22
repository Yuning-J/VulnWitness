"""Verification of a knowledge evidence set handed back by a consumer: the validator, the
decision-path audit and replay, run against the deployment and the planners of the
configuration the set is checked against.

The service runs the first two on every set it seals; replay needs the deployment's
sources, so it runs only here and in tests. Together they bind a set's structure and
catalog content, its capabilities, its decisions and its recorded observations to what
that configuration serves (ADR 0002 §12, ADR 0003 §10, ADR 0004).
"""

from collections.abc import Sequence

from pydantic import ValidationError

from cve_kgrag.application.decision_path_audit import audit_decision_path
from cve_kgrag.application.investigation_deployment import InvestigationDeployment
from cve_kgrag.application.trajectory_replay import (
    ReplayOutcome,
    ReplayTimedOut,
    replay_evidence_set,
)
from cve_kgrag.domain.contract_model import list_validation_problems
from cve_kgrag.domain.evidence_set_verification_report import (
    MAX_REPORTED_VIOLATIONS,
    ReportedDifference,
    VerificationReport,
    VerificationVerdict,
)
from cve_kgrag.domain.investigation import KnowledgeEvidenceSet, SourceCapability
from cve_kgrag.domain.investigation_validation import validate_knowledge_evidence_set
from cve_kgrag.domain.validation import EvidenceValidationError


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


def check_evidence_set(
    evidence_set_bytes: bytes,
    deployment: InvestigationDeployment,
    accepted_planner_capabilities: Sequence[SourceCapability],
) -> VerificationReport:
    """Parse ``evidence_set_bytes`` as a knowledge evidence set and verify it
    (``verify_evidence_set``), reporting every outcome as a verdict rather than raising:
    ``malformed`` with the parser's problems, ``invalid`` with the violations the
    validator, the audit or the replayed set's seal checks found (each list cut to
    ``MAX_REPORTED_VIOLATIONS``), ``replay_timed_out``, ``replay_differs`` with each
    difference, or ``verified``."""
    try:
        evidence_set = KnowledgeEvidenceSet.model_validate_json(evidence_set_bytes)
    except ValidationError as error:
        return VerificationReport(
            verdict=VerificationVerdict.MALFORMED,
            violations=tuple(list_validation_problems(error)[:MAX_REPORTED_VIOLATIONS]),
        )
    try:
        replay_outcome = verify_evidence_set(
            evidence_set, deployment, accepted_planner_capabilities
        )
    except EvidenceValidationError as error:
        return VerificationReport(
            verdict=VerificationVerdict.INVALID,
            violations=error.violations[:MAX_REPORTED_VIOLATIONS],
        )
    if isinstance(replay_outcome, ReplayTimedOut):
        return VerificationReport(verdict=VerificationVerdict.REPLAY_TIMED_OUT)
    if not replay_outcome.differences:
        return VerificationReport(verdict=VerificationVerdict.VERIFIED)
    reported_differences: list[ReportedDifference] = []
    for difference in replay_outcome.differences:
        reported_differences.append(
            ReportedDifference(step_index=difference.step_index, part=difference.part)
        )
    return VerificationReport(
        verdict=VerificationVerdict.REPLAY_DIFFERS, differences=tuple(reported_differences)
    )
