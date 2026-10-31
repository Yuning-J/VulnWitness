"""The investigation warnings a run's interpretation and decisions give, as pure functions.

The controller raises these warnings while it runs, and the decision-path audit
re-derives them from a sealed set's request, interpretation and recorded rounds and
steps with the same functions, so a warning has one implementation.
"""

from collections.abc import Sequence

from cve_kgrag.domain.investigation import (
    Interpretation,
    InvestigationRequest,
    InvestigationWarning,
    InvestigationWarningCode,
    StepAdmission,
)
from cve_kgrag.domain.planning import PlanRejection, QueryIntent
from cve_kgrag.domain.topic import ProtocolTopic, ReviewStatus, describe_topic_family_scope
from cve_kgrag.domain.topic_context import QueryScope


def list_interpretation_warnings(
    request: InvestigationRequest,
    interpretation: Interpretation,
    topic: ProtocolTopic | None,
    ran_any_step: bool,
) -> list[InvestigationWarning]:
    """Excluded terms, a topic the scope expects but the query did not resolve, a query
    without searchable terms, a pending-review card, and the GTP card's family scope."""
    warnings: list[InvestigationWarning] = []
    for name in interpretation.ambiguous_product_names:
        warnings.append(
            InvestigationWarning(code=InvestigationWarningCode.PRODUCT_NAME_AMBIGUOUS, subject=name)
        )
    for excluded_term in interpretation.resolution.excluded_terms:
        warnings.append(
            InvestigationWarning(
                code=InvestigationWarningCode.EXCLUDED_TERM, subject=excluded_term.term
            )
        )
    is_topic_expected = request.scope is not QueryScope.IMPLEMENTATION_ONLY
    if is_topic_expected and interpretation.intent not in {QueryIntent.TOPIC, QueryIntent.EXACT_ID}:
        warnings.append(
            InvestigationWarning(
                code=InvestigationWarningCode.TOPIC_NOT_RESOLVED,
                subject=interpretation.normalized_query,
            )
        )
    if interpretation.intent is QueryIntent.UNSEARCHABLE:
        warnings.append(
            InvestigationWarning(
                code=InvestigationWarningCode.NO_SEARCHABLE_TERMS,
                subject=interpretation.normalized_query,
            )
        )
    # A pending card still drives retrieval and relevance once any step ran.
    if topic is not None and topic.review.status is ReviewStatus.PENDING_REVIEW and ran_any_step:
        warnings.append(
            InvestigationWarning(
                code=InvestigationWarningCode.TOPIC_PENDING_REVIEW, subject=topic.topic_id
            )
        )
    if topic is not None and ran_any_step:
        family_scope = describe_topic_family_scope(interpretation.resolution.matches[0])
        if family_scope is not None:
            warnings.append(
                InvestigationWarning(
                    code=InvestigationWarningCode.TOPIC_FAMILY_SCOPE, subject=family_scope
                )
            )
    return warnings


def build_model_plan_rejected_warning(
    round_number: int, model_rejections: Sequence[PlanRejection]
) -> InvestigationWarning:
    """The warning for a rejected model reply, naming each of its rejection codes once."""
    rejection_codes: list[str] = []
    for rejection in model_rejections:
        if rejection.code.value not in rejection_codes:
            rejection_codes.append(rejection.code.value)
    return InvestigationWarning(
        code=InvestigationWarningCode.MODEL_PLAN_REJECTED,
        subject=f"round {round_number}: {', '.join(rejection_codes)}",
    )


def build_evidence_discarded_warning(
    step_index: int, admission: StepAdmission
) -> InvestigationWarning:
    """The warning for a step whose result a cap kept out of the answer."""
    return InvestigationWarning(
        code=InvestigationWarningCode.EVIDENCE_DISCARDED,
        subject=f"step {step_index}: {admission.value}",
    )
