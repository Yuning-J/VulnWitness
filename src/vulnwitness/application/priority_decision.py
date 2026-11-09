"""Pure first-match policy evaluation over explicit facts (ADR 0016 §3-5)."""

from vulnwitness.domain.asset_register import Asset, AssetAssessment
from vulnwitness.domain.priority_decision import ComplianceStatus, PriorityDecision, UnmatchedRule
from vulnwitness.domain.priority_facts import PriorityFacts
from vulnwitness.domain.priority_policy import PolicyCondition, PriorityPolicy, PriorityRule


def evaluate_priority(
    policy: PriorityPolicy,
    asset: Asset,
    assessment: AssetAssessment,
    facts: PriorityFacts,
) -> PriorityDecision:
    """Recommend from the first matching rule and explain all earlier failed conditions.

    Facts about the register must agree with the supplied asset and assessment; a mismatch
    raises ValueError. There is no authoritative-platform input, so compliance can only be
    not_applicable or basis_insufficient. No service, store or clock is consulted.
    """
    if assessment.asset != asset.name:
        raise ValueError("assessment must name the supplied asset")
    if facts.applicability.value != assessment.applicability:
        raise ValueError("applicability fact must agree with the assessment")
    if facts.system_category.value != asset.system_category:
        raise ValueError("system category fact must agree with the asset")
    earlier_unmatched_rules: list[UnmatchedRule] = []
    for rule in policy.rules:
        failed_conditions: list[PolicyCondition] = []
        for condition in rule.conditions:
            fact_value = getattr(facts, condition.fact).value
            if fact_value not in condition.values:
                failed_conditions.append(condition)
        if failed_conditions:
            earlier_unmatched_rules.append(
                UnmatchedRule(rule_id=rule.id, failed_conditions=tuple(failed_conditions))
            )
            continue
        return PriorityDecision(
            asset=asset.name,
            cve_id=assessment.cve_id,
            recommendation=rule.outcome,
            reason=render_rule_reason(rule, assessment, facts),
            matched_rule=rule,
            facts=facts,
            unknown_facts=facts.list_unknown_facts(),
            earlier_unmatched_rules=tuple(earlier_unmatched_rules),
            compliance=evaluate_compliance(policy, asset),
        )
    raise AssertionError("validated policies end with an unconditional rule")


def render_rule_reason(
    rule: PriorityRule, assessment: AssetAssessment, facts: PriorityFacts
) -> str:
    grade_reasons: list[str] = []
    for authority in sorted(facts.high_grade.triggering_authorities):
        grade_reasons.append(f"the {authority} high grade triggered this policy rule")
    reason = rule.reason.format(
        justification=assessment.justification,
        high_grade_reasons="; ".join(grade_reasons),
    )
    if any(condition.fact == "high_grade" for condition in rule.conditions):
        for link in facts.high_grade.cnvd_links_to_review:
            reason = reason.rstrip(".") + ". "
            reason += (
                f"{link.cnvd_id}'s product name ({link.cnvd_name}) does not overlap "
                "NVD's CPE names; review the link."
            )
    return reason


def evaluate_compliance(policy: PriorityPolicy, asset: Asset) -> tuple[ComplianceStatus, ...]:
    """Only regulations selected by the asset's markets; unknown categories lack basis."""
    compliance: list[ComplianceStatus] = []
    for regulation in policy.regulations:
        if regulation.market not in asset.markets:
            continue
        if (
            asset.system_category != "unknown"
            and asset.system_category not in regulation.system_categories
        ):
            compliance.append(
                ComplianceStatus(
                    regulation_id=regulation.id,
                    status="not_applicable",
                    missing_basis=(),
                    reason="The asset's system category is outside this regulation's scope.",
                )
            )
            continue
        compliance.append(
            ComplianceStatus(
                regulation_id=regulation.id,
                status="basis_insufficient",
                missing_basis=regulation.required_basis,
                reason="No authoritative-platform input is available. Missing basis: "
                + ", ".join(regulation.required_basis)
                + ".",
            )
        )
    return tuple(compliance)
