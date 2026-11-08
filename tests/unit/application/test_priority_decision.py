"""Ordered policy decisions explain escalation, unknowns and separate compliance basis."""

import pytest

from tests.support.priority import build_priority_inputs
from vulnwitness.adapters.priority_policy import default_priority_policy_file, load_priority_policy
from vulnwitness.application.priority_decision import evaluate_priority
from vulnwitness.domain.asset_register import Applicability, SystemCategory
from vulnwitness.domain.priority_facts import HighGradeStatus, KevStatus
from vulnwitness.domain.priority_policy import PriorityPolicy


@pytest.fixture
def policy() -> PriorityPolicy:
    return load_priority_policy(default_priority_policy_file()).policy


@pytest.mark.parametrize(
    ("applicability", "category", "kev", "grade", "rule_id", "recommendation"),
    [
        ("unknown", "external_connection", "listed", "present", "rule-1", "manual_triage_required"),
        ("not_affected", "unknown", "listed", "present", "rule-2", "track"),
        ("affected", "external_connection", "listed", "absent", "rule-3", "act"),
        ("affected", "software_update", "listed", "absent", "rule-3", "act"),
        ("affected", "other", "listed", "present", "rule-4", "attend"),
        ("affected", "unknown", "listed", "none_available", "rule-4", "attend"),
        (
            "affected",
            "unknown",
            "not_listed_in_snapshot",
            "present",
            "rule-5",
            "manual_triage_required",
        ),
        ("affected", "external_connection", "unknown", "present", "rule-6", "attend"),
        (
            "affected",
            "software_update",
            "not_listed_in_snapshot",
            "present",
            "rule-6",
            "attend",
        ),
        ("affected", "other", "unknown", "none_available", "rule-7", "manual_triage_required"),
        (
            "affected",
            "external_connection",
            "not_listed_in_snapshot",
            "none_available",
            "rule-8",
            "manual_triage_required",
        ),
        ("affected", "external_connection", "not_listed_in_snapshot", "absent", "rule-9", "track"),
        ("affected", "other", "not_listed_in_snapshot", "none_available", "rule-9", "track"),
    ],
    ids=[
        "unassessed-before-positive-evidence",
        "not-affected-before-kev",
        "kev-external-act",
        "kev-update-act",
        "kev-other-attend",
        "kev-unknown-category-before-rule-5",
        "unknown-category-before-grade",
        "high-grade-before-unknown-kev",
        "update-high-grade-attend",
        "unknown-kev-before-unavailable-grade",
        "in-scope-no-grade",
        "in-scope-low-grade-track",
        "other-no-grade-track",
    ],
)
def test_first_matching_rule_sets_the_recommendation(
    policy: PriorityPolicy,
    applicability: Applicability,
    category: SystemCategory,
    kev: KevStatus,
    grade: HighGradeStatus,
    rule_id: str,
    recommendation: str,
) -> None:
    asset, assessment, facts = build_priority_inputs(
        applicability, category, kev, grade, ("CNVD",) if grade == "present" else ()
    )

    decision = evaluate_priority(policy, asset, assessment, facts)

    assert decision.matched_rule.id == rule_id
    assert decision.recommendation == recommendation
    assert decision.facts == facts


@pytest.mark.parametrize(
    ("category", "kev", "grade", "expected_unknowns"),
    [
        ("external_connection", "listed", "none_available", ("high_grade",)),
        ("unknown", "listed", "none_available", ("system_category", "high_grade")),
        ("external_connection", "unknown", "present", ("kev",)),
    ],
    ids=["rule-3-no-grade", "rule-4-category-and-grade", "rule-6-kev"],
)
def test_escalation_retains_every_unknown_fact(
    policy: PriorityPolicy,
    category: SystemCategory,
    kev: KevStatus,
    grade: HighGradeStatus,
    expected_unknowns: tuple[str, ...],
) -> None:
    asset, assessment, facts = build_priority_inputs(
        system_category=category,
        kev=kev,
        high_grade=grade,
        authorities=("CNVD",) if grade == "present" else (),
    )

    decision = evaluate_priority(policy, asset, assessment, facts)

    assert decision.unknown_facts == expected_unknowns


def test_earlier_rules_list_every_failed_condition_in_policy_order(policy: PriorityPolicy) -> None:
    asset, assessment, facts = build_priority_inputs(
        kev="unknown", high_grade="present", authorities=("CNVD",)
    )

    decision = evaluate_priority(policy, asset, assessment, facts)

    failed_facts: list[tuple[str, tuple[str, ...]]] = []
    for unmatched_rule in decision.earlier_unmatched_rules:
        condition_facts: list[str] = []
        for condition in unmatched_rule.failed_conditions:
            condition_facts.append(condition.fact)
        failed_facts.append((unmatched_rule.rule_id, tuple(condition_facts)))
    assert failed_facts == [
        ("rule-1", ("applicability",)),
        ("rule-2", ("applicability",)),
        ("rule-3", ("kev",)),
        ("rule-4", ("kev",)),
        ("rule-5", ("system_category",)),
    ]
    assert decision.matched_rule.conditions == policy.rules[5].conditions
    assert decision.earlier_unmatched_rules[2].failed_conditions == (policy.rules[2].conditions[1],)


def test_failed_rule_reports_multiple_conditions_together(policy: PriorityPolicy) -> None:
    asset, assessment, facts = build_priority_inputs(system_category="other")

    decision = evaluate_priority(policy, asset, assessment, facts)

    assert decision.earlier_unmatched_rules[2].failed_conditions == policy.rules[2].conditions[1:]


@pytest.mark.parametrize("authorities", [("CNVD",), ("NVD",), ("NVD", "CNVD")])
def test_grade_reason_names_each_triggering_authority(
    policy: PriorityPolicy, authorities: tuple[str, ...]
) -> None:
    asset, assessment, facts = build_priority_inputs(high_grade="present", authorities=authorities)

    decision = evaluate_priority(policy, asset, assessment, facts)

    for authority in authorities:
        assert f"the {authority} high grade triggered this policy rule" in decision.reason


def test_not_affected_reason_cites_the_analyst_justification(policy: PriorityPolicy) -> None:
    asset, assessment, facts = build_priority_inputs(applicability="not_affected")

    decision = evaluate_priority(policy, asset, assessment, facts)

    assert assessment.justification in decision.reason


@pytest.mark.parametrize(
    ("category", "expected_status"),
    [
        ("other", "not_applicable"),
        ("external_connection", "basis_insufficient"),
        ("software_update", "basis_insufficient"),
        ("unknown", "basis_insufficient"),
    ],
    ids=["out-of-scope", "external", "update", "unknown-category"],
)
def test_compliance_is_separate_and_never_inferred_from_action(
    policy: PriorityPolicy, category: SystemCategory, expected_status: str
) -> None:
    asset, assessment, facts = build_priority_inputs(system_category=category, kev="listed")

    decision = evaluate_priority(policy, asset, assessment, facts)

    assert decision.compliance[0].status == expected_status
    expected_basis = () if category == "other" else policy.regulations[0].required_basis
    assert decision.compliance[0].missing_basis == expected_basis
    for missing_basis in expected_basis:
        assert missing_basis in decision.compliance[0].reason


def test_asset_markets_filter_regulations(policy: PriorityPolicy) -> None:
    asset, assessment, facts = build_priority_inputs(markets=("US",))

    decision = evaluate_priority(policy, asset, assessment, facts)

    assert decision.compliance == ()


@pytest.mark.parametrize("mismatch", ["asset", "applicability", "system_category"])
def test_disagreeing_register_facts_are_rejected(policy: PriorityPolicy, mismatch: str) -> None:
    asset, assessment, facts = build_priority_inputs()
    if mismatch == "asset":
        assessment = assessment.model_copy(update={"asset": "another-asset"})
    elif mismatch == "applicability":
        assessment = assessment.model_copy(update={"applicability": "not_affected"})
    else:
        asset = asset.model_copy(update={"system_category": "other"})

    with pytest.raises(ValueError, match=r"asset|assessment"):
        evaluate_priority(policy, asset, assessment, facts)
