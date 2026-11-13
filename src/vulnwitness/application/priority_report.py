"""Present recorded policy decisions without evaluating policy or inferring compliance."""

from vulnwitness.domain.priority_decision import PriorityArtifact, PriorityDecision
from vulnwitness.domain.priority_facts import FACT_NAMES
from vulnwitness.domain.priority_policy import PolicyCondition
from vulnwitness.domain.session_report import ReportParagraph, ReportSection, ReportTable


def describe_condition(condition: PolicyCondition) -> str:
    """Spell out the recorded operator and operands in their policy order."""
    return f"{condition.fact} {condition.operator} ({', '.join(condition.values)})"


def build_priority_decision(decision: PriorityDecision) -> ReportSection:
    """Keep the recommendation, its evidence and separate regulation statuses together."""
    conditions: list[str] = []
    for condition in decision.matched_rule.conditions:
        conditions.append(describe_condition(condition))
    fact_rows: list[tuple[str, ...]] = []
    for fact_name in FACT_NAMES:
        fact = getattr(decision.facts, fact_name)
        fact_rows.append((fact_name, fact.value, ", ".join(fact.evidence_ids) or "none"))
    fact_details: list[str] = []
    if decision.facts.kev.snapshot_retrieved_at is not None:
        fact_details.append(
            f"KEV snapshot retrieved at: {decision.facts.kev.snapshot_retrieved_at.isoformat()}"
        )
    if decision.facts.high_grade.triggering_authorities:
        fact_details.append(
            "High-grade triggering authorities: "
            + ", ".join(decision.facts.high_grade.triggering_authorities)
        )
    for url in decision.facts.public_exploit.reference_urls:
        fact_details.append(f"Exploit-tagged reference (cited, not fetched): {url}")
    earlier_rules: list[ReportSection] = []
    for rule in decision.earlier_unmatched_rules:
        failures: list[str] = []
        for condition in rule.failed_conditions:
            failures.append(describe_condition(condition))
        earlier_rules.append(ReportSection(rule.rule_id, bullets=tuple(failures)))
    compliance: list[ReportSection] = []
    for status in decision.compliance:
        compliance.append(
            ReportSection(
                status.regulation_id,
                paragraphs=(
                    ReportParagraph(f"Compliance status: {status.status}"),
                    ReportParagraph(status.reason),
                    ReportParagraph(
                        "Missing basis: " + (", ".join(status.missing_basis) or "none")
                    ),
                ),
                layout="panel",
            )
        )
    return ReportSection(
        f"{decision.asset} · {decision.cve_id}",
        paragraphs=(
            ReportParagraph(f"Recommendation: {decision.recommendation}"),
            ReportParagraph(decision.reason),
        ),
        sections=(
            ReportSection(
                f"Matched rule: {decision.matched_rule.id}",
                paragraphs=(ReportParagraph(f"Rule outcome: {decision.matched_rule.outcome}"),),
                bullets=tuple(conditions) or ("Unconditional fallback.",),
            ),
            ReportSection(
                "Facts",
                tables=(ReportTable(("Fact", "Value", "Evidence IDs"), tuple(fact_rows)),),
                bullets=tuple(fact_details),
            ),
            ReportSection("Unknown facts", bullets=decision.unknown_facts or ("None.",)),
            ReportSection(
                "What would change this",
                paragraphs=(ReportParagraph("Failed conditions of every earlier unmatched rule."),)
                if earlier_rules
                else (ReportParagraph("No earlier unmatched rules."),),
                sections=tuple(earlier_rules),
            ),
            ReportSection("Notes", bullets=decision.notes or ("None recorded.",)),
            ReportSection(
                "Compliance status — separate from the recommendation",
                paragraphs=()
                if compliance
                else (ReportParagraph("No market regulation recorded."),),
                sections=tuple(compliance),
            ),
        ),
        layout="panel",
    )


def build_priority_report(priority: PriorityArtifact) -> ReportSection:
    """Render the checked artifact's identities and explanations in fixed recorded order."""
    decisions: list[ReportSection] = []
    for decision in priority.decisions:
        decisions.append(build_priority_decision(decision))
    return ReportSection(
        "Priority decisions",
        paragraphs=(
            ReportParagraph(
                "A recommendation is VulnWitness policy output, not a compliance conclusion."
            ),
            ReportParagraph(
                'KEV not_listed_in_snapshot means not listed in that snapshot, not "not exploited".'
            ),
            ReportParagraph(
                "public_exploit not_referenced_in_record means the record cites no "
                'exploit-tagged reference, not "no public exploit exists".'
            ),
            ReportParagraph(
                f"Policy: {priority.policy.name} · format_version: {priority.policy.format_version}"
            ),
            ReportParagraph(f"Policy digest (SHA-256): {priority.policy.content_sha256}"),
            ReportParagraph(f"Register digest (SHA-256): {priority.register_sha256}"),
            ReportParagraph(f"Reference date: {priority.reference_date.isoformat()}"),
            ReportParagraph(
                "Used after-reference-date information: "
                + str(priority.used_after_reference_date_information).lower()
            ),
        ),
        sections=tuple(decisions),
        anchor="priority-decisions",
    )
