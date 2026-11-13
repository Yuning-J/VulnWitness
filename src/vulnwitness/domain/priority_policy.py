"""Validated ordered decision tables and regulation basis declarations."""

from string import Formatter
from typing import Literal, Self

from pydantic import Field, model_validator

from vulnwitness.domain.asset_register import FormatVersion, Market, NonblankText, SystemCategory
from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.hashing import canonical_sha256
from vulnwitness.domain.priority_facts import FactName

Recommendation = Literal["act", "attend", "track", "manual_triage_required"]
ComplianceBasis = Literal[
    "platform_record", "platform_grade", "publication_date", "reference_date", "handling_evidence"
]
FACT_VALUES: dict[FactName, tuple[str, ...]] = {
    "applicability": ("affected", "not_affected", "unknown"),
    "system_category": ("external_connection", "software_update", "other", "unknown"),
    "kev": ("listed", "not_listed_in_snapshot", "unknown"),
    "high_grade": ("present", "absent", "none_available"),
    "public_exploit": ("referenced", "not_referenced_in_record", "unknown"),
}


class PolicyCondition(ContractModel):
    fact: FactName
    operator: Literal["equals", "in"]
    values: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def check_operands(self) -> Self:
        if self.operator == "equals" and len(self.values) != 1:
            raise ValueError("equals requires exactly one value")
        for value in self.values:
            if value not in FACT_VALUES[self.fact]:
                raise ValueError("condition value is not valid for its fact")
        if len(set(self.values)) != len(self.values):
            raise ValueError("condition values must be unique")
        return self


class PriorityRule(ContractModel):
    id: NonblankText
    conditions: tuple[PolicyCondition, ...]
    outcome: Recommendation
    reason: NonblankText = Field(
        description="Fixed policy text; may interpolate justification or high_grade_reasons."
    )

    @model_validator(mode="after")
    def check_reason_template(self) -> Self:
        for _, field_name, format_spec, conversion in Formatter().parse(self.reason):
            if field_name is None:
                continue
            if (
                field_name not in ("justification", "high_grade_reasons")
                or format_spec
                or conversion
            ):
                raise ValueError("reason uses an unsupported substitution")
        return self


class Regulation(ContractModel):
    id: NonblankText
    market: Market
    system_categories: tuple[SystemCategory, ...] = Field(min_length=1)
    required_basis: tuple[ComplianceBasis, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def check_unique_basis_and_categories(self) -> Self:
        if len(set(self.required_basis)) != len(self.required_basis):
            raise ValueError("regulation basis must be unique")
        if len(set(self.system_categories)) != len(self.system_categories):
            raise ValueError("regulation system categories must be unique")
        return self


class PriorityPolicy(ContractModel):
    name: NonblankText
    format_version: FormatVersion
    rules: tuple[PriorityRule, ...] = Field(min_length=1)
    regulations: tuple[Regulation, ...]

    @model_validator(mode="after")
    def check_ordered_table(self) -> Self:
        rule_ids: set[str] = set()
        for index, rule in enumerate(self.rules):
            if rule.id in rule_ids:
                raise ValueError("duplicate rule ID")
            rule_ids.add(rule.id)
            if not rule.conditions and index != len(self.rules) - 1:
                raise ValueError("only the final rule may be unconditional")
        if self.rules[-1].conditions:
            raise ValueError("the final rule must be unconditional")
        regulation_ids: set[str] = set()
        for regulation in self.regulations:
            if regulation.id in regulation_ids:
                raise ValueError("duplicate regulation ID")
            regulation_ids.add(regulation.id)
        return self

    def compute_content_sha256(self) -> str:
        """Canonical validated content, independent of YAML comments and key order."""
        return canonical_sha256(self.model_dump(mode="json"))
