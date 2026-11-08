"""Explanations and deterministic priority artifacts, separate from compliance findings."""

from typing import Literal, Self

from pydantic import Field, StrictBool, model_validator

from vulnwitness.domain.asset_register import NonblankText
from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.cve import CveId
from vulnwitness.domain.hashing import canonical_json_bytes
from vulnwitness.domain.priority_facts import FactName, PriorityFacts
from vulnwitness.domain.priority_policy import (
    ComplianceBasis,
    PolicyCondition,
    PriorityRule,
    Recommendation,
)
from vulnwitness.domain.search import SCHEMA_VERSION, SchemaVersion
from vulnwitness.domain.session_claim import SessionSequence
from vulnwitness.domain.session_record import Digest, SessionDatasetIdentity
from vulnwitness.domain.timestamps import CalendarDate


class UnmatchedRule(ContractModel):
    rule_id: NonblankText
    failed_conditions: tuple[PolicyCondition, ...] = Field(min_length=1)


class ComplianceStatus(ContractModel):
    regulation_id: NonblankText
    status: Literal["basis_insufficient", "not_applicable", "not_met", "met"]
    missing_basis: tuple[ComplianceBasis, ...]
    reason: NonblankText


class PriorityDecision(ContractModel):
    asset: NonblankText
    cve_id: CveId
    recommendation: Recommendation
    reason: NonblankText
    matched_rule: PriorityRule
    facts: PriorityFacts
    unknown_facts: tuple[FactName, ...]
    earlier_unmatched_rules: tuple[UnmatchedRule, ...]
    compliance: tuple[ComplianceStatus, ...]


class PolicyIdentity(ContractModel):
    name: NonblankText
    format_version: Literal[1]
    content_sha256: Digest


class DecisionResponseDigest(ContractModel):
    call: SessionSequence
    response_sha256: Digest


class PriorityArtifact(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    program_version: NonblankText
    policy: PolicyIdentity
    dataset: SessionDatasetIdentity
    response_digests: tuple[DecisionResponseDigest, ...]
    register_sha256: Digest
    reference_date: CalendarDate
    used_after_reference_date_information: StrictBool
    decisions: tuple[PriorityDecision, ...]

    @model_validator(mode="after")
    def fix_result_order(self) -> Self:
        decisions = sorted(self.decisions, key=decision_sort_key)
        decision_keys: set[tuple[str, str]] = set()
        for decision in decisions:
            decision_key = decision_sort_key(decision)
            if decision_key in decision_keys:
                raise ValueError("duplicate asset and CVE decision")
            decision_keys.add(decision_key)
        response_digests = sorted(self.response_digests, key=response_digest_sort_key)
        response_calls: set[int] = set()
        for response_digest in response_digests:
            if response_digest.call in response_calls:
                raise ValueError("duplicate response call")
            response_calls.add(response_digest.call)
        object.__setattr__(self, "decisions", tuple(decisions))
        object.__setattr__(self, "response_digests", tuple(response_digests))
        return self

    def to_json_bytes(self) -> bytes:
        """Canonical UTF-8 JSON with fixed keys, pair order and response-call order."""
        return canonical_json_bytes(self.model_dump(mode="json")) + b"\n"


def decision_sort_key(decision: PriorityDecision) -> tuple[str, str]:
    return decision.asset, decision.cve_id


def response_digest_sort_key(response_digest: DecisionResponseDigest) -> int:
    return response_digest.call
