"""The M7b gold file (``docs/rebuild/m7b-gold-labels.md``): hand-labelled cases, the rules
that derive each case's sets, and the corpus and FiGHT snapshot the labels were confirmed
against.

A problem is reported by case position and the server's words, never by quoting the file.
"""

from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from cve_kgrag.adapters.strict_yaml import load_strict_yaml
from cve_kgrag.domain.contract_model import list_validation_problems
from cve_kgrag.domain.evidence import SHA256_PATTERN
from cve_kgrag.domain.evidence_set_verification_report import bound_violations
from cve_kgrag.domain.investigation import InvestigationRequest
from cve_kgrag.evaluation.gold_cases import MAX_GOLD_CASES, MAX_GOLD_FILE_BYTES, GoldFileError
from cve_kgrag.evaluation.gold_rules import (
    CVE_PREDICATES,
    TECHNIQUE_PREDICATES,
    CveSubject,
    GoldRuleError,
    Rule,
    TechniqueSubject,
    parse_rule,
)

CASE_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{0,63}$"
MAX_TEXT_CHARS = 500


class EvidenceCategory(StrEnum):
    NAMED_CVE = "named_cve"
    IMPLEMENTATION_CVES = "implementation_cves"
    PROTOCOL_CONTEXT = "protocol_context"
    AFFECTEDNESS = "affectedness"


class Sufficiency(StrEnum):
    SUFFICIENT = "sufficient"
    PARTIAL = "partial"
    INSUFFICIENT = "insufficient"
    UNCERTAIN = "uncertain"


class Split(StrEnum):
    BASELINE = "baseline"
    HOLDOUT = "holdout"


class SetName(StrEnum):
    RELEVANT = "relevant"
    REQUIRED = "required"
    IRRELEVANT = "irrelevant"
    WIDE_CHECK = "wide_check"


class SubjectKind(StrEnum):
    CVES = "cves"
    TECHNIQUES = "techniques"


# The subject kind whose required set holds each category's evidence; affectedness has no
# evidence in M7b, so no set can hold it.
CATEGORY_SUBJECTS: dict[EvidenceCategory, SubjectKind | None] = {
    EvidenceCategory.NAMED_CVE: SubjectKind.CVES,
    EvidenceCategory.IMPLEMENTATION_CVES: SubjectKind.CVES,
    EvidenceCategory.PROTOCOL_CONTEXT: SubjectKind.TECHNIQUES,
    EvidenceCategory.AFFECTEDNESS: None,
}


class LabelRow(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    sufficiency: Sufficiency
    reason: str = Field(min_length=1, max_length=MAX_TEXT_CHARS)


class CaseRow(BaseModel):
    """One case as the file states it; its rules stay raw until ``parse_rule`` reads them."""

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    id: str = Field(pattern=CASE_ID_PATTERN)
    split: Split
    goal: str = Field(min_length=1, max_length=MAX_TEXT_CHARS)
    request: InvestigationRequest
    needs: tuple[EvidenceCategory, ...] = Field(min_length=1)
    rules: dict[SubjectKind, dict[SetName, object]]
    label: LabelRow
    drafted_by: Literal["assistant"]
    confirmed_by: Literal["owner"]
    confirmed_on: date


class GoldFileRow(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    corpus_content_sha256: str = Field(pattern=SHA256_PATTERN)
    fight_snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    cases: list[CaseRow] = Field(min_length=1, max_length=MAX_GOLD_CASES)


@dataclass(frozen=True)
class LabelledCase:
    """A case's identity, request, needed categories, label and parsed rules: for each
    subject kind it has rules for, a rule per set it names."""

    case_id: str
    split: Split
    request: InvestigationRequest
    needs: tuple[EvidenceCategory, ...]
    sufficiency: Sufficiency
    cve_rules: dict[SetName, Rule[CveSubject]] | None
    technique_rules: dict[SetName, Rule[TechniqueSubject]] | None


@dataclass(frozen=True)
class GoldFile:
    corpus_content_sha256: str
    fight_snapshot_sha256: str
    cases: tuple[LabelledCase, ...]


def check_set_names(set_rules: dict[SetName, object], position: int) -> None:
    if SetName.REQUIRED in set_rules and SetName.RELEVANT not in set_rules:
        raise GoldFileError(f"case {position}: a required rule needs a relevant rule")


def read_case(case_row: CaseRow, position: int) -> LabelledCase:
    if len(set(case_row.needs)) != len(case_row.needs):
        raise GoldFileError(f"case {position}: needs lists a category twice")
    for category in case_row.needs:
        subject_kind = CATEGORY_SUBJECTS[category]
        if subject_kind is not None and subject_kind not in case_row.rules:
            raise GoldFileError(
                f"case {position}: needs {category.value} but has no {subject_kind.value} rules"
            )
    cve_rules: dict[SetName, Rule[CveSubject]] | None = None
    technique_rules: dict[SetName, Rule[TechniqueSubject]] | None = None
    try:
        if SubjectKind.CVES in case_row.rules:
            check_set_names(case_row.rules[SubjectKind.CVES], position)
            cve_rules = {}
            for set_name, node in case_row.rules[SubjectKind.CVES].items():
                cve_rules[set_name] = parse_rule(node, CVE_PREDICATES)
        if SubjectKind.TECHNIQUES in case_row.rules:
            check_set_names(case_row.rules[SubjectKind.TECHNIQUES], position)
            technique_rules = {}
            for set_name, node in case_row.rules[SubjectKind.TECHNIQUES].items():
                technique_rules[set_name] = parse_rule(node, TECHNIQUE_PREDICATES)
    except GoldRuleError as error:
        raise GoldFileError(f"case {position}: {error}") from None
    return LabelledCase(
        case_id=case_row.id,
        split=case_row.split,
        request=case_row.request,
        needs=case_row.needs,
        sufficiency=case_row.label.sufficiency,
        cve_rules=cve_rules,
        technique_rules=technique_rules,
    )


def load_gold_file(gold_bytes: bytes) -> GoldFile:
    """The labelled cases of an M7b gold file. Raises ``GoldFileError`` for a file over
    ``MAX_GOLD_FILE_BYTES``, one a strict loader refuses, a row that breaks the shape, a
    rule the engine does not read, or two cases with one ID."""
    if len(gold_bytes) > MAX_GOLD_FILE_BYTES:
        raise GoldFileError(f"the gold file is larger than {MAX_GOLD_FILE_BYTES} bytes")
    try:
        gold_document = load_strict_yaml(gold_bytes.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        raise GoldFileError("the gold file is not UTF-8 YAML a strict loader accepts") from None
    try:
        gold_row = GoldFileRow.model_validate(gold_document)
    except ValidationError as error:
        problems = "; ".join(bound_violations(list_validation_problems(error)))
        raise GoldFileError(f"the gold file breaks its shape: {problems}") from None
    cases: list[LabelledCase] = []
    case_ids: set[str] = set()
    for position, case_row in enumerate(gold_row.cases, start=1):
        if case_row.id in case_ids:
            raise GoldFileError(f"case {position} repeats an earlier case's ID")
        case_ids.add(case_row.id)
        cases.append(read_case(case_row, position))
    return GoldFile(
        corpus_content_sha256=gold_row.corpus_content_sha256,
        fight_snapshot_sha256=gold_row.fight_snapshot_sha256,
        cases=tuple(cases),
    )
