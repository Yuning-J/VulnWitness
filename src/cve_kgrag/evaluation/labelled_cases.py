"""The M7b gold file (``docs/rebuild/m7b-gold-labels.md``): hand-labelled cases, the rules
that derive each case's sets, and the corpus and FiGHT snapshot the labels were confirmed
against.

A problem is reported by case position and the server's words, never by quoting the file.
"""

from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from cve_kgrag.domain.contract_model import list_validation_problems
from cve_kgrag.domain.evidence import SHA256_PATTERN
from cve_kgrag.domain.evidence_set_verification_report import bound_violations
from cve_kgrag.domain.investigation import InvestigationRequest
from cve_kgrag.evaluation.gold_cases import MAX_GOLD_CASES, GoldFileError, compute_case_sha256
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


class SetRulesRow(BaseModel):
    """One subject kind's rules, by the set each derives; a rule stays raw until
    ``parse_rule`` reads it."""

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    relevant: object = None
    required: object = None
    irrelevant: object = None
    wide_check: object = None

    def list_set_rules(self) -> dict[SetName, object]:
        set_rules: dict[SetName, object] = {}
        for set_name in SetName:
            node = getattr(self, set_name.value)
            if node is not None:
                set_rules[set_name] = node
        return set_rules


class RulesRow(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    cves: SetRulesRow | None = None
    techniques: SetRulesRow | None = None

    def list_subject_kinds(self) -> set[SubjectKind]:
        subject_kinds: set[SubjectKind] = set()
        if self.cves is not None:
            subject_kinds.add(SubjectKind.CVES)
        if self.techniques is not None:
            subject_kinds.add(SubjectKind.TECHNIQUES)
        return subject_kinds


class CaseRow(BaseModel):
    """One case as the file states it."""

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    id: str = Field(pattern=CASE_ID_PATTERN)
    split: Split
    goal: str = Field(min_length=1, max_length=MAX_TEXT_CHARS)
    request: InvestigationRequest
    needs: tuple[EvidenceCategory, ...] = Field(min_length=1)
    rules: RulesRow
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
    subject kind it has rules for, a rule per set it names. ``case_sha256`` names it in the
    report's behaviour sections, as an M7a case is named, with the operator FiGHT source."""

    case_id: str
    case_sha256: str
    split: Split
    request: InvestigationRequest
    needs: tuple[EvidenceCategory, ...]
    sufficiency: Sufficiency
    cve_rules: dict[SetName, Rule[CveSubject]] | None
    technique_rules: dict[SetName, Rule[TechniqueSubject]] | None


@dataclass(frozen=True)
class GoldFile:
    """The labelled cases, the corpus and FiGHT snapshot their labels were confirmed
    against, and ``gold_file_sha256``, the SHA-256 of the file's bytes, which the sets file
    derived from it records."""

    gold_file_sha256: str
    corpus_content_sha256: str
    fight_snapshot_sha256: str
    cases: tuple[LabelledCase, ...]


def check_set_names(set_rules: dict[SetName, object], position: int) -> None:
    if SetName.REQUIRED in set_rules and SetName.RELEVANT not in set_rules:
        raise GoldFileError(f"case {position}: a required rule needs a relevant rule")


def check_needs(case_row: CaseRow, position: int) -> None:
    """Each category once, at most one CVE category, so a run's CVE figures go to exactly
    one, and rules for the subject kind of each category that has evidence."""
    if len(set(case_row.needs)) != len(case_row.needs):
        raise GoldFileError(f"case {position}: needs lists a category twice")
    cve_categories = {EvidenceCategory.NAMED_CVE, EvidenceCategory.IMPLEMENTATION_CVES}
    if cve_categories <= set(case_row.needs):
        raise GoldFileError(f"case {position}: needs both named_cve and implementation_cves")
    subject_kinds = case_row.rules.list_subject_kinds()
    for category in case_row.needs:
        subject_kind = CATEGORY_SUBJECTS[category]
        if subject_kind is not None and subject_kind not in subject_kinds:
            raise GoldFileError(
                f"case {position}: needs {category.value} but has no {subject_kind.value} rules"
            )


def read_case(case_row: CaseRow, position: int) -> LabelledCase:
    check_needs(case_row, position)
    cve_rules: dict[SetName, Rule[CveSubject]] | None = None
    technique_rules: dict[SetName, Rule[TechniqueSubject]] | None = None
    try:
        if case_row.rules.cves is not None:
            cve_set_rules = case_row.rules.cves.list_set_rules()
            check_set_names(cve_set_rules, position)
            cve_rules = {}
            for set_name, node in cve_set_rules.items():
                cve_rules[set_name] = parse_rule(node, CVE_PREDICATES)
        if case_row.rules.techniques is not None:
            technique_set_rules = case_row.rules.techniques.list_set_rules()
            check_set_names(technique_set_rules, position)
            technique_rules = {}
            for set_name, node in technique_set_rules.items():
                technique_rules[set_name] = parse_rule(node, TECHNIQUE_PREDICATES)
    except GoldRuleError as error:
        raise GoldFileError(f"case {position}: {error}") from None
    return LabelledCase(
        case_id=case_row.id,
        case_sha256=compute_case_sha256(case_row.request, "operator"),
        split=case_row.split,
        request=case_row.request,
        needs=case_row.needs,
        sufficiency=case_row.label.sufficiency,
        cve_rules=cve_rules,
        technique_rules=technique_rules,
    )


def read_gold_file(gold_document: object, gold_file_sha256: str) -> GoldFile:
    """The labelled cases of an M7b gold file, as ``read_gold_document`` parsed it from
    the bytes whose SHA-256 is ``gold_file_sha256``. Raises ``GoldFileError`` for a row
    that breaks the shape, a rule the engine does not read, or two cases with one ID or
    one ``case_sha256``."""
    try:
        gold_row = GoldFileRow.model_validate(gold_document)
    except ValidationError as error:
        problems = "; ".join(bound_violations(list_validation_problems(error)))
        raise GoldFileError(f"the gold file breaks its shape: {problems}") from None
    cases: list[LabelledCase] = []
    case_ids: set[str] = set()
    case_hashes: set[str] = set()
    for position, case_row in enumerate(gold_row.cases, start=1):
        if case_row.id in case_ids:
            raise GoldFileError(f"case {position} repeats an earlier case's ID")
        case = read_case(case_row, position)
        if case.case_sha256 in case_hashes:
            raise GoldFileError(f"case {position} repeats an earlier case's request")
        case_ids.add(case_row.id)
        case_hashes.add(case.case_sha256)
        cases.append(case)
    return GoldFile(
        gold_file_sha256=gold_file_sha256,
        corpus_content_sha256=gold_row.corpus_content_sha256,
        fight_snapshot_sha256=gold_row.fight_snapshot_sha256,
        cases=tuple(cases),
    )
