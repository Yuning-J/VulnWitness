"""Derive each M7b gold case's sets from its rules, and write them as canonical JSON
(``docs/rebuild/m7b-gold-labels.md``).

The sets file is generated, never edited: ``cve-kgrag eval gold-sets --check`` derives the
sets again and compares the bytes, so a gold file never scores against data its sets were
not derived from.
"""

import json
from collections.abc import Iterable
from dataclasses import dataclass

import yaml

from cve_kgrag.adapters.strict_yaml import load_strict_yaml
from cve_kgrag.domain.cve import CveRecord
from cve_kgrag.evaluation.gold_cases import GoldFileError
from cve_kgrag.evaluation.gold_rules import (
    CveSubject,
    GoldRuleError,
    Rule,
    SubjectT,
    TechniqueSubject,
    build_technique_subject,
)
from cve_kgrag.evaluation.labelled_cases import (
    CATEGORY_SUBJECTS,
    GoldFile,
    LabelledCase,
    SetName,
    SubjectKind,
    Sufficiency,
)


@dataclass(frozen=True)
class DerivedSets:
    """One subject kind's sets for a case. ``allowed`` is relevant minus required;
    ``wide_check`` is ``None`` when the case has no wide check."""

    required: tuple[str, ...]
    allowed: tuple[str, ...]
    irrelevant: tuple[str, ...]
    wide_check: tuple[str, ...] | None


def read_technique_subjects(snapshot_bytes: bytes) -> tuple[TechniqueSubject, ...]:
    """The techniques of a FiGHT snapshot the catalog lists, which the caller has checked
    against its pin. Raises ``GoldRuleError`` for a file that is not one."""
    try:
        document = load_strict_yaml(snapshot_bytes.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        raise GoldRuleError("the FiGHT snapshot is not UTF-8 strict YAML") from None
    techniques = document.get("techniques") if isinstance(document, dict) else None
    if not isinstance(techniques, list):
        raise GoldRuleError("the FiGHT snapshot holds no techniques list")
    subjects: list[TechniqueSubject] = []
    for technique in techniques:
        if not isinstance(technique, dict):
            raise GoldRuleError("the FiGHT snapshot holds a technique that is not a mapping")
        subjects.append(build_technique_subject(technique))
    return tuple(subjects)


def start_matches(set_rules: dict[SetName, Rule[SubjectT]]) -> dict[SetName, set[str]]:
    """An empty match set for each set the rules name."""
    matched_ids: dict[SetName, set[str]] = {}
    for set_name in set_rules:
        matched_ids[set_name] = set()
    return matched_ids


def match_subjects(
    set_rules: dict[SetName, Rule[SubjectT]], subjects: Iterable[SubjectT]
) -> dict[SetName, set[str]]:
    matched_ids = start_matches(set_rules)
    for subject in subjects:
        for set_name, rule in set_rules.items():
            if rule.matches(subject):
                matched_ids[set_name].add(subject.subject_id)
    return matched_ids


def build_derived_sets(matched_ids: dict[SetName, set[str]], case_id: str) -> DerivedSets:
    """The sets the rules matched; raises ``GoldFileError`` when required is not within
    relevant or irrelevant overlaps it."""
    relevant = matched_ids.get(SetName.RELEVANT, set())
    required = matched_ids.get(SetName.REQUIRED, set())
    irrelevant = matched_ids.get(SetName.IRRELEVANT, set())
    if not required <= relevant:
        raise GoldFileError(f"case {case_id}: required holds an item relevant does not")
    if not irrelevant.isdisjoint(relevant):
        raise GoldFileError(f"case {case_id}: irrelevant overlaps relevant")
    wide_check = matched_ids.get(SetName.WIDE_CHECK)
    return DerivedSets(
        required=tuple(sorted(required)),
        allowed=tuple(sorted(relevant - required)),
        irrelevant=tuple(sorted(irrelevant)),
        wide_check=tuple(sorted(wide_check)) if wide_check is not None else None,
    )


def check_label(case: LabelledCase, case_sets: dict[SubjectKind, DerivedSets]) -> None:
    """The case label must be what its sets support: ``sufficient`` when every needed
    category has required items, ``partial`` when some do and some do not,
    ``insufficient`` when none do and every wide-check hit is explicitly irrelevant.
    ``uncertain`` is the owner's call and is not checked."""
    has_required: list[bool] = []
    for category in case.needs:
        subject_kind = CATEGORY_SUBJECTS[category]
        has_required.append(subject_kind is not None and bool(case_sets[subject_kind].required))
    if case.sufficiency is Sufficiency.SUFFICIENT and not all(has_required):
        raise GoldFileError(f"case {case.case_id}: sufficient, but a needed category has none")
    if case.sufficiency is Sufficiency.PARTIAL and (all(has_required) or not any(has_required)):
        raise GoldFileError(
            f"case {case.case_id}: partial needs one needed category with required items "
            "and one without"
        )
    if case.sufficiency is Sufficiency.INSUFFICIENT:
        if any(has_required):
            raise GoldFileError(f"case {case.case_id}: insufficient, but has required items")
        for derived_sets in case_sets.values():
            if derived_sets.wide_check is None:
                raise GoldFileError(f"case {case.case_id}: insufficient without a wide check")
            if not set(derived_sets.wide_check) <= set(derived_sets.irrelevant):
                raise GoldFileError(
                    f"case {case.case_id}: insufficient, but its wide check found items "
                    "not marked irrelevant"
                )


class GoldSetCollector:
    """Matches each CVE record against every case's CVE rules as a store is read, so the
    store is never held in memory; ``derive`` then adds the techniques and checks each
    case."""

    def __init__(self, gold_file: GoldFile) -> None:
        self._gold_file = gold_file
        self._cve_matches: dict[str, dict[SetName, set[str]]] = {}
        for case in gold_file.cases:
            if case.cve_rules is not None:
                self._cve_matches[case.case_id] = start_matches(case.cve_rules)

    def keep_record(self, record: CveRecord) -> None:
        subject = CveSubject.from_record(record)
        for case in self._gold_file.cases:
            if case.cve_rules is None:
                continue
            case_matches = self._cve_matches[case.case_id]
            for set_name, rule in case.cve_rules.items():
                if rule.matches(subject):
                    case_matches[set_name].add(subject.subject_id)

    def derive(
        self, techniques: tuple[TechniqueSubject, ...]
    ) -> dict[str, dict[SubjectKind, DerivedSets]]:
        """Every case's sets by subject kind. Raises ``GoldFileError`` for a case whose
        sets break the rules' constraints or do not support its label."""
        gold_sets: dict[str, dict[SubjectKind, DerivedSets]] = {}
        for case in self._gold_file.cases:
            case_sets: dict[SubjectKind, DerivedSets] = {}
            if case.cve_rules is not None:
                case_sets[SubjectKind.CVES] = build_derived_sets(
                    self._cve_matches[case.case_id], case.case_id
                )
            if case.technique_rules is not None:
                case_sets[SubjectKind.TECHNIQUES] = build_derived_sets(
                    match_subjects(case.technique_rules, techniques), case.case_id
                )
            check_label(case, case_sets)
            gold_sets[case.case_id] = case_sets
        return gold_sets


def format_gold_sets(
    gold_file: GoldFile, gold_sets: dict[str, dict[SubjectKind, DerivedSets]]
) -> bytes:
    """The sets file: the corpus and snapshot they were derived from, then each case's
    sets, as JSON with sorted keys and one item per line, so a change reads as a diff."""
    cases: dict[str, dict[str, dict[str, list[str]]]] = {}
    for case_id, case_sets in gold_sets.items():
        kinds: dict[str, dict[str, list[str]]] = {}
        for subject_kind, derived_sets in case_sets.items():
            named_sets = {
                "required": list(derived_sets.required),
                "allowed": list(derived_sets.allowed),
                "irrelevant": list(derived_sets.irrelevant),
            }
            if derived_sets.wide_check is not None:
                named_sets["wide_check"] = list(derived_sets.wide_check)
            kinds[subject_kind.value] = named_sets
        cases[case_id] = kinds
    sets_document = {
        "corpus_content_sha256": gold_file.corpus_content_sha256,
        "fight_snapshot_sha256": gold_file.fight_snapshot_sha256,
        "cases": cases,
    }
    return (json.dumps(sets_document, indent=2, sort_keys=True) + "\n").encode()
