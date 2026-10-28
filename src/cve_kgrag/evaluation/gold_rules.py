"""The rules of an M7b gold case (``docs/rebuild/m7b-gold-labels.md``): data a script
evaluates over the store's CVE records and the FiGHT snapshot's techniques, never prose.

A rule is a mapping with exactly one key: a predicate or a combinator (``all_of``,
``any_of``, ``none_of``) over a list of rules. CVE rules and technique rules have their own
predicates and never mix. Terms match case-insensitively as whole words, where a word
boundary is any character other than an ASCII letter or digit, so ``Nausf`` matches in
``Nausf_UEAuthentication`` and ``SEAF`` in ``seaf-server``.
"""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import partial
from typing import Generic, Protocol, TypeVar

from cve_kgrag.domain.cve import CVE_ID_PATTERN, MAX_CVE_ID_CHARS, CveRecord
from cve_kgrag.domain.threat_context import FIGHT_TECHNIQUE_ID_PATTERN

MAX_RULE_DEPTH = 8
MAX_RULE_VALUES = 200
MAX_RULE_VALUE_CHARS = 300

# The narrative fields of a FiGHT technique. FiGHT names telecom functions mostly in
# procedure examples and addendums; mitigations and references describe other objects,
# so their words never make a technique match.
TECHNIQUE_TEXT_FIELDS = (
    "name",
    "description",
    "bluf",
    "addendums",
    "procedureexamples",
    "preconditions",
    "postconditions",
)


class GoldRuleError(ValueError):
    """A rule is not one this engine reads; the message names the problem, never the
    rule's text."""


@dataclass(frozen=True)
class CveSubject:
    """What CVE rules read of a record: its English descriptions, the vendor and product
    of each affected product (lower case), its reference URLs (lower case) and whether
    KEV lists it."""

    subject_id: str
    text: str
    products: frozenset[tuple[str, str]]
    reference_urls: tuple[str, ...]
    is_kev: bool

    @classmethod
    def from_record(cls, record: CveRecord) -> "CveSubject":
        english_texts: list[str] = []
        for description in record.descriptions:
            if description.lang.casefold().startswith("en"):
                english_texts.append(description.value)
        products: set[tuple[str, str]] = set()
        for affected_product in record.affected:
            products.add((affected_product.vendor.casefold(), affected_product.product.casefold()))
        reference_urls: list[str] = []
        for reference in record.references:
            reference_urls.append(reference.url.casefold())
        return cls(
            subject_id=record.cve_id,
            text="\n".join(english_texts),
            products=frozenset(products),
            reference_urls=tuple(reference_urls),
            is_kev=record.kev is not None,
        )


@dataclass(frozen=True)
class TechniqueSubject:
    """What technique rules read of a FiGHT technique: its ID and narrative text."""

    subject_id: str
    text: str


def collect_texts(value: object, texts: list[str]) -> None:
    """Every string in ``value``, a YAML scalar, list or mapping, in document order."""
    if isinstance(value, str):
        texts.append(value)
    elif isinstance(value, list):
        for item in value:
            collect_texts(item, texts)
    elif isinstance(value, dict):
        for item in value.values():
            collect_texts(item, texts)


def build_technique_subject(technique: Mapping[str, object]) -> TechniqueSubject:
    """The subject of one technique entry of a FiGHT snapshot."""
    technique_id = technique.get("id")
    if not isinstance(technique_id, str) or not re.fullmatch(
        FIGHT_TECHNIQUE_ID_PATTERN, technique_id
    ):
        raise GoldRuleError("the FiGHT snapshot holds a technique without a valid ID")
    texts: list[str] = []
    for field in TECHNIQUE_TEXT_FIELDS:
        collect_texts(technique.get(field), texts)
    return TechniqueSubject(subject_id=technique_id, text="\n".join(texts))


SubjectT = TypeVar("SubjectT", CveSubject, TechniqueSubject)
SubjectT_contra = TypeVar("SubjectT_contra", CveSubject, TechniqueSubject, contravariant=True)


class Rule(Protocol[SubjectT_contra]):
    def matches(self, subject: SubjectT_contra) -> bool: ...


@dataclass(frozen=True)
class AllOf(Generic[SubjectT]):
    parts: tuple[Rule[SubjectT], ...]

    def matches(self, subject: SubjectT) -> bool:
        return all(part.matches(subject) for part in self.parts)


@dataclass(frozen=True)
class AnyOf(Generic[SubjectT]):
    parts: tuple[Rule[SubjectT], ...]

    def matches(self, subject: SubjectT) -> bool:
        return any(part.matches(subject) for part in self.parts)


@dataclass(frozen=True)
class NoneOf(Generic[SubjectT]):
    parts: tuple[Rule[SubjectT], ...]

    def matches(self, subject: SubjectT) -> bool:
        return not any(part.matches(subject) for part in self.parts)


@dataclass(frozen=True)
class TermsRule:
    """Whole-word terms in the subject's text: any of them, or all of them."""

    patterns: tuple[re.Pattern[str], ...]
    require_all: bool

    def matches(self, subject: CveSubject | TechniqueSubject) -> bool:
        if self.require_all:
            return all(pattern.search(subject.text) for pattern in self.patterns)
        return any(pattern.search(subject.text) for pattern in self.patterns)


@dataclass(frozen=True)
class IdsRule:
    """An explicit list of IDs, each with its reason."""

    ids: frozenset[str]
    reasons: Mapping[str, str]

    def matches(self, subject: CveSubject | TechniqueSubject) -> bool:
        return subject.subject_id in self.ids


@dataclass(frozen=True)
class CpeRule:
    products: frozenset[tuple[str, str]]

    def matches(self, subject: CveSubject) -> bool:
        return not self.products.isdisjoint(subject.products)


@dataclass(frozen=True)
class CpeVendorRule:
    vendors: frozenset[str]

    def matches(self, subject: CveSubject) -> bool:
        return any(vendor in self.vendors for vendor, _ in subject.products)


@dataclass(frozen=True)
class ReferenceRule:
    fragments: tuple[str, ...]

    def matches(self, subject: CveSubject) -> bool:
        return any(
            fragment in reference_url
            for reference_url in subject.reference_urls
            for fragment in self.fragments
        )


@dataclass(frozen=True)
class KevRule:
    is_kev: bool

    def matches(self, subject: CveSubject) -> bool:
        return subject.is_kev == self.is_kev


def read_values(argument: object) -> tuple[str, ...]:
    """A predicate's list of distinct, non-empty strings."""
    if not isinstance(argument, list) or not 1 <= len(argument) <= MAX_RULE_VALUES:
        raise GoldRuleError(f"a predicate needs a list of 1 to {MAX_RULE_VALUES} values")
    values: list[str] = []
    for value in argument:
        if not isinstance(value, str) or not value.strip() or len(value) > MAX_RULE_VALUE_CHARS:
            raise GoldRuleError("a predicate value is not a non-empty string")
        if value in values:
            raise GoldRuleError("a predicate lists a value twice")
        values.append(value)
    return tuple(values)


def compile_term(term: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![A-Za-z0-9]){re.escape(term)}(?![A-Za-z0-9])", re.IGNORECASE)


def build_terms_rule(argument: object, require_all: bool) -> TermsRule:
    patterns: list[re.Pattern[str]] = []
    for term in read_values(argument):
        patterns.append(compile_term(term))
    return TermsRule(patterns=tuple(patterns), require_all=require_all)


def build_ids_rule(argument: object, id_pattern: str) -> IdsRule:
    """``{ids: [...], reasons: {id: reason}}``: distinct well-formed IDs, each with a
    non-empty reason and no reason for an ID the list does not hold."""
    if not isinstance(argument, dict) or set(argument) != {"ids", "reasons"}:
        raise GoldRuleError("an ID list needs exactly ids and reasons")
    ids = read_values(argument["ids"])
    for subject_id in ids:
        # No CVE or technique ID is longer than a CVE ID may be.
        if len(subject_id) > MAX_CVE_ID_CHARS or not re.fullmatch(id_pattern, subject_id):
            raise GoldRuleError("an ID list holds a malformed ID")
    reasons = argument["reasons"]
    if not isinstance(reasons, dict) or set(reasons) != set(ids):
        raise GoldRuleError("an ID list needs one reason for each ID and no other")
    for reason in reasons.values():
        if not isinstance(reason, str) or not reason.strip():
            raise GoldRuleError("an ID list holds an empty reason")
    return IdsRule(ids=frozenset(ids), reasons=dict(reasons))


def build_cpe_rule(argument: object) -> CpeRule:
    products: set[tuple[str, str]] = set()
    for pair in read_values(argument):
        vendor, separator, product = pair.casefold().partition(":")
        if not separator or not vendor or not product or ":" in product:
            raise GoldRuleError("a cpe value is not vendor:product")
        products.add((vendor, product))
    return CpeRule(products=frozenset(products))


def build_cpe_vendor_rule(argument: object) -> CpeVendorRule:
    vendors: set[str] = set()
    for vendor in read_values(argument):
        vendors.add(vendor.casefold())
    return CpeVendorRule(vendors=frozenset(vendors))


def build_reference_rule(argument: object) -> ReferenceRule:
    fragments: list[str] = []
    for fragment in read_values(argument):
        fragments.append(fragment.casefold())
    return ReferenceRule(fragments=tuple(fragments))


def build_kev_rule(argument: object) -> KevRule:
    if not isinstance(argument, bool):
        raise GoldRuleError("kev needs true or false")
    return KevRule(is_kev=argument)


PredicateBuilder = Callable[[object], Rule[SubjectT]]

CVE_PREDICATES: dict[str, PredicateBuilder[CveSubject]] = {
    "cpe": build_cpe_rule,
    "cpe_vendor": build_cpe_vendor_rule,
    "description_any": partial(build_terms_rule, require_all=False),
    "description_all": partial(build_terms_rule, require_all=True),
    "reference_contains": build_reference_rule,
    "cve_ids": partial(build_ids_rule, id_pattern=CVE_ID_PATTERN),
    "kev": build_kev_rule,
}
TECHNIQUE_PREDICATES: dict[str, PredicateBuilder[TechniqueSubject]] = {
    "technique_any": partial(build_terms_rule, require_all=False),
    "technique_ids": partial(build_ids_rule, id_pattern=FIGHT_TECHNIQUE_ID_PATTERN),
}


def parse_rule(
    node: object, predicates: Mapping[str, PredicateBuilder[SubjectT]], depth: int = 1
) -> Rule[SubjectT]:
    """The rule ``node`` states, over the subjects ``predicates`` read. Raises
    ``GoldRuleError`` for anything else."""
    if depth > MAX_RULE_DEPTH:
        raise GoldRuleError(f"a rule nests deeper than {MAX_RULE_DEPTH} levels")
    if not isinstance(node, dict) or len(node) != 1:
        raise GoldRuleError("a rule is not a mapping with exactly one key")
    ((kind, argument),) = node.items()
    if kind in ("all_of", "any_of", "none_of"):
        if not isinstance(argument, list) or not argument:
            raise GoldRuleError(f"{kind} needs a non-empty list of rules")
        parts: list[Rule[SubjectT]] = []
        for part in argument:
            parts.append(parse_rule(part, predicates, depth + 1))
        if kind == "all_of":
            return AllOf(tuple(parts))
        if kind == "any_of":
            return AnyOf(tuple(parts))
        return NoneOf(tuple(parts))
    build_predicate = predicates.get(kind) if isinstance(kind, str) else None
    if build_predicate is None:
        raise GoldRuleError("a rule uses a predicate this kind of rule does not have")
    return build_predicate(argument)
