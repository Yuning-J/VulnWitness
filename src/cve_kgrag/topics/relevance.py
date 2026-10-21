"""Relevance tiers of a CVE record to a protocol topic, from the record's own text.

Tiers are checked in order, and the first that applies wins:

1. ``explicit_protocol_mention``: a description names the protocol (canonical
   name or exact alias);
2. ``protocol_component_implementation``: the record names at least two distinct
   topic terms (entities or ecosystem terms), at least one of them an entity;
3. ``telecom_ecosystem_adjacent``: it names at least two distinct ecosystem terms;
4. ``semantic_only``: none of the above, but the semantic channel matched it.

One acronym alone never tiers a record: ``UDM`` is also the UniFi Dream Machine,
``AMF`` the Action Message Format and ``5G`` a Wi-Fi band. A term found only inside
another found term (``5G`` inside ``5G core``) does not count separately. A record
that fits no tier is not relevant to the topic (``None``). A tier says nothing about
the protocol design: every CVE remains an implementation vulnerability.
"""

from collections.abc import Collection

from cve_kgrag.domain.cve import CveRecord
from cve_kgrag.domain.taxonomy import RetrievalChannel
from cve_kgrag.domain.topic import ProtocolTopic, RelevanceAssessment, RelevanceTier
from cve_kgrag.topics.normalization import (
    TERM_BOUNDARY,
    TermSpan,
    alias_key,
    find_spans,
    split_terms,
)

MIN_CORROBORATING_TERMS = 2
TIER_BASIS = {
    RelevanceTier.EXPLICIT_PROTOCOL_MENTION: "a description names the protocol",
    RelevanceTier.PROTOCOL_COMPONENT_IMPLEMENTATION: (
        "the record names protocol entities, corroborated by a second topic term"
    ),
    RelevanceTier.TELECOM_ECOSYSTEM_ADJACENT: (
        "the record names at least two terms of the protocol's ecosystem"
    ),
    RelevanceTier.SEMANTIC_ONLY: "only semantic similarity links the record to the topic",
}


def list_record_terms(record: CveRecord, include_products: bool) -> list[str]:
    record_terms: list[str] = []
    for description in record.descriptions:
        record_terms.extend(split_terms(description.value))
        record_terms.append(TERM_BOUNDARY)
    if include_products:
        for affected_product in record.list_implicated_products():
            record_terms.extend(split_terms(affected_product.vendor))
            record_terms.append(TERM_BOUNDARY)
            record_terms.extend(split_terms(affected_product.product))
            record_terms.append(TERM_BOUNDARY)
    return record_terms


def find_named_terms(record_terms: list[str], card_terms: Collection[str]) -> tuple[str, ...]:
    """Card terms that occur in the record's terms."""
    named_terms: list[str] = []
    for card_term in card_terms:
        if find_spans(record_terms, alias_key(card_term)):
            named_terms.append(card_term)
    return tuple(named_terms)


def find_corroborating_terms(
    record_terms: list[str], card_terms: Collection[str]
) -> tuple[str, ...]:
    """Card terms found at least once outside the span of a longer found card term.

    Spellings that share a key count once, as the first given.
    """
    spans_by_term: dict[str, list[TermSpan]] = {}
    known_keys: set[str] = set()
    for card_term in card_terms:
        term_key = alias_key(card_term)
        if term_key in known_keys:
            continue
        known_keys.add(term_key)
        term_spans = find_spans(record_terms, term_key)
        if term_spans:
            spans_by_term[card_term] = term_spans
    all_spans: list[TermSpan] = []
    for term_spans in spans_by_term.values():
        all_spans.extend(term_spans)
    corroborating_terms: list[str] = []
    for card_term, term_spans in spans_by_term.items():
        if any(not is_inside_longer(span, all_spans) for span in term_spans):
            corroborating_terms.append(card_term)
    return tuple(corroborating_terms)


def is_inside_longer(span: TermSpan, other_spans: list[TermSpan]) -> bool:
    for other_span in other_spans:
        is_longer = other_span.end - other_span.start > span.end - span.start
        if is_longer and other_span.start <= span.start and span.end <= other_span.end:
            return True
    return False


def build_assessment(tier: RelevanceTier, matched_terms: tuple[str, ...]) -> RelevanceAssessment:
    return RelevanceAssessment(tier=tier, matched_terms=matched_terms, basis=TIER_BASIS[tier])


def assess_relevance(
    record: CveRecord, topic: ProtocolTopic, channels: Collection[RetrievalChannel]
) -> RelevanceAssessment | None:
    description_terms = list_record_terms(record, include_products=False)
    protocol_names = find_named_terms(
        description_terms, (topic.canonical_name, *topic.exact_aliases)
    )
    if protocol_names:
        return build_assessment(RelevanceTier.EXPLICIT_PROTOCOL_MENTION, protocol_names)

    record_terms = list_record_terms(record, include_products=True)
    entity_names: list[str] = []
    for entity in topic.entities:
        entity_names.append(entity.name)
    corroborating_terms = find_corroborating_terms(
        record_terms, (*entity_names, *topic.ecosystem_terms)
    )
    named_entities: list[str] = []
    named_ecosystem_terms: list[str] = []
    for corroborating_term in corroborating_terms:
        if corroborating_term in entity_names:
            named_entities.append(corroborating_term)
        else:
            named_ecosystem_terms.append(corroborating_term)
    if named_entities and len(corroborating_terms) >= MIN_CORROBORATING_TERMS:
        return build_assessment(
            RelevanceTier.PROTOCOL_COMPONENT_IMPLEMENTATION, corroborating_terms
        )
    if len(named_ecosystem_terms) >= MIN_CORROBORATING_TERMS:
        return build_assessment(
            RelevanceTier.TELECOM_ECOSYSTEM_ADJACENT, tuple(named_ecosystem_terms)
        )
    if RetrievalChannel.SEMANTIC in channels:
        return build_assessment(RelevanceTier.SEMANTIC_ONLY, ())
    return None
