"""Registry of reviewed protocol topics and the resolution of query terms to them.

Resolution rules, per topic:

- the canonical name or an exact alias anywhere in the query resolves the topic,
  and every span they cover counts as part of the match;
- otherwise a contextual alias resolves it when one of its context terms appears
  elsewhere in the query, unless the alias sits inside a longer excluded phrase
  (``aka`` inside ``EAP-AKA'``);
- an excluded term that the query uses outside a resolving match is reported with
  its reason, so a bare ``aka`` explains why nothing resolved;
- when several topics match, exact matches come before contextual ones and the
  longer matched name before the shorter, so ``5G-AKA`` and ``5gaka`` outrank a
  broader ``5G`` topic.
"""

from collections.abc import Iterable
from dataclasses import dataclass

from vulnwitness.domain.hashing import canonical_sha256
from vulnwitness.domain.search import MAX_QUERY_CHARS
from vulnwitness.domain.text import list_query_terms, mentions_cve_id_token, normalize_query
from vulnwitness.domain.topic import (
    ExcludedTerm,
    ProtocolTopic,
    RegisteredTopic,
    TopicExclusion,
    TopicMatch,
    TopicMatchKind,
    TopicResolution,
)
from vulnwitness.topics.normalization import (
    TermSpan,
    alias_key,
    find_spans,
    has_hard_separator,
    split_terms,
)


class TopicRegistryError(ValueError):
    """Topic cards contradict each other or themselves; no registry is built."""


def list_exact_names(topic: ProtocolTopic) -> list[tuple[TopicMatchKind, str]]:
    exact_names: list[tuple[TopicMatchKind, str]] = [
        (TopicMatchKind.CANONICAL_NAME, topic.canonical_name)
    ]
    for exact_alias in topic.exact_aliases:
        exact_names.append((TopicMatchKind.EXACT_ALIAS, exact_alias))
    return exact_names


def list_matched_terms(topic: ProtocolTopic) -> list[tuple[str, str]]:
    """Every card term that is matched against text, with the field it belongs to."""
    card_terms: list[tuple[str, str]] = []
    for _, exact_name in list_exact_names(topic):
        card_terms.append(("alias", exact_name))
    for contextual_alias in topic.contextual_aliases:
        card_terms.append(("contextual alias", contextual_alias.alias))
        for context_term in contextual_alias.requires_any:
            card_terms.append(("context term", context_term))
    for exclusion in topic.exclusions:
        card_terms.append(("exclusion", exclusion.term))
    for entity in topic.entities:
        card_terms.append(("entity", entity.name))
    for ecosystem_term in topic.ecosystem_terms:
        card_terms.append(("ecosystem term", ecosystem_term))
    return card_terms


def find_card_violations(topic: ProtocolTopic) -> list[str]:
    violations: list[str] = []
    for field_name, card_term in list_matched_terms(topic):
        if not alias_key(card_term):
            violations.append(f"{topic.topic_id}: {field_name} {card_term!r} has no word")
        elif has_hard_separator(card_term):
            violations.append(
                f"{topic.topic_id}: {field_name} {card_term!r} spans punctuation that "
                "matching treats as a boundary"
            )
    exact_keys: set[str] = set()
    for _, exact_name in list_exact_names(topic):
        exact_keys.add(alias_key(exact_name))
    contextual_keys: set[str] = set()
    for contextual_alias in topic.contextual_aliases:
        contextual_keys.add(alias_key(contextual_alias.alias))
    for exclusion in topic.exclusions:
        if alias_key(exclusion.term) in exact_keys | contextual_keys:
            violations.append(f"{topic.topic_id}: {exclusion.term!r} is both an alias and excluded")
    for contextual_alias in topic.contextual_aliases:
        if alias_key(contextual_alias.alias) in exact_keys:
            violations.append(
                f"{topic.topic_id}: {contextual_alias.alias!r} is both exact and contextual"
            )
    corroborating_keys: dict[str, str] = {}
    for corroborating_term in list_corroborating_terms(topic):
        first_spelling = corroborating_keys.setdefault(
            alias_key(corroborating_term), corroborating_term
        )
        if first_spelling != corroborating_term:
            violations.append(
                f"{topic.topic_id}: {first_spelling!r} and {corroborating_term!r} are one term"
            )
    for query_template in topic.query_templates:
        # A template is a CVE search's query, so it needs a search term that search
        # reads: one of only stopwords or low-signal words would find nothing.
        if len(query_template) > MAX_QUERY_CHARS or not list_query_terms(query_template):
            violations.append(
                f"{topic.topic_id}: query template {query_template[:40]!r} must hold searchable "
                f"terms within {MAX_QUERY_CHARS} characters"
            )
        if mentions_cve_id_token(query_template):
            violations.append(f"{topic.topic_id}: query template names a CVE ID")
    return violations


def list_corroborating_terms(topic: ProtocolTopic) -> list[str]:
    """Entity names and ecosystem terms: each must be a distinct term for relevance."""
    corroborating_terms: list[str] = []
    for entity in topic.entities:
        corroborating_terms.append(entity.name)
    corroborating_terms.extend(topic.ecosystem_terms)
    return corroborating_terms


def is_inside_longer_span(span: TermSpan, enclosing_spans: list[TermSpan]) -> bool:
    for enclosing_span in enclosing_spans:
        is_longer = enclosing_span.end - enclosing_span.start > span.end - span.start
        if is_longer and enclosing_span.start <= span.start and span.end <= enclosing_span.end:
            return True
    return False


def overlaps_any(span: TermSpan, other_spans: list[TermSpan]) -> bool:
    return any(span.overlaps(other_span) for other_span in other_spans)


@dataclass(frozen=True)
class RankedMatch:
    """A match with what orders it: exact before contextual, then the longer matched name.

    Length is that of the name's key, not its word count, so ``5gaka`` ranks like
    ``5G-AKA``.
    """

    match: TopicMatch
    is_contextual: bool
    key_length: int

    def sort_key(self) -> tuple[bool, int, str]:
        return (self.is_contextual, -self.key_length, self.match.topic_id)


class TopicRegistry:
    """Read-only after construction; rejects duplicate IDs and contradictory cards."""

    def __init__(self, topics: Iterable[ProtocolTopic]) -> None:
        violations: list[str] = []
        self._topics_by_id: dict[str, RegisteredTopic] = {}
        exact_owner_by_key: dict[str, str] = {}
        contextual_owners: list[tuple[str, str, str]] = []
        for topic in sorted(topics, key=lambda card: card.topic_id):
            if topic.topic_id in self._topics_by_id:
                violations.append(f"duplicate topic {topic.topic_id}")
            violations.extend(find_card_violations(topic))
            for _, exact_name in list_exact_names(topic):
                owner_id = exact_owner_by_key.setdefault(alias_key(exact_name), topic.topic_id)
                if owner_id != topic.topic_id:
                    violations.append(f"{exact_name!r} names both {owner_id} and {topic.topic_id}")
            for contextual_alias in topic.contextual_aliases:
                contextual_owners.append(
                    (alias_key(contextual_alias.alias), contextual_alias.alias, topic.topic_id)
                )
            self._topics_by_id[topic.topic_id] = RegisteredTopic(
                topic=topic, content_sha256=canonical_sha256(topic.model_dump(mode="json"))
            )
        for contextual_key, contextual_name, topic_id in contextual_owners:
            exact_owner = exact_owner_by_key.get(contextual_key)
            if exact_owner is not None and exact_owner != topic_id:
                violations.append(
                    f"{contextual_name!r} is contextual for {topic_id} but exact for {exact_owner}"
                )
        if violations:
            raise TopicRegistryError("; ".join(violations))

    def get_topic(self, topic_id: str) -> RegisteredTopic | None:
        return self._topics_by_id.get(topic_id)

    def require_topic(self, topic_id: str) -> ProtocolTopic:
        """The card of ``topic_id``; raises ``LookupError`` when no such card is registered."""
        registered_topic = self._topics_by_id.get(topic_id)
        if registered_topic is None:
            raise LookupError(f"{topic_id} is not a registered topic")
        return registered_topic.topic

    def list_topics(self) -> tuple[RegisteredTopic, ...]:
        return tuple(self._topics_by_id.values())

    def resolve(self, query: str) -> TopicResolution:
        """Matches ordered exact before contextual, then by longer span, then by topic ID."""
        terms = split_terms(query)
        ranked_matches: list[RankedMatch] = []
        excluded_terms: list[ExcludedTerm] = []
        for registered_topic in self._topics_by_id.values():
            ranked_match, matched_spans = self._match_topic(registered_topic, terms)
            if ranked_match is not None:
                ranked_matches.append(ranked_match)
            excluded_terms.extend(self._find_excluded_terms(registered_topic, terms, matched_spans))
        ranked_matches.sort(key=lambda ranked: ranked.sort_key())
        matches: list[TopicMatch] = []
        for ranked_match in ranked_matches:
            matches.append(ranked_match.match)
        return TopicResolution(
            normalized_query=normalize_query(query),
            matches=tuple(matches),
            excluded_terms=tuple(excluded_terms),
        )

    def _match_topic(
        self, registered_topic: RegisteredTopic, terms: list[str]
    ) -> tuple[RankedMatch | None, list[TermSpan]]:
        """The topic's match and every span it covers (all exact names, or the contextual one)."""
        topic = registered_topic.topic
        exact_spans: list[TermSpan] = []
        first_exact: tuple[TopicMatchKind, str] | None = None
        longest_key = 0
        for match_kind, exact_name in list_exact_names(topic):
            name_key = alias_key(exact_name)
            name_spans = find_spans(terms, name_key)
            if not name_spans:
                continue
            if first_exact is None:
                first_exact = (match_kind, exact_name)
            longest_key = max(longest_key, len(name_key))
            exact_spans.extend(name_spans)
        if first_exact is not None:
            match = self._build_match(registered_topic, first_exact[0], first_exact[1], ())
            return RankedMatch(match, is_contextual=False, key_length=longest_key), exact_spans

        exclusion_spans: list[TermSpan] = []
        for exclusion in topic.exclusions:
            exclusion_spans.extend(find_spans(terms, alias_key(exclusion.term)))
        for contextual_alias in topic.contextual_aliases:
            for alias_span in find_spans(terms, alias_key(contextual_alias.alias)):
                if is_inside_longer_span(alias_span, exclusion_spans):
                    continue
                context_terms: list[str] = []
                for context_term in contextual_alias.requires_any:
                    context_spans = find_spans(terms, alias_key(context_term))
                    if any(not span.overlaps(alias_span) for span in context_spans):
                        context_terms.append(context_term)
                if context_terms:
                    match = self._build_match(
                        registered_topic,
                        TopicMatchKind.CONTEXTUAL_ALIAS,
                        contextual_alias.alias,
                        tuple(context_terms),
                    )
                    key_length = len(alias_key(contextual_alias.alias))
                    return RankedMatch(match, is_contextual=True, key_length=key_length), [
                        alias_span
                    ]
        return None, []

    def _build_match(
        self,
        registered_topic: RegisteredTopic,
        match_kind: TopicMatchKind,
        matched_alias: str,
        context_terms: tuple[str, ...],
    ) -> TopicMatch:
        topic = registered_topic.topic
        return TopicMatch(
            topic_id=topic.topic_id,
            topic_version=topic.version,
            topic_sha256=registered_topic.content_sha256,
            review_status=topic.review.status,
            match_kind=match_kind,
            matched_alias=matched_alias,
            context_terms=context_terms,
        )

    def _find_excluded_terms(
        self, registered_topic: RegisteredTopic, terms: list[str], matched_spans: list[TermSpan]
    ) -> list[ExcludedTerm]:
        """Excluded terms used outside a match, each reported once, longest phrase only."""
        topic = registered_topic.topic
        exclusion_hits: list[tuple[TermSpan, TopicExclusion]] = []
        exclusion_spans: list[TermSpan] = []
        for exclusion in topic.exclusions:
            for exclusion_span in find_spans(terms, alias_key(exclusion.term)):
                exclusion_hits.append((exclusion_span, exclusion))
                exclusion_spans.append(exclusion_span)
        excluded_terms: list[ExcludedTerm] = []
        for exclusion_span, exclusion in exclusion_hits:
            if overlaps_any(exclusion_span, matched_spans):
                continue
            if is_inside_longer_span(exclusion_span, exclusion_spans):
                continue
            excluded_term = ExcludedTerm(
                topic_id=topic.topic_id, term=exclusion.term, reason=exclusion.reason
            )
            if excluded_term not in excluded_terms:
                excluded_terms.append(excluded_term)
        return excluded_terms
