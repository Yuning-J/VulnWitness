"""The deterministic investigation policy (version ``m7b.6``): pure functions of the
request, its interpretation and the observed steps.

The policy reads a query into an intent, decides whether the query can be answered
at all under the requested scope, plans round 1 by intent and scope, and proposes at
most one refinement from what round 1 observed. It never invents a CVE ID or a
search term: every call it plans uses the caller's IDs, the caller's terms or the
resolved topic card.

Round 1, by intent and scope:

- an exact CVE ID is looked up directly, never expanded into a topic;
- a resolved topic is explored with ``topic_context`` in every scope; under
  ``implementation_only`` the call fans out to the card's CVE searches only, never to
  FiGHT (``count_tool_calls``);
- free text is searched under ``implementation_only``, with recognized product
  versions kept out of lexical terms and an auxiliary exact product read when
  recognition is unambiguous; under
  ``protocol_context_only`` its words are searched in FiGHT directly
  (``fight_direct_search``), and under ``mixed`` both, the CVE search first, when the
  words may go to FiGHT (``find_fight_block``), else only the CVE search. The product
  read adds one call only when the base plan leaves room in the call budget.

Refinement, at most one call, never one round 1 already issued, and only for an
implementation or protocol need round 1 left open (``domain/evidence_needs.py``); a named
CVE no lookup found is met by no other call:

- R1: every ID of a round-1 exact lookup is unknown and the resolved topic names a
  further target, so explore the topic;
- R2: an implementation or protocol need is open and the resolved topic was not
  explored, so explore it (``topic_after_literal_miss`` when a literal search of a topic
  query, which only a model's plan issues, did not meet the need; ``topic_for_open_need``
  otherwise);
- R3: the implementation need is open and round 1's searches did not send every search
  term, none of which is an unexplained unindexed term, so search all of them.

No rule plans ``fight_direct_search``: round 1 already plans it wherever it may run, and a
run holds at most one.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import assert_never

from vulnwitness.application.product_recognition import (
    find_question_phrases,
    is_unqualified_network_function,
    recognize_product,
    remove_recognized_versions,
)
from vulnwitness.domain.cve import MAX_CVE_ID_CHARS
from vulnwitness.domain.evidence_catalog import EvidenceCatalog
from vulnwitness.domain.evidence_needs import (
    is_need_open,
    list_searched_terms,
    list_unexplained_unindexed_terms,
)
from vulnwitness.domain.investigation import (
    DecisionBasis,
    EvidenceNeed,
    EvidenceNeedKind,
    FightBlock,
    FightBlockReason,
    Interpretation,
    InvestigationRequest,
    StepReason,
    StopReason,
    ToolStep,
    list_version_mentions,
)
from vulnwitness.domain.planning import (
    CveExactLookupCall,
    CveSearchCall,
    DeterministicPlannerIdentity,
    FightDirectSearchCall,
    PlannerKind,
    ProductQueryCall,
    QueryIntent,
    ToolCall,
    ToolName,
    TopicContextCall,
    compute_call_key,
)
from vulnwitness.domain.search import MAX_QUERY_CHARS, SearchWarningCode
from vulnwitness.domain.text import (
    asks_affectedness,
    find_cve_ids,
    find_version_mentions,
    list_query_terms,
    mentions_cve_id_token,
    normalize_query,
    remove_cve_id_tokens,
    tokenize,
)
from vulnwitness.domain.topic import ProtocolTopic
from vulnwitness.domain.topic_context import QueryScope
from vulnwitness.topics.registry import TopicRegistry

DETERMINISTIC_POLICY_VERSION = "m7b.6"
# An exact lookup or a CVE search is one backend query.
CVE_TOOL_COST = 1
# A direct FiGHT search is one backend query.
FIGHT_DIRECT_SEARCH_COST = 1


@dataclass(frozen=True)
class PlannedStep:
    call: ToolCall
    reason: StepReason


def list_calls(planned_steps: Sequence[PlannedStep]) -> list[ToolCall]:
    calls: list[ToolCall] = []
    for planned_step in planned_steps:
        calls.append(planned_step.call)
    return calls


def list_search_terms(query: str, excluded_tokens: set[str]) -> tuple[str, ...]:
    """The query's search terms (``list_query_terms``: no CVE-ID token or likeness,
    stopword or low-signal word) without excluded-term tokens, each once, in query order.

    CVE-ID tokens are found in ``query`` as written, by the same rule that finds its IDs,
    so a character NFKC would expand into digits (``¼``) cannot split a digit off one.
    They are found again in the joined terms, until none is left: dropping an excluded
    token, or a term past the length limit, can bring a word ending in ``cve`` and two
    numbers together (``crash nvdcve EPS AKA 2021 2022``), and the plan gate rejects
    search text holding a CVE-ID token, the policy's own search included.

    A token is skipped when it would push the joined search text past
    ``MAX_QUERY_CHARS``: NFKC normalization can lengthen a query (``ﬃ`` becomes
    ``ffi``), and a search request never exceeds the caller's own limit.
    """
    search_terms: list[str] = []
    search_text_length = 0
    for token in list_query_terms(query):
        if token in excluded_tokens or token in search_terms:
            continue
        joined_length = search_text_length + len(token) + (1 if search_terms else 0)
        if joined_length > MAX_QUERY_CHARS:
            continue
        search_terms.append(token)
        search_text_length = joined_length
    search_text = " ".join(search_terms)
    while mentions_cve_id_token(search_text):
        search_text = remove_cve_id_tokens(search_text)
    return tuple(search_text.split())


def list_kept_cve_ids(query: str) -> list[str]:
    """The CVE IDs the query names that the CVE program can assign, in query order: an ID
    longer than ``MAX_CVE_ID_CHARS`` is never assigned, so it is neither looked up nor a
    reason to keep FiGHT from the query's words."""
    kept_cve_ids: list[str] = []
    for cve_id in find_cve_ids(query):
        if len(cve_id) <= MAX_CVE_ID_CHARS:
            kept_cve_ids.append(cve_id)
    return kept_cve_ids


def find_fight_block(query: str, topic_registry: TopicRegistry) -> FightBlock | None:
    """Why the query's search terms may not be sent to FiGHT without a reviewed topic, or
    None when they may: all of them are sent, or none.

    Checked in order: a topic resolved (its card's terms reach FiGHT through
    ``topic_context``); an excluded term is named, which is never stripped and searched
    around (an ASCII run is a registry word of its own beside a non-ASCII letter, so
    ``5Géaka`` names the excluded ``aka``); a CVE ID ``interpret_request`` keeps is
    named, so only a topic is a text target; one of the search terms the registry reads
    alone as a topic or an excluded term, which catches a search term that is not a word
    of the registry's reading (``topics/normalization.py``: the CVE side normalizes
    twice, so ``na\\u00df\\u0301`` searches ``nas``); it guards FiGHT only. The rule
    reuses the registry's resolution and exclusions and the search-term rules, and adds
    no word list.
    """
    resolution = topic_registry.resolve(query)
    if resolution.matches:
        return FightBlock(
            reason=FightBlockReason.TOPIC_RESOLVED, subject=resolution.matches[0].topic_id
        )
    if resolution.excluded_terms:
        return FightBlock(
            reason=FightBlockReason.EXCLUDED_TERM, subject=resolution.excluded_terms[0].term
        )
    kept_cve_ids = list_kept_cve_ids(query)
    if kept_cve_ids:
        return FightBlock(reason=FightBlockReason.CVE_ID_NAMED, subject=kept_cve_ids[0])
    for search_term in list_search_terms(query, set()):
        term_resolution = topic_registry.resolve(search_term)
        if term_resolution.matches or term_resolution.excluded_terms:
            return FightBlock(reason=FightBlockReason.TERM_READS_AS_TOPIC, subject=search_term)
    return None


def list_fight_terms(
    query: str, topic_registry: TopicRegistry, evidence_catalog: EvidenceCatalog
) -> tuple[str, ...]:
    """The words a direct FiGHT search sends: every search term of the query when
    ``find_fight_block`` gives none, else none. The interpretation records them, and the
    executor and the request builders call this on the same request and registry."""
    return interpret_request(
        InvestigationRequest(query=query, scope=QueryScope.MIXED), topic_registry, evidence_catalog
    ).fight_terms


def list_affectedness_mentions(
    normalized_query: str, evidence_catalog: EvidenceCatalog
) -> tuple[str, ...]:
    """Each product version the query asks affectedness of, once, in query order: a word
    some stored record carries as its whole vendor or product, followed by a dotted
    version, in a query holding an affectedness word. A product and version without such
    a word is a search, not a question about that version. Network-function acronyms
    require a matching vendor phrase in the query."""
    if not asks_affectedness(normalized_query):
        return ()
    vocabulary = find_question_phrases(normalized_query)
    affectedness_mentions: list[str] = []
    for word, version in find_version_mentions(normalized_query):
        affectedness_mention = f"{word} {version}"
        is_new = affectedness_mention not in affectedness_mentions
        if is_new and evidence_catalog.names_product(word):
            if is_unqualified_network_function(
                word, vocabulary, evidence_catalog.find_product_identities(word)
            ):
                continue
            affectedness_mentions.append(affectedness_mention)
    return tuple(affectedness_mentions)


def interpret_request(
    request: InvestigationRequest, topic_registry: TopicRegistry, evidence_catalog: EvidenceCatalog
) -> Interpretation:
    """The query's intent, CVE IDs, searchable terms, the words a direct FiGHT search may
    send and why not, topic resolution and the product versions it asks affectedness of.

    Tokens of each excluded term the registry reports are stripped from the search
    terms (``EPS AKA crash`` searches ``crash``); an excluded word the registry does not
    report is still searched (``topics/normalization.py``; ADR 0002 §8). Every CVE ID
    named is kept, so a query naming more than one lookup can carry is stopped by
    ``find_interpretation_stop`` rather than cut short. An ID longer than
    ``MAX_CVE_ID_CHARS`` is one the CVE program never assigns, and a token that starts
    as an ID but runs on into another digit or letter is malformed: neither is looked up
    or searched.
    """
    normalized_query = normalize_query(request.query)
    cve_ids = list_kept_cve_ids(request.query)
    resolution = topic_registry.resolve(request.query)
    excluded_tokens: set[str] = set()
    for excluded_term in resolution.excluded_terms:
        excluded_tokens.update(tokenize(excluded_term.term))
    affectedness_mentions = list_affectedness_mentions(normalized_query, evidence_catalog)
    product_recognition, ambiguous_product_names = recognize_product(
        normalized_query,
        affectedness_mentions,
        evidence_catalog,
        request.budget.max_results_per_call,
    )
    version_mentions = list_version_mentions(affectedness_mentions, product_recognition)
    lexical_query = request.query
    if version_mentions:
        lexical_query = remove_recognized_versions(normalized_query, version_mentions)
    search_terms = list_search_terms(lexical_query, excluded_tokens)
    fight_block = find_fight_block(request.query, topic_registry)
    # Without a block no excluded term was named, so the search terms are all the query's.
    fight_terms: tuple[str, ...] = ()
    if fight_block is None:
        fight_terms = search_terms

    if cve_ids:
        intent = QueryIntent.EXACT_ID
    elif resolution.matches:
        intent = QueryIntent.TOPIC
    elif search_terms:
        intent = QueryIntent.FREE_TEXT
    elif resolution.excluded_terms:
        intent = QueryIntent.EXCLUDED_TERMS_ONLY
    else:
        intent = QueryIntent.UNSEARCHABLE
    return Interpretation(
        intent=intent,
        normalized_query=normalized_query,
        cve_ids=tuple(cve_ids),
        search_terms=search_terms,
        fight_terms=fight_terms,
        fight_block=fight_block,
        resolution=resolution,
        affectedness_mentions=affectedness_mentions,
        product_recognition=product_recognition,
        ambiguous_product_names=ambiguous_product_names,
    )


def find_resolved_topic(
    interpretation: Interpretation, topic_registry: TopicRegistry
) -> ProtocolTopic | None:
    """The card of the best topic match, or ``None`` when no topic resolved."""
    if not interpretation.resolution.matches:
        return None
    return topic_registry.require_topic(interpretation.resolution.matches[0].topic_id)


def list_allowed_terms(
    interpretation: Interpretation, topic: ProtocolTopic | None
) -> frozenset[str]:
    """The search vocabulary: the query's own terms plus the resolved card's terms."""
    allowed_terms = set(interpretation.search_terms)
    if topic is None:
        return frozenset(allowed_terms)
    card_texts = [topic.canonical_name, *topic.exact_aliases]
    for entity in topic.entities:
        card_texts.append(entity.name)
    card_texts.extend(topic.ecosystem_terms)
    card_texts.extend(topic.query_templates)
    for card_text in card_texts:
        allowed_terms.update(tokenize(card_text))
    return frozenset(allowed_terms)


def exceeds_lookup_cap(cve_ids: Sequence[str], max_results_per_call: int) -> bool:
    """Whether the IDs overflow one exact lookup: more IDs than the caller lets one call
    return (``max_results_per_call``, at most ``MAX_RESULTS_PER_CALL``), so the lookup's
    backend limit would cut a named ID.

    The lookup text always fits ``MAX_QUERY_CHARS``: an ID is read only from decimal
    digits, which fold one character to one, so the distinct IDs joined by spaces are no
    longer than the query they were read from.
    """
    return len(cve_ids) > max_results_per_call


def find_interpretation_stop(
    request: InvestigationRequest, interpretation: Interpretation
) -> tuple[StopReason, DecisionBasis] | None:
    """A stop decided before any call, or ``None`` when round 1 should be planned."""
    is_protocol_scope = request.scope is QueryScope.PROTOCOL_CONTEXT_ONLY
    if is_protocol_scope and interpretation.cve_ids:
        return StopReason.POLICY_BLOCKED, DecisionBasis.CVE_IDS_OUTSIDE_SCOPE
    if is_protocol_scope and request.filters.is_active():
        return StopReason.POLICY_BLOCKED, DecisionBasis.FILTERS_OUTSIDE_SCOPE
    if exceeds_lookup_cap(interpretation.cve_ids, request.budget.max_results_per_call):
        return StopReason.POLICY_BLOCKED, DecisionBasis.CVE_IDS_OVER_LOOKUP_CAP
    if interpretation.intent is QueryIntent.EXCLUDED_TERMS_ONLY:
        return StopReason.NO_EVIDENCE, DecisionBasis.EXCLUDED_TERMS_ONLY
    if interpretation.intent is QueryIntent.UNSEARCHABLE:
        return StopReason.NO_EVIDENCE, DecisionBasis.NO_SEARCHABLE_TERMS
    # Protocol-only free text whose words may not be sent to FiGHT without a reviewed topic.
    is_protocol_free_text = is_protocol_scope and interpretation.intent is QueryIntent.FREE_TEXT
    if is_protocol_free_text and not interpretation.fight_terms:
        return StopReason.NO_EVIDENCE, DecisionBasis.PROTOCOL_SCOPE_NEEDS_TOPIC
    return None


def build_search_call(interpretation: Interpretation) -> CveSearchCall:
    return CveSearchCall(tool=ToolName.CVE_SEARCH, query=" ".join(interpretation.search_terms))


def build_topic_call(interpretation: Interpretation) -> TopicContextCall:
    return TopicContextCall(
        tool=ToolName.TOPIC_CONTEXT, topic_id=interpretation.resolution.matches[0].topic_id
    )


def build_fight_direct_search_call() -> FightDirectSearchCall:
    return FightDirectSearchCall(tool=ToolName.FIGHT_DIRECT_SEARCH)


def plan_first_round(
    request: InvestigationRequest, interpretation: Interpretation
) -> list[PlannedStep]:
    """The calls chosen by intent and scope, one or, for ``mixed`` free text whose words may
    go to FiGHT, the CVE search then the direct FiGHT search: both needs of such a question
    are known before planning, and neither search depends on the other's results. Only
    intents that passed the stop table arrive."""
    if interpretation.intent is QueryIntent.EXACT_ID:
        exact_lookup = CveExactLookupCall(
            tool=ToolName.CVE_EXACT_LOOKUP, cve_ids=interpretation.cve_ids
        )
        return [PlannedStep(exact_lookup, StepReason.QUERY_CVE_IDS)]
    if interpretation.intent is QueryIntent.TOPIC:
        return [PlannedStep(build_topic_call(interpretation), StepReason.REVIEWED_TOPIC)]
    fight_step = PlannedStep(build_fight_direct_search_call(), StepReason.QUERY_TERMS_FIGHT)
    if request.scope is QueryScope.PROTOCOL_CONTEXT_ONLY:
        return [fight_step]
    search_step = PlannedStep(build_search_call(interpretation), StepReason.QUERY_TERMS)
    search_steps = [search_step]
    required_calls = 1
    if request.scope is QueryScope.MIXED and interpretation.fight_terms:
        required_calls += 1
    if (
        interpretation.product_recognition is not None
        and request.budget.max_tool_calls > required_calls
    ):
        search_steps.append(
            PlannedStep(
                ProductQueryCall(
                    tool=ToolName.PRODUCT_QUERY, recognition=interpretation.product_recognition
                ),
                StepReason.RECOGNIZED_PRODUCT,
            )
        )
    if request.scope is QueryScope.MIXED and interpretation.fight_terms:
        return [*search_steps, fight_step]
    return search_steps


def has_only_unknown_ids(round_one_steps: Sequence[ToolStep]) -> bool:
    """Whether round 1 looked IDs up and every one of them is unknown to the repository.

    An ID excluded by the filters is known, so it never counts as unknown.
    """
    requested_ids: set[str] = set()
    unknown_ids: set[str] = set()
    for step in round_one_steps:
        if not isinstance(step.call, CveExactLookupCall):
            continue
        requested_ids.update(step.call.cve_ids)
        for search_warning in step.search_warnings:
            if search_warning.code is SearchWarningCode.UNKNOWN_CVE_ID:
                unknown_ids.add(search_warning.subject)
    return bool(requested_ids) and requested_ids <= unknown_ids


def has_issued_call(call: ToolCall, steps: Sequence[ToolStep]) -> bool:
    call_key = compute_call_key(call)
    return any(step.call_key == call_key for step in steps)


def choose_refinement_step(
    interpretation: Interpretation,
    round_one_steps: Sequence[ToolStep],
    needs: Sequence[EvidenceNeed],
) -> PlannedStep | None:
    """The follow-up call the first refinement rule that fires gives, or ``None``. Every
    rule serves an open implementation or protocol need: a named CVE no lookup found is
    met by no other call, so it never draws a refinement on its own."""
    has_topic = bool(interpretation.resolution.matches)
    is_implementation_open = is_need_open(needs, EvidenceNeedKind.IMPLEMENTATION_CVES)
    is_protocol_open = is_need_open(needs, EvidenceNeedKind.PROTOCOL_CONTEXT)
    if (
        has_topic
        and (is_implementation_open or is_protocol_open)
        and not (has_issued_call(build_topic_call(interpretation), round_one_steps))
    ):
        if has_only_unknown_ids(round_one_steps):
            return PlannedStep(build_topic_call(interpretation), StepReason.TOPIC_AFTER_UNKNOWN_IDS)
        has_literal_search = any(isinstance(step.call, CveSearchCall) for step in round_one_steps)
        if interpretation.intent is QueryIntent.TOPIC and has_literal_search:
            return PlannedStep(
                build_topic_call(interpretation), StepReason.TOPIC_AFTER_LITERAL_MISS
            )
        return PlannedStep(build_topic_call(interpretation), StepReason.TOPIC_FOR_OPEN_NEED)
    search_terms = set(interpretation.search_terms)
    is_searchable = not list_unexplained_unindexed_terms(interpretation, round_one_steps)
    is_unsearched = not search_terms <= list_searched_terms(round_one_steps)
    if is_implementation_open and search_terms and is_unsearched and is_searchable:
        return PlannedStep(build_search_call(interpretation), StepReason.QUERY_TERMS_FOR_OPEN_NEED)
    return None


def plan_refinement(
    interpretation: Interpretation,
    round_one_steps: Sequence[ToolStep],
    needs: Sequence[EvidenceNeed],
) -> list[PlannedStep]:
    """At most one follow-up call for a need round 1 left open, or ``[]``; a call round 1
    already issued (a model's round-1 plan may have run it) is never planned again."""
    refinement_step = choose_refinement_step(interpretation, round_one_steps, needs)
    if refinement_step is None or has_issued_call(refinement_step.call, round_one_steps):
        return []
    return [refinement_step]


def count_tool_calls(call: ToolCall, scope: QueryScope, topic_registry: TopicRegistry) -> int:
    """Backend queries a call costs: a topic call fans out to one CVE search per query
    template, plus one FiGHT search unless the scope is ``implementation_only``; every
    other call is one query."""
    if isinstance(call, CveExactLookupCall | CveSearchCall | ProductQueryCall):
        return CVE_TOOL_COST
    if isinstance(call, FightDirectSearchCall):
        return FIGHT_DIRECT_SEARCH_COST
    if isinstance(call, TopicContextCall):
        template_searches = len(topic_registry.require_topic(call.topic_id).query_templates)
        if scope is QueryScope.IMPLEMENTATION_ONLY:
            return template_searches
        return template_searches + 1
    assert_never(call)


def describe_deterministic_planner() -> DeterministicPlannerIdentity:
    return DeterministicPlannerIdentity(
        kind=PlannerKind.DETERMINISTIC, policy_version=DETERMINISTIC_POLICY_VERSION
    )
