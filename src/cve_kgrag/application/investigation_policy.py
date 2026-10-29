"""The deterministic investigation policy (version ``m7b.1``): pure functions of the
request, its interpretation and the observed steps.

The policy reads a query into an intent, decides whether the query can be answered
at all under the requested scope, plans round 1 by intent and scope, and proposes at
most one refinement from what round 1 observed. It never invents a CVE ID or a
search term: every call it plans uses the caller's IDs, the caller's terms or the
resolved topic card.

Round 1, by intent and scope:

- an exact CVE ID is looked up directly, never expanded into a topic;
- a resolved topic is explored with ``topic_context`` under ``mixed`` and
  ``protocol_context_only``; under ``implementation_only`` the caller's own terms
  are searched literally first, since one search costs less than a topic's fan-out;
- free text is searched literally.

Refinement, at most one call, never one round 1 already issued, and only for an
implementation or protocol need round 1 left open (``domain/evidence_needs.py``); a named
CVE no lookup found is met by no other call:

- R1: every ID of a round-1 exact lookup is unknown and the resolved topic names a
  further target, so explore the topic;
- R2: an implementation or protocol need is open and the resolved topic was not
  explored, so explore it (after a literal search for a topic query, or for an open
  need otherwise);
- R3: the implementation need is open and round 1's searches did not send every search
  term, none of which is an unexplained unindexed term, so search all of them.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from cve_kgrag.domain.cve import MAX_CVE_ID_CHARS
from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.evidence_needs import (
    is_need_open,
    list_searched_terms,
    list_unexplained_unindexed_terms,
)
from cve_kgrag.domain.investigation import (
    DecisionBasis,
    EvidenceNeed,
    EvidenceNeedKind,
    Interpretation,
    InvestigationRequest,
    StepReason,
    StopReason,
    ToolStep,
)
from cve_kgrag.domain.planning import (
    CveExactLookupCall,
    CveSearchCall,
    DeterministicPlannerIdentity,
    PlannerKind,
    QueryIntent,
    ToolCall,
    ToolName,
    TopicContextCall,
    compute_call_key,
)
from cve_kgrag.domain.search import MAX_QUERY_CHARS, SearchWarningCode
from cve_kgrag.domain.text import (
    asks_affectedness,
    find_cve_ids,
    find_version_mentions,
    list_query_terms,
    mentions_cve_id_token,
    normalize_query,
    remove_cve_id_tokens,
    tokenize,
)
from cve_kgrag.domain.topic import ProtocolTopic
from cve_kgrag.domain.topic_context import QueryScope
from cve_kgrag.topics.registry import TopicRegistry

DETERMINISTIC_POLICY_VERSION = "m7b.1"
# An exact lookup or a CVE search is one backend query.
CVE_TOOL_COST = 1


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


def list_affectedness_mentions(
    normalized_query: str, evidence_catalog: EvidenceCatalog
) -> tuple[str, ...]:
    """Each product version the query asks affectedness of, once, in query order: a word
    some stored record carries as its whole vendor or product, followed by a dotted
    version, in a query holding an affectedness word. A product and version without such
    a word is a search, not a question about that version."""
    if not asks_affectedness(normalized_query):
        return ()
    affectedness_mentions: list[str] = []
    for word, version in find_version_mentions(normalized_query):
        affectedness_mention = f"{word} {version}"
        is_new = affectedness_mention not in affectedness_mentions
        if is_new and evidence_catalog.names_product(word):
            affectedness_mentions.append(affectedness_mention)
    return tuple(affectedness_mentions)


def interpret_request(
    request: InvestigationRequest, topic_registry: TopicRegistry, evidence_catalog: EvidenceCatalog
) -> Interpretation:
    """The query's intent, CVE IDs, searchable terms, topic resolution and the product
    versions it asks affectedness of.

    Tokens of an excluded term are stripped from the search terms, so an ambiguous
    alias cannot reach the CVE index through free text (``EPS AKA crash`` searches
    ``crash``). Every CVE ID named is kept, so a query naming more than one lookup
    can carry is stopped by ``find_interpretation_stop`` rather than cut short. An ID
    longer than ``MAX_CVE_ID_CHARS`` is one the CVE program never assigns, and a token
    that starts as an ID but runs on into another digit or letter is malformed: neither
    is looked up or searched.
    """
    normalized_query = normalize_query(request.query)
    cve_ids: list[str] = []
    for cve_id in find_cve_ids(request.query):
        if len(cve_id) <= MAX_CVE_ID_CHARS:
            cve_ids.append(cve_id)
    resolution = topic_registry.resolve(request.query)
    excluded_tokens: set[str] = set()
    for excluded_term in resolution.excluded_terms:
        excluded_tokens.update(tokenize(excluded_term.term))
    search_terms = list_search_terms(request.query, excluded_tokens)

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
        resolution=resolution,
        affectedness_mentions=list_affectedness_mentions(normalized_query, evidence_catalog),
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
    if is_protocol_scope and interpretation.intent is QueryIntent.FREE_TEXT:
        return StopReason.NO_EVIDENCE, DecisionBasis.PROTOCOL_SCOPE_NEEDS_TOPIC
    return None


def build_search_call(interpretation: Interpretation) -> CveSearchCall:
    return CveSearchCall(tool=ToolName.CVE_SEARCH, query=" ".join(interpretation.search_terms))


def build_topic_call(interpretation: Interpretation) -> TopicContextCall:
    return TopicContextCall(
        tool=ToolName.TOPIC_CONTEXT, topic_id=interpretation.resolution.matches[0].topic_id
    )


def plan_first_round(
    request: InvestigationRequest, interpretation: Interpretation
) -> list[PlannedStep]:
    """One call chosen by intent and scope; only intents that passed the stop table arrive."""
    if interpretation.intent is QueryIntent.EXACT_ID:
        exact_lookup = CveExactLookupCall(
            tool=ToolName.CVE_EXACT_LOOKUP, cve_ids=interpretation.cve_ids
        )
        return [PlannedStep(exact_lookup, StepReason.QUERY_CVE_IDS)]
    if interpretation.intent is QueryIntent.TOPIC:
        is_literal_first = request.scope is QueryScope.IMPLEMENTATION_ONLY and bool(
            interpretation.search_terms
        )
        if is_literal_first:
            return [PlannedStep(build_search_call(interpretation), StepReason.QUERY_TERMS)]
        return [PlannedStep(build_topic_call(interpretation), StepReason.REVIEWED_TOPIC)]
    return [PlannedStep(build_search_call(interpretation), StepReason.QUERY_TERMS)]


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
    template, plus one FiGHT search unless the scope is ``implementation_only``."""
    if not isinstance(call, TopicContextCall):
        return CVE_TOOL_COST
    template_searches = len(topic_registry.require_topic(call.topic_id).query_templates)
    if scope is QueryScope.IMPLEMENTATION_ONLY:
        return template_searches
    return template_searches + 1


def describe_deterministic_planner() -> DeterministicPlannerIdentity:
    return DeterministicPlannerIdentity(
        kind=PlannerKind.DETERMINISTIC, policy_version=DETERMINISTIC_POLICY_VERSION
    )
