"""What an investigation's request needs, and whether its admitted steps and answer met it.

The needs follow from the request and its interpretation alone, never from labelled
cases, and whether one was met follows from what the run recorded, so the controller, the
validator and the decision-path audit compute the same needs from a sealed set. Each need
is judged only from the tool that can serve it: an exact lookup a named CVE, a CVE search
or a topic call implementation CVEs, a topic call or, with no topic, a direct FiGHT search
protocol context; no tool serves affectedness (ADR 0003). A need no admitted step of a
serving tool has a result for is ``not_evaluated``: whether it is met cannot yet be judged.

A need is ``found`` only through an exact correspondence or a reviewed mapping: an exact
lookup that returned the named CVE, or the topic call of a resolved, reviewed topic that
returned evidence. That is a rule about how the evidence was reached, not proof that the
answer is sufficient: a topic run can still stop on evidence that does not answer the
question. Hits of a search on the question's own words (``cve_search``,
``fight_direct_search``) give ``matches_unassessed``: matches were found and their
relevance was not assessed, which is not a finding that no relevant evidence exists. The
current version does not judge such results sufficient automatically, so a free-text run
ends with the matches listed and the need unmet.

Searches on the query's own words share one term-coverage check: a search term a search
warned no record holds, and the interpretation does not explain (``list_explained_terms``),
leaves the need ``not_found``. It keeps every answer item.

``docs/rebuild/m7b-b-evidence-needs.md`` and ``docs/rebuild/m7b-c-fight-direct-search.md``
give the rules and their limits.
"""

from collections.abc import Iterable, Sequence

from cve_kgrag.domain.investigation import (
    ADMITTED_ADMISSIONS,
    EvidenceNeed,
    EvidenceNeedKind,
    Interpretation,
    InvestigationCandidate,
    InvestigationRequest,
    NeedOutcome,
    ToolStep,
    list_named_products,
)
from cve_kgrag.domain.planning import (
    CveExactLookupCall,
    CveSearchCall,
    FightDirectSearchCall,
    TopicContextCall,
)
from cve_kgrag.domain.search import SearchWarningCode
from cve_kgrag.domain.text import AFFECTEDNESS_QUESTION_TERMS, list_query_terms, tokenize
from cve_kgrag.domain.threat_context import ThreatContextItem
from cve_kgrag.domain.topic_context import (
    SERVED_STATUSES,
    KnowledgeSource,
    QueryScope,
    TopicContextWarningCode,
)

RequiredNeed = tuple[EvidenceNeedKind, str | None]
OPEN_NEED_OUTCOMES = frozenset(
    {NeedOutcome.NOT_FOUND, NeedOutcome.NOT_EVALUATED, NeedOutcome.MATCHES_UNASSESSED}
)


def derive_needs(
    request: InvestigationRequest, interpretation: Interpretation
) -> list[RequiredNeed]:
    """The needs, in order: each named CVE; for a text target, implementation CVEs and
    protocol context as the scope allows; then affectedness for each product the filters
    name and each product version the query asks affectedness of.

    Without IDs, the search terms or a resolved topic are a text target. With IDs, only a
    resolved topic is: the named lookup answers "What is CVE-X", and words B cannot read
    as a further target add no need. ``mixed`` allows both kinds of evidence; it needs
    them only for a text target.
    """
    scope = request.scope
    required_needs: list[RequiredNeed] = []
    for cve_id in interpretation.cve_ids:
        required_needs.append((EvidenceNeedKind.NAMED_CVE, cve_id))
    has_topic = bool(interpretation.resolution.matches)
    has_text_target = has_topic
    if not interpretation.cve_ids:
        has_text_target = has_topic or bool(interpretation.search_terms)
    if has_text_target and scope is not QueryScope.PROTOCOL_CONTEXT_ONLY:
        required_needs.append((EvidenceNeedKind.IMPLEMENTATION_CVES, None))
    if has_text_target and scope is not QueryScope.IMPLEMENTATION_ONLY:
        required_needs.append((EvidenceNeedKind.PROTOCOL_CONTEXT, None))
    if scope is not QueryScope.PROTOCOL_CONTEXT_ONLY:
        for _, product in list_named_products(
            request.filters, interpretation.affectedness_mentions
        ):
            required_needs.append((EvidenceNeedKind.AFFECTEDNESS, product))
    return required_needs


def list_admitted_steps(steps: Sequence[ToolStep]) -> list[ToolStep]:
    admitted_steps: list[ToolStep] = []
    for step in steps:
        if step.admission in ADMITTED_ADMISSIONS:
            admitted_steps.append(step)
    return admitted_steps


def list_searched_terms(steps: Sequence[ToolStep]) -> set[str]:
    """The search terms the admitted CVE searches sent, together."""
    searched_terms: set[str] = set()
    for step in list_admitted_steps(steps):
        if isinstance(step.call, CveSearchCall):
            searched_terms.update(list_query_terms(step.call.query))
    return searched_terms


def list_spellings(text: str) -> set[str]:
    """The words of ``text`` and the words written together, as a query may spell an
    alias (``5gaka`` for ``5G-AKA``)."""
    words = tokenize(text)
    spellings = set(words)
    spellings.add("".join(words))
    return spellings


def list_explained_terms(interpretation: Interpretation) -> set[str]:
    """Query words the interpretation reads whatever the index holds: the spellings of
    each matched alias and of the context terms that licensed it, and, in a question
    whether a product version is affected, the words of each such version (``5.8.2``
    searches ``5``, ``8``, ``2``) and the words that ask it (``affected``)."""
    explained_terms: set[str] = set()
    for topic_match in interpretation.resolution.matches:
        explained_terms.update(list_spellings(topic_match.matched_alias))
        for context_term in topic_match.context_terms:
            explained_terms.update(list_spellings(context_term))
    for affectedness_mention in interpretation.affectedness_mentions:
        explained_terms.update(tokenize(affectedness_mention))
    if interpretation.affectedness_mentions:
        explained_terms.update(AFFECTEDNESS_QUESTION_TERMS)
    return explained_terms


def filter_unexplained_terms(
    interpretation: Interpretation, unindexed_terms: Iterable[str]
) -> set[str]:
    """Of the words a search warned no record holds, the query's search terms the
    interpretation does not explain (``5gaka`` names 5G-AKA whether or not a record
    spells it so). The one explanation rule of both the CVE and the FiGHT side."""
    search_terms = set(interpretation.search_terms)
    explained_terms = list_explained_terms(interpretation)
    unexplained_terms: set[str] = set()
    for term in unindexed_terms:
        if term in search_terms and term not in explained_terms:
            unexplained_terms.add(term)
    return unexplained_terms


def list_unexplained_unindexed_terms(
    interpretation: Interpretation, steps: Sequence[ToolStep]
) -> set[str]:
    """The query's search terms an admitted CVE search warned no record holds, other than
    words the interpretation explains."""
    unindexed_terms: list[str] = []
    for step in list_admitted_steps(steps):
        for search_warning in step.search_warnings:
            if search_warning.code is SearchWarningCode.TERM_NOT_INDEXED:
                unindexed_terms.append(search_warning.subject)
    return filter_unexplained_terms(interpretation, unindexed_terms)


def list_unexplained_unindexed_fight_terms(
    interpretation: Interpretation, fight_steps: Sequence[ToolStep]
) -> set[str]:
    """The query's search terms one of ``fight_steps``, admitted direct FiGHT searches,
    warned no technique holds, other than words the interpretation explains. FiGHT's
    warning is a topic warning, so it never reaches the CVE side's rule."""
    unindexed_terms: list[str] = []
    for step in fight_steps:
        for topic_warning in step.topic_warnings:
            if topic_warning.code is TopicContextWarningCode.TERM_NOT_INDEXED:
                unindexed_terms.append(topic_warning.subject)
    return filter_unexplained_terms(interpretation, unindexed_terms)


def has_failed_source(steps: Sequence[ToolStep], source: KnowledgeSource) -> bool:
    return any(
        source_outcome.source is source and source_outcome.status not in SERVED_STATUSES
        for step in steps
        for source_outcome in step.source_outcomes
    )


def judge_named_cve(cve_id: str, admitted_steps: Sequence[ToolStep]) -> NeedOutcome:
    """Not evaluated without an admitted lookup of the ID; found when one returned it."""
    lookup_steps: list[ToolStep] = []
    for step in admitted_steps:
        if isinstance(step.call, CveExactLookupCall) and cve_id in step.call.cve_ids:
            lookup_steps.append(step)
    if not lookup_steps:
        return NeedOutcome.NOT_EVALUATED
    if any(cve_id in step.answer_ids for step in lookup_steps):
        return NeedOutcome.FOUND
    if has_failed_source(lookup_steps, KnowledgeSource.CVE_SEARCH):
        return NeedOutcome.SOURCE_UNAVAILABLE
    return NeedOutcome.NOT_FOUND


def judge_protocol_context(
    interpretation: Interpretation,
    admitted_steps: Sequence[ToolStep],
    protocol_context: Sequence[ThreatContextItem],
) -> NeedOutcome:
    """Served by the admitted topic steps when a topic resolved, else by the admitted direct
    FiGHT searches. Unsupported when no topic resolved and the words may not be sent to
    FiGHT (``interpretation.fight_block`` says why); not evaluated without a serving step.
    Without a topic, not found when a direct search warned that no technique holds a word
    the interpretation does not explain (``list_explained_terms``), so the techniques stay
    listed and the step's ``term_not_indexed`` names the word. Otherwise, when the answer
    lists a technique a serving step returned: found from a topic call, matches unassessed
    from a direct search on the question's own words."""
    has_topic = bool(interpretation.resolution.matches)
    if not has_topic and not interpretation.fight_terms:
        return NeedOutcome.UNSUPPORTED
    serving_call_type: type[TopicContextCall | FightDirectSearchCall] = FightDirectSearchCall
    if has_topic:
        serving_call_type = TopicContextCall
    serving_steps: list[ToolStep] = []
    serving_answer_ids: set[str] = set()
    for step in admitted_steps:
        if isinstance(step.call, serving_call_type):
            serving_steps.append(step)
            serving_answer_ids.update(step.answer_ids)
    if not serving_steps:
        return NeedOutcome.NOT_EVALUATED
    if not has_topic and list_unexplained_unindexed_fight_terms(interpretation, serving_steps):
        return NeedOutcome.NOT_FOUND
    if any(item.technique_id in serving_answer_ids for item in protocol_context):
        if has_topic:
            return NeedOutcome.FOUND
        return NeedOutcome.MATCHES_UNASSESSED
    if has_failed_source(serving_steps, KnowledgeSource.MITRE_FIGHT):
        return NeedOutcome.SOURCE_UNAVAILABLE
    return NeedOutcome.NOT_FOUND


def judge_implementation_cves(
    interpretation: Interpretation,
    admitted_steps: Sequence[ToolStep],
    implementation_candidates: Sequence[InvestigationCandidate],
) -> NeedOutcome:
    """How the retrieval reached the listed CVEs, not a judgement of their relevance.

    Not evaluated without an admitted CVE search or topic call. Not found when a search
    term the interpretation does not explain (``list_explained_terms``) is held by no
    record. With a resolved topic, found when the answer lists a CVE an admitted topic
    call found, at the relevance tier the card gave it, and matches unassessed when only a
    search on the question's own words found the listed CVEs. Without a topic, matches
    unassessed when the admitted searches together sent every search term and one of them
    returned a CVE.
    """
    serving_steps: list[ToolStep] = []
    for step in admitted_steps:
        if isinstance(step.call, CveSearchCall | TopicContextCall):
            serving_steps.append(step)
    if not serving_steps:
        return NeedOutcome.NOT_EVALUATED
    if list_unexplained_unindexed_terms(interpretation, admitted_steps):
        return NeedOutcome.NOT_FOUND
    if interpretation.resolution.matches:
        topic_step_indices: set[int] = set()
        search_step_indices: set[int] = set()
        for step in serving_steps:
            if isinstance(step.call, TopicContextCall):
                topic_step_indices.add(step.step_index)
            else:
                search_step_indices.add(step.step_index)
        if any(
            topic_step_indices.intersection(candidate.found_by_steps)
            for candidate in implementation_candidates
        ):
            return NeedOutcome.FOUND
        if any(
            search_step_indices.intersection(candidate.found_by_steps)
            for candidate in implementation_candidates
        ):
            return NeedOutcome.MATCHES_UNASSESSED
    else:
        has_searched_every_term = set(interpretation.search_terms) <= list_searched_terms(
            admitted_steps
        )
        has_search_answer = any(
            isinstance(step.call, CveSearchCall) and step.answer_ids for step in serving_steps
        )
        if has_searched_every_term and has_search_answer:
            return NeedOutcome.MATCHES_UNASSESSED
    if has_failed_source(serving_steps, KnowledgeSource.CVE_SEARCH):
        return NeedOutcome.SOURCE_UNAVAILABLE
    return NeedOutcome.NOT_FOUND


def judge_needs(
    request: InvestigationRequest,
    interpretation: Interpretation,
    steps: Sequence[ToolStep],
    implementation_candidates: Sequence[InvestigationCandidate],
    protocol_context: Sequence[ThreatContextItem],
) -> tuple[EvidenceNeed, ...]:
    """Each need ``derive_needs`` gives, with the outcome the admitted ``steps`` and the
    answer's items give it."""
    admitted_steps = list_admitted_steps(steps)
    judged_needs: list[EvidenceNeed] = []
    for kind, subject in derive_needs(request, interpretation):
        if kind is EvidenceNeedKind.NAMED_CVE and subject is not None:
            outcome = judge_named_cve(subject, admitted_steps)
        elif kind is EvidenceNeedKind.PROTOCOL_CONTEXT:
            outcome = judge_protocol_context(interpretation, admitted_steps, protocol_context)
        elif kind is EvidenceNeedKind.IMPLEMENTATION_CVES:
            outcome = judge_implementation_cves(
                interpretation, admitted_steps, implementation_candidates
            )
        else:
            # Affectedness: no deployment serves it (ADR 0003).
            outcome = NeedOutcome.SOURCE_UNAVAILABLE
        judged_needs.append(EvidenceNeed(kind=kind, subject=subject, outcome=outcome))
    return tuple(judged_needs)


def is_need_open(needs: Sequence[EvidenceNeed], kind: EvidenceNeedKind) -> bool:
    """Whether a need of ``kind`` is ``not_found``, ``not_evaluated`` or
    ``matches_unassessed``: unmet, and a tool could still meet it (the reviewed topic, when
    one resolved and was not explored). ``source_unavailable`` and ``unsupported`` are
    final."""
    return any(need.kind is kind and need.outcome in OPEN_NEED_OUTCOMES for need in needs)


def has_unmet_need_beyond_affectedness(needs: Sequence[EvidenceNeed]) -> bool:
    return any(
        need.outcome is not NeedOutcome.FOUND and need.kind is not EvidenceNeedKind.AFFECTEDNESS
        for need in needs
    )


def has_affectedness_need(needs: Sequence[EvidenceNeed]) -> bool:
    return any(need.kind is EvidenceNeedKind.AFFECTEDNESS for need in needs)
