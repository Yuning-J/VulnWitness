"""What an investigation's request needs, and whether its admitted steps and answer met it.

The needs follow from the request and its interpretation alone, never from labelled
cases, and whether one was met follows from what the run recorded, so the controller, the
validator and the decision-path audit compute the same needs from a sealed set. Each need
is met only by the tool that can serve it: an exact lookup a named CVE, a CVE search
implementation CVEs, a topic call implementation CVEs and protocol context; no tool serves
affectedness (ADR 0003).

``docs/rebuild/m7b-b-evidence-needs.md`` gives the rules and their limits.
"""

from collections.abc import Sequence

from cve_kgrag.domain.investigation import (
    EvidenceNeed,
    EvidenceNeedKind,
    Interpretation,
    InvestigationCandidate,
    InvestigationRequest,
    NeedOutcome,
    StepAdmission,
    ToolStep,
    list_named_products,
)
from cve_kgrag.domain.planning import CveExactLookupCall, CveSearchCall, TopicContextCall
from cve_kgrag.domain.search import SearchWarningCode
from cve_kgrag.domain.text import AFFECTEDNESS_QUESTION_TERMS, list_query_terms, tokenize
from cve_kgrag.domain.threat_context import ThreatContextItem
from cve_kgrag.domain.topic_context import SERVED_STATUSES, KnowledgeSource, QueryScope

RequiredNeed = tuple[EvidenceNeedKind, str | None]


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
        if step.admission is StepAdmission.ADMITTED:
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


def list_unexplained_unindexed_terms(
    interpretation: Interpretation, steps: Sequence[ToolStep]
) -> set[str]:
    """The query's search terms an admitted search warned no record holds, other than
    words the interpretation explains (``5gaka`` names 5G-AKA whether or not a record
    spells it so)."""
    search_terms = set(interpretation.search_terms)
    explained_terms = list_explained_terms(interpretation)
    unexplained_terms: set[str] = set()
    for step in list_admitted_steps(steps):
        for search_warning in step.search_warnings:
            if search_warning.code is not SearchWarningCode.TERM_NOT_INDEXED:
                continue
            term = search_warning.subject
            if term in search_terms and term not in explained_terms:
                unexplained_terms.add(term)
    return unexplained_terms


def has_failed_source(steps: Sequence[ToolStep], source: KnowledgeSource) -> bool:
    return any(
        source_outcome.source is source and source_outcome.status not in SERVED_STATUSES
        for step in steps
        for source_outcome in step.source_outcomes
    )


def judge_named_cve(cve_id: str, admitted_steps: Sequence[ToolStep]) -> NeedOutcome:
    lookup_steps: list[ToolStep] = []
    for step in admitted_steps:
        if isinstance(step.call, CveExactLookupCall) and cve_id in step.call.cve_ids:
            lookup_steps.append(step)
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
    """Found when the answer lists a technique an admitted topic step returned. Without a
    resolved topic no tool reaches FiGHT."""
    if not interpretation.resolution.matches:
        return NeedOutcome.UNSUPPORTED
    topic_steps: list[ToolStep] = []
    topic_answer_ids: set[str] = set()
    for step in admitted_steps:
        if isinstance(step.call, TopicContextCall):
            topic_steps.append(step)
            topic_answer_ids.update(step.answer_ids)
    if any(item.technique_id in topic_answer_ids for item in protocol_context):
        return NeedOutcome.FOUND
    if has_failed_source(topic_steps, KnowledgeSource.MITRE_FIGHT):
        return NeedOutcome.SOURCE_UNAVAILABLE
    return NeedOutcome.NOT_FOUND


def judge_implementation_cves(
    interpretation: Interpretation,
    admitted_steps: Sequence[ToolStep],
    implementation_candidates: Sequence[InvestigationCandidate],
) -> NeedOutcome:
    """A limited check of the retrieval process, not proof that the CVEs are relevant.

    Not found when a search term the interpretation does not explain
    (``list_explained_terms``) is held by no record. With a
    resolved topic, found when the answer lists a CVE an admitted topic call or search
    found, at the relevance tier the card gave it. Without one, found when the admitted
    searches together sent every search term and one of them returned a CVE.
    """
    if list_unexplained_unindexed_terms(interpretation, admitted_steps):
        return NeedOutcome.NOT_FOUND
    serving_steps: list[ToolStep] = []
    for step in admitted_steps:
        if isinstance(step.call, CveSearchCall | TopicContextCall):
            serving_steps.append(step)
    if interpretation.resolution.matches:
        serving_step_indices: set[int] = set()
        for step in serving_steps:
            serving_step_indices.add(step.step_index)
        if any(
            serving_step_indices.intersection(candidate.found_by_steps)
            for candidate in implementation_candidates
        ):
            return NeedOutcome.FOUND
    else:
        has_searched_every_term = set(interpretation.search_terms) <= list_searched_terms(
            admitted_steps
        )
        has_search_answer = any(
            isinstance(step.call, CveSearchCall) and step.answer_ids for step in serving_steps
        )
        if has_searched_every_term and has_search_answer:
            return NeedOutcome.FOUND
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
    """Whether a need of ``kind`` is ``not_found``: unmet, and a tool could still meet it.
    ``source_unavailable`` and ``unsupported`` are final."""
    return any(need.kind is kind and need.outcome is NeedOutcome.NOT_FOUND for need in needs)


def has_unmet_need_beyond_affectedness(needs: Sequence[EvidenceNeed]) -> bool:
    return any(
        need.outcome is not NeedOutcome.FOUND and need.kind is not EvidenceNeedKind.AFFECTEDNESS
        for need in needs
    )


def has_affectedness_need(needs: Sequence[EvidenceNeed]) -> bool:
    return any(need.kind is EvidenceNeedKind.AFFECTEDNESS for need in needs)
