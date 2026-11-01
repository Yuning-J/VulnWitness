"""The single gate every plan passes before a call runs, whichever planner proposed it.

Per step, in order (the first failing check is the step's rejection):

1. ``tool_not_permitted_by_scope``: a CVE tool under ``protocol_context_only``, or a
   direct FiGHT search under ``implementation_only``;
2. ``invented_cve_id``: an exact lookup of an ID the caller did not name;
3. ``cve_id_in_search_text``: a free-text search carrying a CVE ID;
4. ``term_outside_vocabulary``: a search with no search term (``list_query_terms``:
   a search of nothing but stopwords and the low-signal words ``cve`` and ``cves`` has
   none), or a term outside the caller's terms and the resolved card's terms;
5. ``topic_not_resolved``: a topic other than the one the query resolved;
   ``fight_direct_search_blocked``: a direct FiGHT search the interpretation does not
   allow (no ``fight_terms``; ``fight_block`` records why);
6. ``repeated_call``: a call that would run as one already issued in this run, or
   as an earlier call of the plan that passed checks 1-5. A direct FiGHT search's key is
   constant, so a run holds at most one.

Then over the whole plan, every call counted, repeats included, except a topic
that was not resolved (it may have no card to cost): ``missing_baseline_source``
(a model's round-1 plan skips a source the deterministic round-1 plan consults),
``missing_named_cve_id`` (a CVE ID the caller named is carried neither by an exact
lookup the run issued nor by one of the plan's; here only a lookup that passed checks
1-6 counts, and a search never stands in for one), ``over_tool_call_budget`` and
``over_source_budget``. Any rejection rejects the whole plan; nothing is trimmed.

So every named ID is looked up in round 1, whichever planner's plan the round runs:
a model plan that omits one falls back to the policy's plan, which looks every named
ID up in one call that fits any budget. A round-2 plan owes no lookup, since round 2
runs only after round 1 issued its whole plan; a round 1 stopped before then ends
``budget_exhausted`` or ``invalid_evidence``, never with an answer or ``no_evidence``.

The vocabulary check reads search terms only, so text it never sees (another script,
punctuation, stopwords, low-signal words) must not run either: an accepted call is
replaced by its canonical form (``canonicalize_call``) before it is run or recorded, so
``cve ausf`` runs, is keyed and is recorded as ``ausf``. The repeat check therefore
keys the canonical call: canonicalization drops a token that would push a search past
``MAX_QUERY_CHARS``, so two raw searches can run as one query. A call's key is what
its backend query depends on, so two calls that differ only in term order, repeated
terms, stopwords, low-signal words or repeated IDs share a key and count as a repeat.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import assert_never

from pydantic import ValidationError

from vulnwitness.application.investigation_policy import (
    count_tool_calls,
    list_allowed_terms,
    list_search_terms,
)
from vulnwitness.domain.investigation import Interpretation, InvestigationRequest, ToolStep
from vulnwitness.domain.planning import (
    CveExactLookupCall,
    CveSearchCall,
    FightDirectSearchCall,
    PlanRejection,
    PlanRejectionCode,
    ProductQueryCall,
    QueryPlan,
    ToolCall,
    ToolName,
    TopicContextCall,
    compute_call_key,
    is_tool_permitted,
    list_tool_sources,
)
from vulnwitness.domain.text import list_query_terms, mentions_cve_id_token
from vulnwitness.domain.topic import ProtocolTopic
from vulnwitness.domain.topic_context import KnowledgeSource, QueryScope
from vulnwitness.topics.registry import TopicRegistry


@dataclass(frozen=True)
class PlanContext:
    scope: QueryScope
    interpretation: Interpretation
    allowed_terms: frozenset[str]
    issued_call_keys: frozenset[str]
    remaining_tool_calls: int
    consulted_sources: frozenset[KnowledgeSource]
    max_sources: int
    # Set only for a model's round-1 plan: the sources the deterministic plan consults.
    baseline_sources: frozenset[KnowledgeSource] | None
    # The CVE IDs the caller named that no exact lookup the run issued carried.
    cve_ids_to_look_up: frozenset[str]


def build_plan_context(
    request: InvestigationRequest,
    interpretation: Interpretation,
    topic: ProtocolTopic | None,
    issued_steps: Sequence[ToolStep],
    baseline_sources: frozenset[KnowledgeSource] | None,
) -> PlanContext:
    """The gate's context for the next plan, from the steps the run issued before it.

    Every issued step was charged before it ran and is never refunded, so the steps
    alone give the remaining tool calls, the sources consulted and the named IDs still to
    look up: the controller building a plan and the audit re-gating a recorded one read
    the same values.
    """
    issued_call_keys: set[str] = set()
    charged_tool_calls = 0
    consulted_sources: set[KnowledgeSource] = set()
    looked_up_cve_ids: set[str] = set()
    for step in issued_steps:
        issued_call_keys.add(step.call_key)
        charged_tool_calls += step.charged_tool_calls
        consulted_sources.update(step.sources)
        if isinstance(step.call, CveExactLookupCall):
            looked_up_cve_ids.update(step.call.cve_ids)
    budget = request.budget
    return PlanContext(
        scope=request.scope,
        interpretation=interpretation,
        allowed_terms=list_allowed_terms(interpretation, topic),
        issued_call_keys=frozenset(issued_call_keys),
        remaining_tool_calls=budget.max_tool_calls - charged_tool_calls,
        consulted_sources=frozenset(consulted_sources),
        max_sources=budget.max_sources,
        baseline_sources=baseline_sources,
        cve_ids_to_look_up=frozenset(interpretation.cve_ids) - looked_up_cve_ids,
    )


def list_plan_sources(calls: Sequence[ToolCall], scope: QueryScope) -> frozenset[KnowledgeSource]:
    """Every source the plan's calls consult under ``scope``."""
    plan_sources: set[KnowledgeSource] = set()
    for call in calls:
        plan_sources.update(list_tool_sources(call, scope))
    return frozenset(plan_sources)


def canonicalize_call(call: ToolCall) -> ToolCall:
    """The call as it runs and is recorded: a search keeps only its search terms, each
    once and in order, and an exact lookup each ID once; a topic call and a direct FiGHT
    search, which carry no text, stay as they are. Only an accepted call is canonicalized,
    so its search has a term within the query limit."""
    if isinstance(call, CveSearchCall):
        search_terms = list_search_terms(call.query, set())
        return CveSearchCall(tool=ToolName.CVE_SEARCH, query=" ".join(search_terms))
    if isinstance(call, CveExactLookupCall):
        cve_ids: list[str] = []
        for cve_id in call.cve_ids:
            if cve_id not in cve_ids:
                cve_ids.append(cve_id)
        return CveExactLookupCall(tool=ToolName.CVE_EXACT_LOOKUP, cve_ids=tuple(cve_ids))
    return call


def parse_plan_text(plan_text: str) -> QueryPlan | None:
    """The plan, or ``None`` when the text is not a valid ``QueryPlan``."""
    try:
        return QueryPlan.model_validate_json(plan_text)
    except ValidationError:  # model output is untrusted: a malformed plan is an observation
        return None


def find_call_rejection(call: ToolCall, plan_context: PlanContext) -> PlanRejectionCode | None:
    """The first of checks 1-5 the call fails, read from the call alone."""
    interpretation = plan_context.interpretation
    if not is_tool_permitted(call, plan_context.scope):
        return PlanRejectionCode.TOOL_NOT_PERMITTED_BY_SCOPE
    if isinstance(call, CveExactLookupCall):
        if not set(call.cve_ids) <= set(interpretation.cve_ids):
            return PlanRejectionCode.INVENTED_CVE_ID
    elif isinstance(call, CveSearchCall):
        if mentions_cve_id_token(call.query):
            return PlanRejectionCode.CVE_ID_IN_SEARCH_TEXT
        query_terms = list_query_terms(call.query)
        has_foreign_term = any(term not in plan_context.allowed_terms for term in query_terms)
        # The canonical search keeps terms within the query limit; it must keep one.
        has_search_term = bool(list_search_terms(call.query, set()))
        if not has_search_term or has_foreign_term:
            return PlanRejectionCode.TERM_OUTSIDE_VOCABULARY
    elif isinstance(call, ProductQueryCall):
        if call.recognition != interpretation.product_recognition:
            return PlanRejectionCode.TERM_OUTSIDE_VOCABULARY
    elif isinstance(call, TopicContextCall):
        matches = interpretation.resolution.matches
        if not matches or call.topic_id != matches[0].topic_id:
            return PlanRejectionCode.TOPIC_NOT_RESOLVED
    elif isinstance(call, FightDirectSearchCall):
        if not interpretation.fight_terms:
            return PlanRejectionCode.FIGHT_DIRECT_SEARCH_BLOCKED
    else:
        assert_never(call)
    return None


def find_plan_rejections(
    calls: Sequence[ToolCall], plan_context: PlanContext, topic_registry: TopicRegistry
) -> list[PlanRejection]:
    rejections: list[PlanRejection] = []
    earlier_keys: set[str] = set()
    planned_sources: set[KnowledgeSource] = set()
    planned_tool_calls = 0
    planned_cve_ids: set[str] = set()
    for step_position, call in enumerate(calls):
        rejection_code = find_call_rejection(call, plan_context)
        if rejection_code is None:
            run_key = compute_call_key(canonicalize_call(call))
            if run_key in plan_context.issued_call_keys or run_key in earlier_keys:
                rejection_code = PlanRejectionCode.REPEATED_CALL
            earlier_keys.add(run_key)
        if rejection_code is not None:
            rejections.append(PlanRejection(step_position=step_position, code=rejection_code))
        elif isinstance(call, CveExactLookupCall):
            planned_cve_ids.update(call.cve_ids)
        # A topic the query did not resolve may have no card, so it has no cost.
        if rejection_code is not PlanRejectionCode.TOPIC_NOT_RESOLVED:
            planned_sources.update(list_tool_sources(call, plan_context.scope))
            planned_tool_calls += count_tool_calls(call, plan_context.scope, topic_registry)
    baseline_sources = plan_context.baseline_sources
    if baseline_sources is not None and not baseline_sources <= planned_sources:
        rejections.append(PlanRejection(code=PlanRejectionCode.MISSING_BASELINE_SOURCE))
    if not plan_context.cve_ids_to_look_up <= planned_cve_ids:
        rejections.append(PlanRejection(code=PlanRejectionCode.MISSING_NAMED_CVE_ID))
    if planned_tool_calls > plan_context.remaining_tool_calls:
        rejections.append(PlanRejection(code=PlanRejectionCode.OVER_TOOL_CALL_BUDGET))
    if len(plan_context.consulted_sources | planned_sources) > plan_context.max_sources:
        rejections.append(PlanRejection(code=PlanRejectionCode.OVER_SOURCE_BUDGET))
    return rejections
