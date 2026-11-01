# ADR 0011: Product triage workflow

Status: accepted

Contract: `2.0.0-dev.50`

## Composition boundary

`vulnwitness triage` composes capabilities, cursor-based product queries and selected CVE
lookups into one ADR 0010 session. `application.triage_workflow.TriageWorkflow` takes injected
service callables, the recording port, an artifact port, a monotonic clock, limits and the
CLI response encoder. The CLI supplies dependencies and renders the summary. Recording
continues to own call persistence; it never authors findings. This workflow implements no
retrieval, version comparison, investigation stopping policy, model planning or MCP tool.
The same application entry point can be composed by another interface.

## Budgets and refusals

V1 accepts a new or empty session directory only. Reusing completed or interrupted sessions
is refused before modification. No resume or append semantics are implied by `triage`.
The existing recorder still enforces dataset binding, atomic private writes and per-call
admission. Session metadata options retain their ordinary meaning.

Default limits are 20 product pages, 5 lookups and 120 seconds. Lookups are capped at 10;
page size defaults to 10 and uses the existing product request bound of 20. Before the
first call, preflight requires `1 + max_pages + lookup_budget` remaining session calls.
For explicit selection, `lookup_budget` is the number of requested IDs; otherwise it is
`lookups`. This conservative reservation needs no speculative unrecorded product query.
Because V1 requires an empty directory, the remaining call limit is the new session's full
limit. Selection IDs must be unique and fit the lookup budget.

The injected monotonic clock is checked between synchronous service calls and after the
last admitted call. Calls already executing finish and are recorded; the workflow does not
abandon work that could later mutate a session. The limit can therefore overrun by the
duration of one call. A deadline stop is recorded as `time_limit` in `triage.json`.

## Deterministic selection

Selection reads the complete inventoried prefix before sorting. It orders by:

1. `product_field` before `description_mention`;
2. with a version, returned note `hit`, `unknown`, then `no_hit`;
3. newest publication first, missing dates last;
4. CVE ID ascending.

The workflow uses returned note outcomes without recomputing version comparisons. Its
basis-first selection deliberately differs from product page grouping, which puts version
outcome first. Wording is "first N by the stated order". It makes no severity, relevance or
danger judgement. Repeatable `--select` overrides the order with user-chosen IDs in supplied
order; every ID must occur on a page actually read. A page cap cannot imply membership of
an unseen CVE.

## Findings and trust

The workflow writes product-field or description-mention claims for every inventoried CVE,
including every returned matched product pair, and version-note claims when requested.
Page and page-size caps bound this artifact; retaining every inventoried match makes the
inventory auditable independently of the much smaller deep dive. No threshold silently
changes findings coverage to selected CVEs only.

For completed lookups it copies catalogue paths, including inheritance and hop identities,
or a source record fact. Claim values and citations come only from the recorded responses.
If no supported record fact is present, the run stops with `lookup_claim_unavailable` and
exit 2, retaining the lookup and listing the unfinished findings step. Missing fields are
never converted to negative claims. CVSS fallback facts require a unique metric selector.
Every finding is `author: workflow`, `status: unconfirmed`, and uses the ADR 0010 canonical
claim rendering. Selections and pagination progress are authored bookkeeping. The workflow
writes no analyst notes, model judgements, selection narrative or open-ended interpretation:
field agreement cannot justify those conclusions. A user or agent can author interpretation
separately under the existing findings contract.

The ordinary session check runs after findings are saved. Record consistency, citation
resolution and deterministic claim verification must all pass for exit 0. Passing still
establishes neither source support, real-world truth nor deployed applicability.

## Scope and outcomes

`triage.json` has a published `triage.schema.json` under `schemas/v2`; the contract bump adds
this workflow artifact without changing session format 1 or service response shapes. It
contains only workflow bookkeeping: configured caps, reserved calls, inventory page-call
numbers, counts, CVE IDs, the returned total and traversal flag, selected and looked-up IDs,
lookup-call numbers, selection rule, stop reason, failure code, caps hit and remaining steps.
It contains no vulnerability conclusions. The session checker retains its existing layers;
the workflow artifact is not evidence or an additional source-authenticity guarantee.

Inventory scope and deep-dive scope appear separately in both JSON and text. Reaching the
page cap leaves inventory incomplete, but selected lookups can still finish within the time
budget. `lookups` bounds the intended deep dive and does not by itself make a run incomplete.
An empty complete inventory exits 1; complete runs with passing checks exit 0. Page caps,
deadline stops, failures, invalid selections and failed checks exit 2. Completed calls remain
on service failure; the typed failure itself is also recorded by the existing recorder.
Findings cover only completed successful calls, and remaining planned steps are listed.
Recording or filesystem failures can prevent artifact publication and are reported as
failures without releasing an unrecorded service answer.

Text is the default presentation. `--format json` prints exactly the saved workflow summary;
`session check` remains available for the full layered report. Triage records its underlying
calls as ordinary CLI JSON responses regardless of presentation format.
