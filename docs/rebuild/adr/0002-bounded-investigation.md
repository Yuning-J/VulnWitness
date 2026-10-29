# ADR 0002 — Bounded investigation

Status: accepted (M4). Applies to `application/investigate.py` and the contracts
in `domain/investigation.py`, `domain/planning.py` and `domain/budget.py`.

## Context

The brief (§10) asks for an agent that chooses allowlisted tools, observes what
they return and refines at most once, under server caps a caller may lower but
never raise: 2 rounds, 8 tool calls, 4 sources, 20 results per call, 30 seconds
and 200 000 context bytes. It must stop honestly, never loop, never let a planner
write facts, and work fully without a language model. The review gate (G2–G4)
asks for proof that observations change the trajectory, that every path
terminates, that failures stay typed, and that runs replay to the same hash.

Three designs were compared: a minimal one, a safety-first one and one built for
testability and replay. The last was taken as the base, with the straight-line
controller and literal-first topic refinement of the minimal design and the
budget and identity rules of the safety-first design.

## Decisions

### 1. One straight-line state machine, no loop over rounds

`interpret → plan → retrieve → assess → (refine → retrieve → assess) → validate →
return`. Round 2 is reachable only through one `assess → refine` edge, and the
controller calls round 2 at most once in straight-line code. Every transition is
recorded with the observation it was decided on (`DecisionBasis`); legality is
checked by the final validator rather than by a raising guard in the controller,
so a controller defect fails closed at validation instead of mid-run.

### 2. Charge the fan-out, before the call, never refund

`max_tool_calls` counts backend queries. A `topic_context` call costs one per
query template of the resolved card plus one FiGHT search unless the scope is
`implementation_only`; a CVE tool costs 1. The cost is known before the call from
the card, so the plan gate rejects an over-budget plan before anything runs. Each
call is charged before it runs, and the charge stands whether the call fails,
lands late or returns invalid evidence, so retries and failures cannot hide
inside the budget. Planner calls are counted separately.

`max_results_per_call` bounds every backend request, not only the tool request:
the investigation sets `TopicContextRequest.max_results_per_search` to the cap,
so each template search a `topic_context` call fans out to, and its FiGHT search,
asks for no more. Each step records those backend requests (source, query text or
FiGHT terms, limit), built from the same request builders the tool runs, and the
final validation requires one charged tool call per recorded request and every
recorded limit within the cap. A single `limit` per step was rejected: a topic
step's fan-out would hide behind it, so the trajectory could state a cap no
backend saw.

### 3. Wall time as a ceiling: abandon at the deadline, discard late results

The deadline is checked against an injected monotonic clock before every planner
call and every tool call; once it has passed, nothing more is planned or called
and the run stops with `budget_exhausted`. Every planner and tool call runs under
an injected `ThreadedCallRunner`, which starts the call on a fresh daemon thread
and waits on a queue for at most the remaining seconds, read from the same
clock. When the remaining time reaches zero before the call returns, the runner
gives control back with a typed `CallTimedOut`: the step is recorded as
`timed_out` (charged, no status, hash, results or bytes), a planner round as
`model_timed_out`, the breach is `wall_time`, and the run stops with
`budget_exhausted`. A result that returns but finishes at or after the deadline is
still recorded with its hash as `discarded_after_deadline` and never admitted.
No other adapter method runs during a request: the planner's identity, the FiGHT
pin, the evidence catalog and the source capabilities are read once, when the
composition root builds the service, so sealing the result cannot block either.
So the caller gets control back within the wall-time cap, and nothing computed
after the deadline reaches the answer. Just before each deadline check reads the
clock, the service tells an injected `reach_checkpoint` which point it reached (a
round's planner or a step, before it starts, while its call runs, at its finish);
a measured run ignores it, and replay uses it to put a recorded deadline back
where it fell (see 12).

Python cannot stop a running thread, so an abandoned call is not killed: it keeps
its daemon thread until it returns, and its result is dropped. That is safe
because the tools and the planner are read-only, so an abandoned call has no
effect on the run, and a daemon thread never blocks interpreter exit. Network
adapters still receive the remaining seconds as their timeout, a planner at most a
third of the run's budget (`PLANNER_SHARE_OF_WALL_TIME`), the deadline the call runner
waits to for a planner call (`ModelPort.propose_plan(..., timeout_seconds)`, and a network adapter, the
Trustify adapter included once it exists (ADR 0003)) and must honour it, so an
abandoned call also releases its thread and connection soon after the deadline. The
controller records a planner call still running at the end of its share, or whose reply
lands at or after it, with the run in time, as the failed reply `PLANNER_CAP_REPLY`, so the round falls back to the policy
(ADR 0005 §2). A
`ThreadPoolExecutor` was rejected because its worker threads are not daemons and an
abandoned call would block interpreter exit; a process per call was rejected as too
costly for in-process index lookups.

### 4. A raw-text model port, a core-side gate and a deterministic fallback

`ModelPort.propose_plan` returns `ModelReply`: raw text or a typed failure. The
core parses the text into a closed `QueryPlan` (tool calls only; scope, filters,
limits, URLs, claims and evidence cannot be expressed) and runs it through the
same gate as the deterministic plan: scope permission, no invented CVE ID, no CVE
ID hidden in search text, a vocabulary of the query's own terms plus the resolved
card's terms, only the resolved topic, no repeated call, the round-1 baseline
sources, an exact lookup of every CVE ID the caller named (see 9), and the call and
source budgets. Any rejection rejects the whole plan,
and the round falls back to the deterministic plan, so a broken or hostile model
degrades to the production baseline instead of blocking the question; the round
records the model plan's rejections followed by any of the fallback plan's. A reply
that arrives after the deadline, or no reply by it, stops the run; a round the
deadline stops before its configured model is consulted is recorded as
`model_skipped_at_deadline`, and a round 1 whose policy plan is over the source budget, which no
model plan could pass since it must consult the same sources, as `model_not_consulted`,
so a round's outcome always says which planner kind the run was configured with.

The vocabulary check reads only search terms, so an accepted call is rewritten into
its canonical form before it runs or is recorded: a search keeps its search terms,
each once, and an exact lookup each ID once. Text the check never reads (another
script, punctuation, stopwords, the low-signal words `cve` and `cves`) therefore
reaches neither the semantic channel nor the trajectory. A call's key hashes what the
backend query depends on, the set of IDs or of search terms (`list_query_terms`), so
reordering or repeating them, or adding a stopword or low-signal word, cannot pass as
a new call and spend the one refinement on a query that already ran. The repeat check
keys the canonical call, because canonicalization also drops a token that would push
a normalized search past the query limit: two searches differing only in such a token
run as one query. The planner sees codes and counts, never source text.

Each round records the model's reply as the port returned it, within `ModelReply`'s
length caps: the plan text or the typed failure, beside its hash. Every outcome
with a reply records it, a failed reply (`model_unavailable`) and a reply that
landed after the deadline (`model_reply_after_deadline`) included; only
`deterministic`, `model_timed_out`, `model_skipped_at_deadline` and
`model_not_consulted` have none.
Recording only the reply's hash was rejected: a hash cannot be parsed, so the
outcome, the rejection codes and the accepted plan it led to could not be
re-derived, and a rejected or failed reply could be relabelled accepted. Recording
only an accepted reply's canonical plan was rejected for the same reason: a failed
or rejected reply would leave nothing to re-derive from. The reply is data: it is
never logged and never quoted in a warning or a violation, and the steps and the
accepted plan carry only the canonical calls.

The planner's identity is one of two shapes, `DeterministicPlannerIdentity` (kind
`deterministic` and the policy version) or `ModelPlannerIdentity` (kind `model`, the
model name, the adapter, its version and the endpoint fingerprint), discriminated by `kind`, so neither can carry the other's field.
The service consults a model exactly when a `ModelPort` is configured, while every
trajectory and the `model_planner` capability record the planner's identity; the
two must agree. The composition root therefore requires a
model port to be paired with a model planner's identity, which discovery builds
from the settings and the installed entry point (ADR 0004 §5: `ModelPlanning`
holds a `ModelPlannerIdentity`): a port claiming the policy's identity would
record its model's plans as the policy's and seal every interpretation-stop set
with `model_planner` `not_configured`. Without a port the composition root derives
the deterministic identity itself, so that side needs no check. Catching the
mismatch per request, at seal, was rejected: the deployment would serve until the
first set that exposed it, and an interpretation stop never does.

### 5. Timings outside the hash, a content-derived ID

`result_sha256` covers the whole evidence set except `timings` and itself, and
`investigation_id` derives from the schema version and the request. Equal requests
over equal data therefore produce byte-identical hashed content whenever and
however fast they run. Replaying a set runs the controller again for its request
and compares everything but the timings; the responses carry no timestamps either
(see 12). A random run ID was rejected: it would make two identical investigations
look different and adds nothing a caller cannot attach.

### 6. Affectedness as a typed missing answer source

Product context (vendors, products, purls outside `protocol_context_only`) makes
`affectedness` an answer source. No adapter serves it yet, so once a call has run
it is reported `source_unavailable`, every named product gets one `unknown`
applicability entry with an explicit basis, and the run cannot end `sufficient` or
`no_match`. Reporting the CVE result alone as `ok` was rejected: it would let a CVE
match, or FiGHT similarity, read as an affectedness answer.

### 7. `TopicContextRequest.filters`

The topic-context service takes the caller's `SearchFilters` and applies them to
every template CVE search; FiGHT is never filtered. Without this, a product
question explored through the topic would return CVEs for other products.

### 8. Excluded-term tokens are stripped from free text

A topic card's exclusions (`aka`, `EPS AKA`, `EAP-AKA'`) block topic resolution
but did not stop the excluded tokens from reaching the lexical index: `EPS AKA
crash` would have searched `aka` and returned a 5G-AKA record. The tokens of every
excluded term in the query are removed from its search terms, so the query
searches `crash`, and a bare `aka` searches nothing and stops `no_evidence`.

### 9. A CVE named by ID is never dropped

When a query names CVE IDs and also resolves a topic, the exact lookup's candidates
keep their relevance assessment when they relate to the topic and are kept
unassessed (`relevance: null`) otherwise; only free-text search candidates are
dropped as unrelated. Exact identifiers dominate fuzzy evidence, and dropping a
record the caller named and the lookup found would report `no_match` for a CVE
that exists. A query naming more IDs than one lookup returns (the request's
`max_results_per_call`, at most 20, which is the lookup's backend limit) is
`policy_blocked` before any call
rather than cut short, so no named ID goes unexamined behind a `no_evidence` stop
and no lookup's limit cuts one. Bounding by the server's 20 alone was rejected: a
caller's lower cap then cut the lookup silently, and a model's ID order chose which
named CVE vanished. The answer merge puts every candidate an exact lookup found
ahead of the rest before the result cap cuts it, so a model's step order cannot
push a named CVE out either.

A named ID is found however it is written, and a malformed one is never read as
another ID. IDs are matched on a skeleton of the query, one character at a time,
and each match is mapped back to the characters it was read from. The skeleton is
what a reader sees when looking for an ID: each character NFKD-folded on its own,
invisible characters and combining marks left out (so `Ç` and `C`+U+0327 read
alike), a decimal digit of any script read as its ASCII digit. On it, `CVE` followed
by an ID's parts is a likeness: an optional word such as `ID` or `number`, then a
four-digit year and a number of four or more digits, or any two or more digit
groups, the parts apart by any run of characters other than Latin letters and
digits (spaces, punctuation, dashes, symbols, another script's text), or by nothing.
The Cyrillic, Greek, Cherokee and Lisu lookalikes of C, V and E and the Latin small
capitals count as those letters where the likeness expects `CVE`. A likeness names an
ID only when it is written exactly as one: `CVE`, a dash, four digits, a dash, four
or more digits, where any dash separates the parts (`CVE‐2021‐44228` with U+2010, as
word processors write it, is looked up) and every digit is a decimal digit that NFKC
folds to ASCII (fullwidth digits do). The year-and-number reading is tried first, so
`CVE-2021-44228 2022` still names CVE-2021-44228.

An ID is a token that ends where the next visible character could not continue it: a
number of any script, a combining mark, an underscore, a Latin letter, or anything
NFKC folds into one continues it, and so does an unassigned or private-use code point.
A letter of another script does not, because the change of script is a word boundary
and Chinese, Japanese, Korean and Thai write the next word against the ID. Invisible
characters (format controls such as zero-width spaces, soft hyphens and direction
overrides, every other default-ignorable code point such as variation selectors, the
combining grapheme joiner and Hangul fillers, and control characters other than
whitespace) are read past, so the visible neighbour decides; a combining mark before
an ID belongs to the character it follows. Inside the ID no invisible character may
hide, since a direction override can display `3000` as `0003`. So
`CVE-2021-44228漏洞`, `CVE-2021-44228เป็น` and `CVE-2021-44228`+ZWSP+`漏洞` name
CVE-2021-44228, while `CVE-2021-44228٤` (an Arabic-Indic digit), `CVE-2021-44228²`
(which whole-text NFKC would read as CVE-2021-442282), `CVE-2021-44228⒈` and
`CVE-2021-4422`+ZWSP+`8` (displayed as CVE-2021-44228) name none. A Han numeral such
as `一` is a word, not a digit, so it ends an ID like any other Han character. Under
plain Unicode word boundaries an ID against CJK text was read as free text and could
answer another CVE as `sufficient`; under ASCII boundaries `CVE-2021-44228٤` was cut
to CVE-2021-44228, and an ID against Thai text went unseen under a CJK-only boundary
list.

A token holding an ID together with anything that continues it, and a likeness not
written as an ID, are malformed identifiers: neither is looked up nor searched as
words, and a model search that holds one is rejected (`cve_id_in_search_text`). So
`CVE 2021 44228`, `CVE.2021.44228`, `CVEー2021ー44228` (the katakana prolonged sound
mark a Japanese IME writes for a dash), `CVE ID 2021-44228`, `CVE-2021-4422 8`,
`CVE-٢٠٢١-٤٤٢٢٨`, a Cyrillic Es or a small capital for the C, and a variation
selector or a control character between digits fail closed: searched as words, their
numbers would match records apart from the ID a reader takes them for. Latin letters
are not gaps, so `CVE count 2021 12345` and `CVE 2022 log4j` are not IDs, and their
words other than `cve` stay search words (`CVE 2022 log4j` searches `2022 log4j`).
A query's search terms are closed under the same rule: once stopwords and punctuation
are left out, the remaining words are read for likenesses again, `cve` still in place,
until none is left, so `CVE of 2021-44228` searches nothing and `ausf crash cve in
2021 and 2022` and `ausf crash nvdcve in 2021 and 2022` search `ausf crash`. The
policy reads its joined terms once more after dropping excluded tokens (`crash nvdcve
EPS AKA 2021 2022` searches `crash`), so it never builds a search its own gate
rejects. Tokens are found by the same rule, on the query as written, wherever IDs are
read: one module
(`domain/text.py`) serves the interpretation, the gate, the validator, the search
service and the topic registry. Unit tests sweep every number-like code point after an
ID, every invisible code point beside one, every invisible code point and combining
mark inside one, and every assigned character that neither is nor folds into a letter
or digit between or inside its parts.

`cve` and `cves` are low-signal query words (`LOW_SIGNAL_QUERY_TERMS`): every record
is a CVE, so the words discriminate none, and searched alone they match whichever
description happens to mention CVEs. A query's search text (`extract_search_text`)
is the query with its CVE-ID tokens removed first, so the `CVE` of an ID is never
read as a word and an exact lookup is untouched, then normalized, then without the
words of any ID likeness its words form (read with `cve` in place, as above) and
without those two words, repeated until neither is left, since dropping a word can
bring others together into a likeness (`nvdcve cves 2021 44228` searches nothing). Its
search terms (`list_query_terms`) are that text's tokens. A low-signal word goes
whole however it is spelt: a possessive with any apostrophe (`CVE's`, `CVE’s`) and
an invisible or control character inside it (`c`+ZWSP+`ve`) read as the plain word,
while a visible separator keeps words apart (`c ve` is two words). Only whole words
go: `nvdcve` and `cvelist` stay. The search service matches and embeds that text and
runs neither text channel when it holds no term; a query with neither a term nor an ID
(`cve`, `CVEs`) calls no lexical, semantic or graph channel and warns
`no_searchable_terms`, and its filters, which only narrow what the query finds, add no
candidate. The interpretation's search terms, the gate's vocabulary and empty-search
checks, the canonical search, the call key, the validator's searchable-text check and
the registry's template check all read `list_query_terms`, and the decision-path audit
and replay re-derive through those same functions. So `cve ausf crash` searches
`ausf crash`, a bare `cve` stops `no_evidence` (`no_searchable_terms`) before any
call, a model search of only `cve` (or `cve of 2021 44228`) is rejected
`term_outside_vocabulary` as a search with no term, and a model's `cve ausf` runs, is
keyed and is recorded as `ausf`, so it repeats an issued `ausf`. The words are
dropped on the query side only: `tokenize` builds the lexical index from every
description word. `vulnerability`, `vulnerabilities` and `vuln` stay search words,
since a caller may mean them as a search for weaknesses in general; whether to add
them is decided on the M5 and M7 gold queries and evaluation data. The rule's
compatibility record, with what it changes against M4 acceptance, is in
`../m5-mcp-and-sources.md`.

A planner cannot leave a named ID out either. The gate rejects a plan
(`missing_named_cve_id`) unless every named ID is carried by an exact lookup the
run already issued or by one of the plan's own accepted lookups; a free-text
search over the remaining terms never stands in for it. A model's round-1 plan
that omits one therefore falls back to the policy's plan, whose single lookup of
every named ID fits any budget, and round 2, which runs only after round 1 issued
its whole plan, owes no lookup. Checking only that a model's lookups name no ID
the caller did not (a subset) was rejected: a model could look up one of two named
IDs, or search the residual text instead, and the run would report `ok` or
`no_evidence` for a CVE it never queried. The decision-path audit re-gates every
recorded reply with the same check, so a resealed set cannot present such a plan
as accepted.

### 10. The network LLM adapter is deferred

M4 ships the port, the `QueryPlan` schema, the gate and a scripted test planner;
the service is complete without a model. A provider adapter follows in a separate
M4 change. It will be an optional adapter loaded through a `planner` entry point
(ADR 0001 §3) with a standard-library HTTP transport, so the core gains no
dependency, and its endpoint, model and credentials will be read at the M6
configuration boundary and passed in, never read from the environment inside the
adapter.

### 11. Served content re-checked against the service's own sources

An evidence ID derives from every other anchor field, and `result_sha256` covers
the set, but both are hashes a holder can recompute after editing an anchor, and
neither covers what a record or technique says: an anchor's `content_sha256`
hashes the raw source entry, not the served record. The final validation
therefore requires every anchor, CVE record and FiGHT technique a response serves
to equal the one an `EvidenceCatalog` of the deployment's sources holds under its
ID (a technique apart from what the search that found it matched), and every
evidence ID a trajectory step records to be one the catalog holds. The catalog is
built from the CVE bundle's records and anchors and the FiGHT source's techniques
and anchors. Signing responses was rejected: it adds key management for a
property the service can already establish by lookup, and the catalog is the same
lookup an evidence-by-ID read needs. The `get_evidence` knowledge tool serves the
catalog's anchor under an evidence ID, which a consumer compares with the anchor it
holds, and `cve-kgrag verify` (`verify_evidence_set`) runs the
validator, the audit and replay on a set handed back (ADR 0003 §10).

### 12. The trajectory is re-derived, not trusted

A resealed set can rewrite its trajectory as freely as its anchors, so the final
validation recomputes what the trajectory claims from its own parts instead of
reading recorded summaries. Each step's call key is recomputed from its call with
`compute_call_key`, and a CVE tool's backend request from its call with
`format_cve_tool_query`; both live in `domain/planning.py` and are the functions
the controller and the executor use, so there is one derivation, not a second
copy that could drift; so does `is_tool_permitted`, the gate's scope rule. Rounds
and steps are cross-checked as one run: a round lists exactly its steps, which
run the leading calls of its accepted plan in order, leave calls unrun only when
a step was not admitted or the deadline was reached, and were planned by the
planner its outcome names, with a reason the policy gives that tool in that round
(`POLICY_STEP_TOOL_AND_ROUND`); no call is accepted twice or against the scope;
outcomes match the planner kind, rejections and the recorded reply match the
outcome, the reply's hash is recomputed from the reply,
and the round, planner-call, planner-duration and `plan_accepted` counts come
from the rounds. Rounds are tied to the state machine: round 1 exactly when the
run planned and round 2 only after it refined, and the decision-path audit re-derives
whether refine planned round 2, so a round can be neither invented nor erased.
A step's observations are tied to its call: a step that got a response records
one outcome per source it consulted, a lookup's `unknown_cve_id` and
`excluded_by_filters` warnings must agree with the evidence catalog, a search warns
`term_not_indexed` only for one of its own search terms, and only a CVE
search under a semantic request runs the semantic channel. The byte cap is a pure
decision over recorded sizes, so a step is discarded over `max_context_bytes`
exactly when it would push the admitted bytes past the cap. A topic step's template
searches depend on its card, which the set does not carry, so for them the
validator checks only the count, sources and limits; the decision-path audit
and replay rebuild them from the registry's card.

Agreement between parts is not enough: a holder who rewrites a decision everywhere
it shows (the interpretation, or a policy call with its call key, accepted plan and
backend request) produces a set whose parts all agree. So the decisions themselves
are re-derived too. The controller's stop decisions are pure functions of recorded
observations (`application/investigation_decisions.py`), and the gate's context is
built from the steps issued before a plan (`build_plan_context`); so is a round's
plan, `choose_round_plan`, given the model reply the round records. A
decision-path audit (`application/decision_path_audit.py`) runs on every sealed
set after the validator and calls the same functions over the set and the topic
registry: it recomputes the interpretation and requires equality, recomputes the
interpretation stop, and every round's plan: it parses and gates the recorded reply
again in the context rebuilt from the earlier steps, so the planner outcome, the
rejection codes in order, the accepted plan (the model's in canonical form, or the
policy's fallback), each step's planner and reason, and the `model_plan_rejected`
warning must be the derived ones. It then walks the assess and refine decisions,
so the transitions, rounds, stop reason and the cap a breach names must be the
derived ones. It also rebuilds every step's backend requests from its call
and the registry's card (`list_backend_requests`, the function the controller
records them with), which binds the charge the gate's remaining budget is rebuilt
from; requires exactly the warnings the interpretation and the decisions give
(`application/investigation_warnings.py`, shared with the controller); and
recomputes the coverage's source outcomes from the admitted steps. The audit lives
in the application layer because it needs the topic registry and the policy, which
the domain validator does not import; it takes only the set and the registry, so
`verify_evidence_set` runs it on a set handed back (ADR 0003 §10).

Both checks trust a step's observations: its status, source outcomes, answer
IDs, byte size and admission, and the answer assembled from them. The set records
each response's hash, not the response, so a holder can keep a real hash and
rewrite the summary and the answer around it (a failed FiGHT call shown as served,
or an admitted response shown as discarded over the byte cap), and both checks
accept it. Replay (`application/trajectory_replay.py`, `replay_evidence_set`)
closes that gap by running the controller itself again. It builds an
`InvestigationService` over the deployment the set is checked against
(`InvestigationDeployment`: sources, catalog, pin, capabilities, call runner and
clocks), runs the recorded request, and compares the set it seals with the
recorded one over every part except the timings, naming each step field and
set-level part that differs. A run has two external inputs besides its sources,
and replay injects both. The model's replies come from `RecordedModelPort`, which
answers each round with the reply that round records; a round the record holds no
reply for gets a typed `unavailable` reply, and a recorded reply the replayed run
never asks for is left out of its round, so either shows as a `trajectory.rounds`
difference. The deadline is measured, so it is put back rather than re-derived:
`ReplayClock` moves the clock past the deadline at the checkpoint where the record
says the run found it (`find_deadline_checkpoint`), and the controller's own
checks reproduce the deadline outcome there and nowhere else. Because the replayed
run plans from what the sources return now, a source that answers differently
changes the stop, status, warnings, coverage, breach, rounds and transitions, and
replay names them; a recorded round the replayed observations do not lead to is
never run.

Two other designs were rejected. A replay that rebuilt each step and the answer
under the recorded stop and decision warnings compared the observations but kept
the recorded control path: a response that shrank under the byte cap still showed
the recorded `budget_exhausted` stop, and a round 1 that now answers still
replayed the recorded round 2. Any replay-specific re-implementation of the
controller's decisions could drift from what the controller records, which is the
drift replay exists to detect.

Replay is bounded like a run. The recorded request's own `max_wall_time_seconds`,
measured on the deployment's monotonic clock, bounds it, and every tool call runs
under the deployment's `ThreadedCallRunner`. A separate replay budget was not
added: the recorded run fit its calls in that cap, and one cap keeps one code
path. A replay that finds the deadline anywhere but at the recorded point compared
nothing and returns `ReplayTimedOut`, never a difference list, so a blocking
source fails closed. The controller announces a call's finish only for a call that
returned, so a replayed call its runner abandoned finds the deadline during the
call and cannot pass for a recorded late result's finish.

So the three checks split cleanly. The validator proves structure and catalog
content, the audit proves the decisions follow from the recorded observations and
model replies, and replay proves the recorded observations, and everything decided
from them, follow from the sources' responses. Replay needs the sources, so it is
not run at seal; `cve-kgrag verify` (`verify_evidence_set`) runs it on a set handed
back.

Re-derivation proves internal consistency, not authenticity. Whoever reseals a set
can rewrite a round's reply, its hash, the accepted plan and the steps together;
the rewrite re-derives cleanly, and nothing short of an authenticated seal can
detect it. A keyed hash over the planner's reply alone was considered and rejected:
every other recorded decision and observation would stay rewritable around it, so
it is the wrong boundary. If response authenticity is required, it needs a separate
seal over the whole response, designed in its own ADR. Where the deadline fell is
likewise taken from the record. The validator ties a `wall_time` breach to a run
wall time at or past the cap and a timed-out or late step to its finish time, but
timings are outside the hash: a rewrite that ends the run at an earlier
checkpoint, with timings to match, replays without a difference.

### 13. Source capabilities are the deployment's, and agree with the run

`source_capabilities` tells a reader what the deployment that ran the
investigation could serve, so a set that hides a planner, invents a FiGHT snapshot
or drops the list entirely misdescribes every answer in it. The composition root
computes the four source capabilities once, when it builds the deployment, and the
service appends the `model_planner` capability from the planner it is built with;
the final validation takes the result as a fourth input beside the pin and the
catalog, and the set must report exactly it. Letting the deployment carry the
planner entry too was rejected: the planner identity then entered twice, a service
built with another planner than its deployment's failed only at seal, per request,
and replay needed a helper to rewrite the entry. The list has a fixed shape (`CAPABILITY_SUBJECTS`:
`cve_search`, `mitre_fight`, `affectedness`, `semantic_channel`, `model_planner`,
once each and in that order; the states each subject can report; a version exactly
for an available CVE source, FiGHT source or model planner, a coverage exactly for
an available FiGHT source), and it is cross-checked against the run, so that a
misdescribed deployment is caught at seal too: `model_planner` describes the
trajectory's planner, an available `mitre_fight` names the pinned snapshot and an
unavailable one served nothing (and, with one outcome per consulted source on
every step, every step that consulted it records its failure), a
`semantic_channel` that cannot search (not configured, or unavailable; ADR 0004 §1)
carries no semantic hit, every search that ran it reports it unavailable for the
capability's reason, and every step that searched text under a
semantic request reports its CVE outcome unserved, and the unavailable
`affectedness` matches the coverage's affectedness outcome, which carries the
capability's detail. The
semantic capability is read from the search service the investigation uses, not
from settings, so an injected search service is described as it is wired. A
typed object with one field per subject was considered; the list keeps the wire
shape every M4 consumer already reads, and its order is fixed by validation.

### 14. Published schemas state what the server accepts

A consumer validating a payload against `schemas/v2` should not accept one the
server rejects. The published schemas state these rules:

- `schema_version` of `KnowledgeEvidenceSet`, `SearchResponse` and
  `TopicContextResponse` is a `const` of `SCHEMA_VERSION`. Parsing rejects any
  other version (`SchemaVersion` in `domain/search.py`), and each response's
  validator rejects one set on a built model.
- The planner identity is a `oneOf` of its two shapes (see 4).
- Each model validator's cross-field rule is an `if`/`then`/`else` or `oneOf` on its
  model: `ModelReply` (an `ok` reply carries plan text and no detail, a failed one
  detail and no plan text), `ToolStep` (a `timed_out` or `rejected_invalid_evidence`
  step carries nothing from a response; any other records its status and hash),
  `EvidenceAnchor` (an inference method exactly for an inferred anchor),
  `VersionRange` (an exact version or at least one bound, not both),
  `SourceOutcome` (a failed outcome names no snapshot or coverage) and
  `TopicReview` (a reviewed card names its reviewer and date, a pending one
  neither).
- Every timestamp and date carries a `pattern` (`domain/timestamps.py`) that admits
  only values the server parses: a Gregorian date from year 0001 with its month's
  days (29 February in leap years only), a time up to 23:59:59 with at most six
  fractional digits, and a required offset up to 23:59. Draft 2020-12 treats
  `format` as an annotation unless a validator opts in, so `format: date-time` alone
  accepted any string, and a shape-only pattern accepted `2026-99-99`. The server
  parses some spellings the pattern refuses, never the reverse.
- Every published pattern that ends in `$` ends in `$(?!\n)`. Python's `$` also
  matches before a final newline, so a Python validator (`jsonschema`) read
  `^CVE-[0-9]{4}-[0-9]{4,}$` as accepting `CVE-2024-0001\n`, which the server
  rejects; ECMA-262 and pydantic's Rust engine end at the value's end. A model's
  `Field(pattern=...)` keeps its bare `$`, because the Rust engine has no lookaround;
  the snapshot generator (`schema_snapshots.PublishedJsonSchema`) adds the guard to
  the published copy.
- The validator's capability shape (see 13): `source_capabilities` is one
  capability per subject in `CAPABILITY_SUBJECTS` order (`prefixItems`), each in a
  state its subject can report, with a version and a coverage exactly where that
  state names one.
- The validator's other single-payload rules: the planner kind fixes each round's
  outcome (`PLANNER_OUTCOMES_BY_KIND`) and which planner may plan a step; a round
  records the model's reply and its hash exactly when the model replied
  (`REPLIED_MODEL_OUTCOMES`); a rejected reply records at least one rejection, its
  outcome's fixed code first (`FIRST_REJECTION_BY_OUTCOME`), and a `model_rejected`
  round never starts with such a code; every other round records no rejection,
  except a policy plan the gate rejected, and never a code only a model reply
  produces (`MODEL_REPLY_REJECTION_CODES`); the stop reason fixes the statuses
  (`STATUSES_BY_STOP_REASON`); and the requested and applied scope are the
  request's. These constants live in `domain/investigation.py`, beside the models
  whose schema states them.

`ToolStep`, `VersionRange`, `SourceOutcome`, `SourceCapability`, `RoundRecord`,
`Trajectory` and `KnowledgeEvidenceSet` generate their clauses from the constants
the code checks; `ModelReply`, `EvidenceAnchor` and `TopicReview` state their two-way
rule by hand beside the model validator.

The validator's remaining rules compare one part of a set with another (counts,
transitions, coverage and warnings the steps imply; claims and evidence against
the answer) or with something outside it, and stay server-side; the field
descriptions name the ones a field carries: `result_sha256`, `investigation_id` and
evidence IDs are recomputed and a mismatch is rejected, the capabilities must be
the serving deployment's and agree with the run, served content must equal the
evidence catalog's, and the trajectory must re-derive. Expressing the planner
constraint as an `if`/`then` over the one-model `PlannerIdentity` was considered;
two models make the constraint structural in the code too, and the call sites
narrow with `isinstance`.

## Consequences

- A blocking or slow source cannot hold a run past its wall-time cap; an abandoned
  call keeps a daemon thread until it returns, so an adapter that ignores its
  timeout leaks a thread per abandoned call.
- A set carries the model's reply text, bounded by `ModelReply`'s caps, in each
  round that got one; a consumer must treat it as untrusted data, as the core does.
- A payload valid under the published schemas can still be rejected by the server
  for a rule that compares parts of the set or needs the server: a recomputed hash
  or ID, the catalog, the deployment's capabilities, the counts and coverage the
  steps imply, or the trajectory's re-derivation. A payload in another schema
  version, a planner identity of the wrong shape, a malformed timestamp or date, a
  model reply, step, anchor, version range, source outcome, review or capability
  list breaking its model's rule, or a round, planner kind, stop status or scope
  breaking the validator's single-payload rules fails the schema too.
- A model port that does not describe a model planner stops the deployment at
  start-up instead of mislabelling its sets.
- A response proves its own consistency, not its origin: authenticity of its
  anchors, CVE records and FiGHT techniques comes from re-checking them against
  the service's evidence catalog: the service does it at seal, a consumer for one
  anchor by comparing it with what the `get_evidence` knowledge tool serves, and
  `cve-kgrag verify` for a set handed back.
- A recorded trajectory that does not re-derive from its own calls, rounds,
  transitions and outcomes is rejected, so a holder cannot forge a call key,
  detach steps from the plan that ran them, or invent or erase a round without
  the validator noticing; a rewritten topic template search passes the validator
  and is caught by the audit and by replay.
- A step summary or answer rewritten over a real response hash passes the validator
  and the audit, and is caught only by replay, which needs the deployment's
  sources. `cve-kgrag verify` replays a set handed back; such a rewrite goes
  unnoticed by whoever does not replay.
- Replay reports a changed source as the changed stop, rounds and transitions a run
  gives now, not only as changed observations. It is bounded by the request's own
  wall-time cap, so a source that has become slower or blocks makes it return
  `ReplayTimedOut`, which proves nothing either way.
- A set whose interpretation, policy plans, accepted model plans, assess, refine
  and stop decisions, breach, topic searches, warnings or coverage are not the ones
  the controller's functions give over its own record is rejected, however
  consistently the forgery was applied: a rejected or failed model reply cannot be
  relabelled accepted, and an accepted plan cannot be swapped for another the gate
  would accept, because the recorded reply is parsed and gated again. A holder who
  rewrites the reply itself together with everything derived from it is not
  detected; that needs an authenticated seal over the whole response. A topic card
  edited after a set was sealed changes its hash, so the audit rejects that set
  under the edited registry.
- A set whose `source_capabilities` differ from the deployment's, break the fixed
  shape or contradict its planner, FiGHT pin, semantic channel use or affectedness
  outcome is rejected, so a holder cannot reseal it with an emptied or rewritten
  list. Adding a capability subject or state is a contract change.
- Product questions end `partial` or a failure status while the affectedness source
  is `BLOCKED_UNVERIFIED` (ADR 0003).
- `budget_exhausted` always reports `partial`, even when the plan was rejected
  before any call ran.
- Any CVE ID or active filter under `protocol_context_only` is `policy_blocked`
  rather than ignored.
- A literal-first topic search under `implementation_only` costs one extra call
  for a compact alias (`5gaka`) and saves four for a spelled-out one (`5G-AKA`).
