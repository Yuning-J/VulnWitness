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
controller of the minimal design and the budget and identity rules of the
safety-first design.

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
`implementation_only`; a CVE tool and a direct FiGHT search (`fight_direct_search`,
see 15) cost 1. The cost is known before the call from
the card, so the plan gate rejects an over-budget plan before anything runs. Each
call is charged before it runs, and the charge stands whether the call fails,
lands late or returns invalid evidence, so retries and failures cannot hide
inside the budget. Planner calls are counted separately.

`max_results_per_call` bounds every backend request, not only the tool request:
the investigation sets `TopicContextRequest.max_results_per_search` to the cap,
so each template search a `topic_context` call fans out to, and its FiGHT search,
asks for no more, as does the one FiGHT search of `fight_direct_search`. Each step records those backend requests (source, query text or
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
card's terms, only the resolved topic, a direct FiGHT search only when the
interpretation allows one (`fight_direct_search_blocked`, see 15), no repeated call,
the round-1 baseline
sources, an exact lookup of every CVE ID the caller named (see 9), and the call and
source budgets. Any rejection rejects the whole plan,
and the round falls back to the deterministic plan, so a broken or hostile model
degrades to the production baseline instead of blocking the question; the round
records the model plan's rejections followed by any of the fallback plan's. A reply
that arrives after the deadline, or no reply by it, stops the run; a round the
deadline stops before its configured model is consulted is recorded as
`model_skipped_at_deadline`, and a round the policy plans without calling the configured
model as `model_not_consulted`, so a round's outcome always says which planner kind the
run was configured with.

A configured model plans only a question that names a CVE ID or resolves a reviewed
topic. Free text (no kept CVE ID, no resolved topic) is planned by the policy in every
scope, with the question's search terms as its baseline: product policy, not a
completeness or sufficiency guarantee and not a safety rule. A round 1 whose policy plan
is over the source budget is not given to the model either, since a round-1 model plan
must consult the same sources and so none could pass. Such a round is round 1, records
no reply and no planner call, and runs the policy's plan, or records the gate's
rejections of it and runs nothing. A free-text round whose deadline passed before
planning records `model_skipped_at_deadline`, since the deadline is checked first.

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
excluded term the registry reports in the query are removed from its search terms, so the query
searches `crash`, and a bare `aka` searches nothing and stops `no_evidence`.

The strip sees only the excluded terms the registry reports, so it relies on the
registry reading the CVE search tokens as whole words: the ASCII words of
`split_terms` (`topics/normalization.py`) are, in order, exactly the `[0-9a-z]` runs of
the once-normalized query (`TOKEN.findall(normalize_query(text))`). An ASCII run
meeting a non-ASCII letter (accented or of another script), a non-ASCII digit or a
modifier letter is a word of its own (`5Géaka threats` reports `aka` and searches
`5g threats`; `EAP-AKAʼ` with U+02BC reports `EAP-AKA'`), and an invisible format
character (Unicode Cf: zero-width space, soft hyphen) is a hard boundary no alias joins
across (`x\u200baka attacks` reports `aka`; `5g\u200baka` reports `aka` and does not
resolve 5G-AKA). The rule is on the registry side only; the CVE tokenizer and index
read words as `[0-9a-z]` runs.

There is no end-to-end guarantee that every excluded word the CVE search sends is
reported. Known exceptions:

- The CVE search terms (`list_query_terms`) normalize the query twice, and
  `normalize_query` is not idempotent. Confirmed under the current Unicode data:
  `na\u00df\u0301 threats` reads in the registry as `nass` but searches `nas`, and
  `x H\u0302\u0331 attacks` reads `\u0125` as a non-ASCII word but searches `h`. A
  card excluding `NAS` or `h` gets no exclusion reported, and the CVE side sends the
  word. The check of each search term read alone (`term_reads_as_topic`, §15) blocks
  FiGHT for it; nothing strips it on the CVE side. No packaged card has such an
  exclusion, which does not make every valid card safe.
- A Cf inside an excluded phrase splits it, so the phrase is not stripped as a whole:
  `EAP\u200b-AKA' threats` reports and strips `aka`, is blocked from FiGHT, and searches
  `eap threats`.
- A Cf inside an excluded word splits the word itself, so the exclusion is not
  recognised at all: `a\u200bka attacks` reports nothing, warns nothing, searches
  `ka attacks`, and under `mixed` or `protocol_context_only` runs a direct FiGHT search
  of `ka`, `attacks`.

The FiGHT side blocks where the CVE side strips: a query in which the registry
reports an excluded term gets no direct FiGHT search at all (see 15), because FiGHT's generic matches for the
remaining words would stand in for protocol context the caller did not ask about.

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
holds, and `vulnwitness verify` (`verify_evidence_set`) runs the
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
`term_not_indexed` only for one of its own search terms, a `fight_direct_search`
step warns `term_not_indexed` (a topic warning) only for a term of its own FiGHT
search that no technique it returned matched, and a `topic_context` step never
does, and only a CVE
search under a semantic request runs the semantic channel. An oversized response admits
its longest prefix of whole results and their referenced anchors as `admitted_prefix`.
Searches and lookups retain ranked CVE candidates; direct FiGHT searches retain ranked
techniques. Topic calls interleave implementation candidates, techniques and excluded
candidates at each rank, in that order, so both answer sections receive a head before
either receives a tail. The first non-fitting entry ends the prefix. Only when the first
entry cannot fit is the step discarded over `max_context_bytes`.

A prefix step records a compact `prefix_admission`: the complete response's sealed
`original_result_sha256`, per-list kept and omitted counts, `charged_bytes`, and
`next_result_bytes`, the additional canonical bytes the first omitted entry would need.
Its charged `context_bytes` measures the retained response's canonical JSON, including
metadata and anchors. Original response bodies are not carried in the set; omitted record
size does not grow the sealed artifact. Prefix admission is not a
breach. `evidence_prefix_omitted` names the step and omitted entry count; topic truncation
warnings include admission omissions, search-limit warnings describe the original retrieval, and
`answer_truncated` counts retrieval-limit and answer-assembly omissions separately.
The validator and audit check visible whole records, anchors, ranks, consistent per-list
counts and warnings, agreement between the witness and step charge, and
`charged <= remaining < charged + next`. Replay runs the tools against complete source
responses and reproduces the original digest, exact maximal prefix, canonical charge
and next-result increment. A consistently rewritten witness can pass the local checks;
exact response sizes after per-call metadata is lost, and omitted counts, require replay.
A search whose per-call candidates survive in the answer is reconstructed locally to
check its canonical charge and retained-prefix hash. A topic step's template
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
interpretation stop, and every round's plan: it decides again whether a configured
model was to be consulted (`is_model_consultable`), so a topic or exact-ID round cannot
be relabelled `model_not_consulted` nor a free-text round recorded as the model's, and
parses and gates the recorded reply
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
each response's hash, with a compact witness for a prefix admission, so a holder can
keep a real hash and
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
not run at seal; `vulnwitness verify` (`verify_evidence_set`) runs it on a set handed
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
  produces (`MODEL_REPLY_REJECTION_CODES`); a `model_not_consulted` round is round 1,
  and, like a `deterministic` one, records rejections only when it runs nothing
  (`POLICY_PLANNED_OUTCOMES`); the stop reason fixes the statuses
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

### 15. FiGHT from a topic card, or from the question's own words

When a topic resolves, its card owns FiGHT: only the card's name, aliases and
entities reach it, through `topic_context`. When none resolves, an investigation may
make one FiGHT search of the query's own search terms (`fight_direct_search`, which
takes no arguments, so no planner chooses its words), never past an excluded term the registry
reports (§8 lists how one can go unreported), a CVE ID the interpretation keeps, or a search term the registry reads alone as a topic
or an excluded term. The words go all or none: `interpret_request` records
`fight_block` (`topic_resolved`, `excluded_term`, `cve_id_named`,
`term_reads_as_topic`, with its subject) and `fight_terms`, every search term
without a block and none with one (`find_fight_block`, `list_fight_terms`). The
planner input, the round-1 plan, the gate, the executor, the validator and the audit
read that one rule. The policy plans it in round 1 for `protocol_context_only` free
text and, after the CVE search, for `mixed` free text; no refinement rule plans it,
and its constant call key holds a run to one. `topic_context` needs a match and
`fight_direct_search` needs none, so a run has at most one step that searches FiGHT.

A direct search's response keeps the unresolved resolution and `topic_not_resolved`,
names each sent word no technique holds (`term_not_indexed`), and gives its
techniques no topic identity; the evidence needs judge its protocol need, a word no
technique holds and the interpretation does not explain leaving it `not_found`, and
its listed techniques otherwise leaving it `matches_unassessed` (§16,
`../m7b-b-evidence-needs.md`). Both FiGHT paths order techniques by one phrase-unit
BM25 score over the sent terms (`domain/bm25.py`, shared with the CVE index), ties by
technique ID.

The investigation tool is named `fight_direct_search`, apart from the public MCP
`search_fight`, on purpose: it searches FiGHT without a card and only inside an
investigation, while `search_fight` keeps its published meaning and still requires a
resolved topic (ADR 0003).

Rejected:

- dropping the word that triggered a block and sending the rest: it bypasses the
  question whether the words may enter FiGHT, and the remaining generic words could
  meet the need falsely;
- sending the matcher's Unicode words (`5géaka`, `threats`): a second word set per
  query beside the search terms the CVE side and the interpretation record;
- a round-2 rule for `mixed` free text: the protocol need is always open after a
  CVE-only round, so it would always fire, add a reason, and never run under
  `max_rounds` 1;
- word-level BM25: the scoring unit must equal the matching unit, and word-level
  credit would let the `aka` of `5G-AKA` raise any technique that mentions EAP-AKA;
- one FiGHT order per path: a direct search needs a ranked order, and two orders over
  one source are harder to state and to check than one.

### 16. A need is found through a reviewed mapping or an exact match, never through matches of words

A need is `found` only through an exact correspondence or a reviewed mapping: an exact
lookup that returned the named CVE, or the topic call of a resolved, reviewed topic that
returned evidence. Matches of a search on the question's own words (`cve_search`,
`fight_direct_search`) give `matches_unassessed`: matches were found and their relevance
was not assessed, which is not a finding that no relevant evidence exists. The answer
keeps every match. `matches_unassessed` is open, so for a resolved topic not yet explored
the policy plans the topic call after it (R2, `topic_after_literal_miss`); with a model
configured, round 2 consults the model, whose plan may replace that call, and the run
still cannot end `sufficient` on word matches. For free text no rule applies, and the
run stops `needs_unmet` without a repeated search. One rule in
`domain/evidence_needs.py` serves the policy, the validator's stop checks, the audit and
replay.

So that a topic question reaches the reviewed mapping, the policy explores a resolved
topic in round 1 in every scope. Under `implementation_only` the topic call never
consults FiGHT (`count_tool_calls`); a literal search of a topic question is only ever a
model's plan.

The current version does not judge free-text results sufficient automatically: no
relevance judge exists for a question no reviewed topic covers, and labelling its
matches unassessed is the honest output. This is the rule of this version, not a
permanent bar on free-text sufficiency. Nor is `found` a sufficiency proof: the basis is
how the evidence was reached, not that a trusted source returned it, and a topic's card
can list CVEs that do not answer the question, so a topic run can still stop
`sufficient` wrongly.

Rejected:

- `found` when some listed candidate holds every query term: no baseline candidate does
  without a longer stopword list, and the ones that do are still lexical matches;
- matching the question's product name against stored vendor and product names: stored
  names include ordinary words (`known`, `service`, `free`, `core`, `network`, `gtp`),
  and `smf` names Simple Machines Forum;
- searching the question's literal words first for a topic under `implementation_only`:
  its hits would be `matches_unassessed` and need the topic anyway, and a spelled-out
  phrase can return a response over the byte cap whose longest whole-result prefix is
  admitted, or whose first result cannot fit and is discarded.

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
  `vulnwitness verify` for a set handed back.
- A recorded trajectory that does not re-derive from its own calls, rounds,
  transitions and outcomes is rejected, so a holder cannot forge a call key,
  detach steps from the plan that ran them, or invent or erase a round without
  the validator noticing; a rewritten topic template search passes the validator
  and is caught by the audit and by replay.
- A step summary or answer rewritten over a real response hash passes the validator
  and the audit, and is caught only by replay, which needs the deployment's
  sources. `vulnwitness verify` replays a set handed back; such a rewrite goes
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
- A topic question under `implementation_only` costs the card's template count (4 for
  5G-AKA) where a literal search would cost 1. Under a `max_tool_calls` below that count
  the policy's plan is over budget and the run stops `budget_exhausted` with no answer;
  no literal search stands in.
- A free-text answer ends `needs_unmet` / `partial` with its needs `matches_unassessed`
  and the matches listed; only a named CVE or a reviewed topic can end `sufficient`. On
  the 13 baseline cases this is measured as 4 of the 5 gold-sufficient cases reported
  `partial` with unchanged answers (`false_gap` 4/5), the price of no longer calling
  lexical matches sufficient (`wrong_stop` 4/13 to 2/13).
- `mixed` free text whose words may go to FiGHT plans two round-1 calls over two
  sources, so under `max_sources: 1` or `max_tool_calls: 1` it stops
  `budget_exhausted` with no answer, as a `mixed` topic query does.
- A query that names an excluded term gets no FiGHT search without a card: its
  protocol need is `unsupported`, with the block recorded.
