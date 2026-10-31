# Relevance in the investigation loop

Status: implemented. The model drives one
sourced, budgeted refined search. It does not judge whether evidence is sufficient.

## Rules

- Relevance labels take part in presentation and in the refinement decision.
- They change no need outcome and add no need status.
- `found` and `sufficient` keep their current basis: an exact lookup or a reviewed topic.
- One relevant candidate does not show that a need is covered. Labels live on the
  candidates and in the trajectory; needs keep expressing the need judgement.

## Scope of this package

- **Questions covered.** Free-text CVE investigations only: no named CVE and no resolved
  topic. `mixed` runs, but its FiGHT side is neither assessed nor refined.
- **Paths left unchanged.** The exact-lookup and topic paths.
- **When it runs.** Only when a model planner is configured, so in CLI `investigate` and
  `eval planner`. REST and MCP stay deterministic (ADR 0007).
- **At most two rounds in total.** The refined search is round 2; nothing is added
  after the policy's rounds.
- **Time budget.** Both assessor calls and the refined search count against the existing
  deadline.
- **On failure.** If the model fails or the gate rejects its proposal, the run keeps
  what round 1 found.

## The loop

**retrieve → assess → name a gap and propose one search → gate → round 2 → present**

1. **Retrieve.** The policy plans round 1, as today.
2. **Assess.**
   - One assessor call labels each admitted CVE candidate `relevant`, `not_relevant` or
     `cannot_tell`.
   - Input and prompt are those of the experiment (`relevance-assessor-experiment.md`):
     opaque keys, descriptions cut at 1,000 characters, product names and CWE IDs.
3. **Gap and proposal.** In the same reply the model may give:
   - **One gap:** `{component, reason: coverage_unclear, note}`. The component is a
     normalised word or phrase of the question. The note is a short reason, recorded and
     never acted on. The gap is a hypothesis for a refined search, not a fact the system
     can prove. It fits a run that already has relevant candidates while one component
     still looks uncovered.
   - **One `cve_search`** whose every term has a source in this investigation:
     - a search term of the question;
     - the vendor, product or parsed CPE product name of an admitted candidate;
     - a term the run's resolved topic card allows. No free-text run resolves a topic,
       so this source is empty in this package.

     Store-wide CPE names, unresolved topic aliases and CWE terms are not sources.
4. **Gate.**
   - The existing plan gate applies: query length, repeated call, scope, budget and
     deadline.
   - In addition, the gate checks that the gap has the right structure, that the
     component is a word or phrase of the question, and that every term of the search
     has a source.
   - The gate checks structure, sources and that the action is allowed. It cannot
     prove that the component has no evidence.
   - Each added term is recorded with its source: the candidate and the field it came
     from.
   - No new index or vocabulary is built.
5. **Round 2.** The search runs, and its new candidates get one more assessor call.
6. **Present.**
   - Round 1 and round 2 candidates are merged into one list.
   - The list is grouped by label: relevant, cannot tell, not relevant, then unassessed.
   - Within a group, the existing deterministic order holds: round 1 rank, then round 2
     rank.
   - The final cap of 20 applies to that order, and anything it leaves out is reported
     with the existing omission warning. So new relevant evidence can enter the answer.
   - No candidate is dropped *because of* a model label. The cap still bounds what is
     shown.
   - The answer says: *"The model assessed the candidates' relevance; the system has not
     confirmed that the evidence need is met."*
   - It never says "not assessed" once labels exist, and never presents labels as a
     sufficiency result.

## Records and checks

- The assessor replies, the labels, the gap, the proposal with each term's source, and
  the gate verdict are recorded in the trajectory, like planner replies.
- Replay uses the recorded replies.
- The validator checks the shape of the labels, that every executed term has a source,
  and the label-grouped order and the cap.
- Needs and stops are computed exactly as now.
- New optional fields on candidates and steps take one contract bump.

## How it is judged

- **Judged on the 13 baseline cases** with `eval planner --model-runs`. This is a
  development result, not an independent quality acceptance.
- **Primary measures:**
  - required items gained, measured against the gold labels, never against the
    assessor's own labels;
  - Coverage@20 before and after;
  - irrelevant items added;
  - assessor calls, tool calls and wall time.
- **Still reported:** the decision rules are unchanged, but the answers change, so the
  gold-judged stop figures (`wrong_stop`, `false_gap`) can change too. They are reported
  as a secondary measure.

## Not in this package

- Any change to need outcomes or sufficiency.
- Model planning on the servers.
- A third round.
- Assessing or refining FiGHT.
- The topic and exact-lookup paths.
- Tuning the assessor prompt.

## Development result (2026-10-31, baseline only)

`eval planner --model-runs 2` over the 13 M7b baseline cases, `deepseek-flash`, effort
`none`. A development result, not a quality acceptance.

- The assessor ran on all 16 free-text model runs, and every reply parsed.
- It named a gap and a search once: srsRAN, the negative case, "no candidate mentions
  srsRAN". The refined `srsran` search found nothing new, as it should.
- It named no gap in `gtp-mobile-core`, `oai-cn5g` or `kamailio-version-affected`, the
  free-text cases whose required coverage is below 1 (0.33, 0.67, 0.95).
- Coverage@20 and irrelevant items are unchanged in every case, and so are the
  gold-judged stop figures.
- Cost: one assessor call, with additional time per free-text run compared with the
  deterministic run.

The loop is wired and safe, and it shows labels. On this data the model labels
candidates but does not find the gaps, so no gain is measured. Eliciting gaps is the
open question.

## Re-test with one consistent runtime prompt (2026-10-31)

The runtime prompt now states both tasks and the full reply shape once. The experiment's
prompt is unchanged. Same baseline, two model runs:

- Searches proposed: 3 of 16, up from 1: `gtp-mobile-core` twice and `ueransim` once.
  One was rejected by the gate, and the others ran.
- Coverage@20 and irrelevant items are unchanged in every case. Run timing was recorded
  separately.
- **Reach.** The deterministic run misses 12 required CVEs in `gtp-mobile-core`,
  `oai-cn5g` and `kamailio-version-affected`.
  - Only 2 of them share a vendor or product term with the sourced vocabulary.
  - At least 10 of them hold a term the sources already allow in their description
    text: all five OAI misses hold `openairinterface`, the Kamailio miss holds
    `kamailio`, and several GTP misses hold `gtp`.
  - So they can enter the lexical scoring. Missing the top 20 does not mean the
    source rule makes them unreachable. Ranking, the budget cut or the merge may be
    the cause.

The term-source rule may limit targeted follow-up searches, but it is not shown to be the
main bottleneck. Before any recall change, first find where each missed record drops out
(ranking, budget truncation or the answer merge). Widening the term sources is not a
proven answer. The prompt iteration on these cases stops here.
