# M7b — work packages after the first model run

The first model-planner run ([`m7b-results-2026-10-28.md`](m7b-results-2026-10-28.md))
traced the gaps in its answers to retrieval, request interpretation and the stop rule
rather than to planning. The owner agreed the order D (the evaluation corrections in that
record), A1 (fast lexical search), A2 (terms no record holds, and an admission rule against generic-only matches), B
(per-request evidence needs and the stop rule), C (FiGHT search from the question's own
terms); each package is measured on its own. Development reads the `baseline` cases and
synthetic queries only; the `holdout` cases, read once in the first run, are read again
only after the agreed packages.

On 2026-10-30, while the mixed-script follow-up to C was analysed, a search of
`eval/gold/m7b_cases.yaml` printed the request lines (query and scope) of the four
holdout cases. No label or other field was read, and nothing from them shaped a design or
a measurement. The owner ruled that the four requests count as seen, so they are no
longer a strict blind test; with their labels unseen and unused for tuning, they remain a
validation set evaluated once, and they guide no further design.

## A1 — lexical search without per-record objects

Lexical search is an inverted index that builds a match object only for the results it
returns. Its results are byte-equal to the per-record scan it replaced on 1,056 searches
over the 2026-10-27 store; [`PLAN.md`](PLAN.md#follow-ups-from-m6-adr-0009) gives the
timings.

## A2 — terms no record holds

Each search term no record holds is named in a `term_not_indexed` search warning (contracts
`2.0.0-dev.27`). The lexical outcome carries them as `unindexed_terms`, sorted and once
each, only on success; the search service accepts only terms it sent the channel, and
evidence-set verification accepts the warning only for a search term of a step whose
lexical channel ran. Ranking is A1's: every record holding a search term is ranked, so
`srsRAN vulnerabilities` still answers with records matching `vulnerabilities`, and says
that no record names `srsran`.

**An admission rule, measured and not adopted.** A2 also measured ranking a record only
when it holds a specific term of the query: a term held by no more records than the larger
of 1,000 and 1% of the records, or by none. Over the 2026-10-27 store (396,211 records) that makes
`vulnerabilities` (12,185 records), `affected` (46,472), `known` (4,282), `core` (8,344),
`2` (114,519) and `de` (303,750) generic, and keeps `huawei` (2,376), `5g` (1,309),
`kamailio` (20) and `free5gc` (108) specific.

**Its effect on the 13 baseline cases** (deterministic runs, against the same runs without
the rule; answer IDs classified by the gold sets):

| Share | Removed: required / allowed / irrelevant / unjudged | Added | `wrong_stop` | Implementation coverage |
|---|---|---|---|---|
| none | — | — | 7/13 | 0.827 |
| 0.5% | 0 / 0 / 0 / 38 | 1 required, 1 irrelevant | 6/13 | 0.833 |
| **1%** | 0 / 0 / 0 / 38 | 1 required, 1 irrelevant | 6/13 | 0.833 |
| 2% | 0 / 0 / 0 / 36 | — | 6/13 | 0.827 |
| 5% | — | — | 7/13 | 0.827 |

At 1%:

- `srsran-negative` drops all 20 answers, each matching only `vulnerabilities`, and stops
  `no_evidence` with `term_not_indexed` for `srsran` instead of `sufficient`; its judged
  sufficiency stays `insufficient`, and it is no longer a wrong stop.
- `ueransim` drops 16 of 20 answers that matched only `vulnerabilities`; the 4 UERANSIM
  records remain and the run stays `sufficient`.
- `kamailio-version-affected` trades one unjudged answer for one required CVE.
- `gtp-mobile-core` trades one unjudged answer for one the gold rules label
  irrelevant.
- No required or allowed item is lost; the other nine cases are unchanged. Judged
  sufficiency is 5 sufficient, 6 partial, 2 insufficient with and without the rule.

0.5% also makes `huawei` generic, which the synthetic queries below show costs answers;
5% leaves `vulnerabilities` below the threshold and changes nothing.

**Synthetic queries**, written before the measurement and not taken from the gold file
(top 20, 1% against no rule):

| Query | Effect |
|---|---|
| `kamailo vulnerabilities`, `openlte vulnerabilities` | 20 generic answers become none, with `term_not_indexed` for the unknown word |
| `nextepc vulnerabilities` | 20 answers become the one NextEPC record |
| `volte vulnerabilities` | 20 answers, 8 of them VoLTE records, become all 11 VoLTE records |
| `ericsson network manager vulnerabilities` | 6 answers matching only generic words give way to Ericsson records |
| `huawei 5g core vulnerabilities` | unchanged (at 0.5%, `huawei` is generic and 8 answers without `5g` are lost) |
| `buffer overflow`, `linux kernel use after free`, `cisco ios xe vulnerabilities`, `magma core vulnerabilities`, `nokia vulnerabilities`, `lte enodeb vulnerabilities`, `srs ran vulnerabilities`, `free5gc amf` | unchanged |

**Phrasing variants and alternatives.** A rare word is not necessarily a subject word.
Further pre-registered queries, each with the words a relevant record must name, compare
the rule with two alternatives: a record must cover half the query's summed term weight
(IDF), or a term is specific only if it also occurs in some record's vendor or product
name. Each cell gives results in the top 20 and how many name the subject:

| Query (subject) | No rule | 1% rule | Half the weight | Vendor or product names |
|---|---|---|---|---|
| `list recent linux kernel use after free` (linux, kernel, free) | 20/20 | 20/11 | 20/20 | 20/11 |
| `linux kernel use after free 2023` (linux, kernel, free) | 20/20 | 20/10 | 20/20 | 20/10 |
| `kamailo flaws`, `srsran bugs`, `openlte weaknesses` (no such records) | 20 unrelated each | 20 unrelated each | none | none, except 20 unrelated for `srsran bugs` |
| `any known kamailio vulnerabilities` (kamailio) | 20/18 | 20/20 | 20/4 | 20/20 |
| `ericsson network manager vulnerabilities` (ericsson) | 20/14 | 20/20 | 20/13 | 20/20 |
| `huawei 5g core security problems` (huawei) | 20/6 | 20/6 | 3/2 | 20/7 |

On the baseline cases' own searches, half the weight loses required items (`oai-cn5g` 10
to 0, `kamailio-version-affected` 19 to 7). Vendor or product names lose the `ueransim`
gain, since `ueransim` is in no product name and its search falls back to every record,
and two required items of `5g-aka-implementations`.

The owner did not adopt the rule (2026-10-29). A rare filler word becomes specific and
excludes every record without it before scoring: with 1,001 Linux use-after-free records
and one unrelated record holding `recent`, `recent linux kernel use after free` returns only
the unrelated record. That is lost recall, which no later stop decision can bring back;
the baseline cases' gains do not outweigh it. No vendor list, filler-word list or further
threshold is added; whether matches answer the question is the assessment's job (B), and
"has a CVE" does not by itself meet an implementation evidence need.

## C — FiGHT search from the question's own words

The design and the owner's decisions are in
[`m7b-c-fight-direct-search.md`](m7b-c-fight-direct-search.md). Each stage (C1, C1 + C1b,
C1 + C1b + C2) is measured against the dev.29 run before the next is added.

**Pre-registered synthetic queries.** Registered before any synthetic run of C, with the
words a relevant technique must hold. None names a holdout subject (NAS, Diameter, PJSIP).
Each runs as a deterministic investigation over the 2026-10-27 store and FiGHT 3.1.0 with
default budgets; per stage the table reports `fight_terms` or the block, the matched and
listed technique counts, how many of the top 10 and top 20 hold a subject word, the
`term_not_indexed` words, the protocol need's outcome and the stop. A subject word held by
a technique is a crude, word-level check, not a relevance label.

| Query | Scope | Subject words |
|---|---|---|
| `SS7 location tracking attacks` | protocol_context_only | ss7 |
| `IMSI catcher threats` | protocol_context_only | imsi |
| `fake base station attacks` | protocol_context_only | base, station |
| `network slicing attacks` | protocol_context_only | slice, slicing |
| `NRF service discovery abuse` | protocol_context_only | nrf |
| `SEPP roaming interconnect threats` | protocol_context_only | sepp |
| `authentication vector theft from the home network` | protocol_context_only | authentication, vector, vectors |
| `LTE downgrade attacks` | protocol_context_only | downgrade, bidding |
| `GTP-U TEID guessing` | protocol_context_only | teid |
| `GTP tunnel attacks against the UPF` | protocol_context_only | gtp |
| `UPF user plane threats` | protocol_context_only | upf, user, plane |
| `UDM threats` | protocol_context_only | udm |
| `AMF attacks` | protocol_context_only | amf |
| `SIP IMS signalling attacks` | protocol_context_only | sip, ims |
| `SIP IMS signaling attacks` | protocol_context_only | sip, ims |
| `PFCP session manipulation threats` | protocol_context_only | pfcp (FiGHT holds none) |
| `Bluetooth pairing attacks` | protocol_context_only | bluetooth (none) |
| `MQTT broker threats` | protocol_context_only | mqtt (none) |
| `WPA3 Wi-Fi handshake attacks` | protocol_context_only | wpa3, wifi, wi (none) |
| `srsRAN vulnerabilities` | mixed | srsran (none) |

**Exclusion table.** Each issues no FiGHT step and records the block: `aka attacks`,
`EAP-AKA' threats`, `5G, aka NR GTP threats` (`excluded_term`), `EPS AKA crash` under
both `protocol_context_only` and `mixed` (`excluded_term`), `5Géaka threats`
(`excluded_term`, `aka`; C as measured below recorded `term_reads_as_topic`, see
[C follow-up](#c-follow-up--mixed-script-words)), `CVE-2024-37877 GTP threats` under
`mixed` (`cve_id_named`).

**Measured on the 13 baseline cases.** Deterministic runs over the 2026-10-27 store and
FiGHT 3.1.0 with default budgets, `gold-sets --check` passed before each. The dev.29 row
is a clean checkout of c1b5b8a; each stage row is a working tree on that commit, whose
diff (new files included), its SHA-256 and the run settings stay with the run under
`~/data/cve-kgrag/`. The holdout cases ran with the others and were not read.

| Row | Code | Diff SHA-256 | Run (under `runs/c-stages/`) |
|---|---|---|---|
| dev.29 | c1b5b8a, clean | — | `dev29/planner-93_xb68r` |
| C1 | c1b5b8a + diff | `f14e17b2edd9d214625851d7010b9a6facc9c0586857b7d1f3db1dda757c0eaa` | `c1/planner-sc82a8yi` |
| C1 + C1b | c1b5b8a + diff | `92f33035c1f60c35c7c131d9de75ab7f96e4618d05c7753113b97471ccbcaf69` | `c1b/planner-h9mrj05n` |
| C1 + C1b + C2 | c1b5b8a + diff | `bb4a86324674aa0a488ca75b65a15cceefe88ea956cf106397a30dd528c70bfe` | `c2/planner-zxfwa9np` |

| Figure | dev.29 | C1 | C1 + C1b | C1 + C1b + C2 |
|---|---|---|---|---|
| `wrong_stop` | 3/13 | 5/13 | 4/13 | 4/13 |
| Protocol coverage, mean over 3 | 0.222 | 0.347 | 0.347 | 0.556 |
| Protocol irrelevant items | 0 | 5 | 5 | 7 |
| Implementation coverage, mean over 8 | 0.827 | 0.827 | 0.827 | 0.827 |
| `false_gap`, `unflagged_gap`, `premature_no_evidence` | 0 | 0 | 0 | 0 |
| `need_agreement` | 13/13 | 13/13 | 13/13 | 13/13 |

- Every case lists the same CVEs in the same order in all four rows; C changes only
  FiGHT evidence and the stops that read it. Judged sufficiency stays 5 sufficient, 6
  partial, 2 insufficient.
- `gtp-mobile-core` (mixed, no topic) runs `cve_search` and `fight_direct_search` in
  round 1. Its protocol coverage goes 0.0 → 0.375 (C1) → 1.0 (C2), and it stops
  `sufficient` from C1 on. That is a wrong stop: its implementation coverage is 0.333,
  a shortfall B's needs cannot see. It stays an open quality gap, not offset by the
  coverage gain.
- `sip-ims-threats` (labelled insufficient) no longer stops before planning. Under C1 it
  stops `sufficient`, a wrong stop. With C1b, `signalling` is held by no technique, so
  the protocol need is `not_found` and the run stops `needs_unmet`, with its techniques
  listed. That saving rests on the spelling: `signaling` is held (below). Its irrelevant
  items in the top 20 are 5 under the count order and 7 under BM25.
- `5g-aka-threats` and `5g-aka-implementations` keep their steps, needs and stops. C2
  replaces 5 of their 20 listed techniques with 5 others, all labelled allowed, and
  their coverage stays 0.333; FGT5044 is still cut at the limit. They remain wrong stops
  for the card-term review.
- `oai-cn5g` remains the fourth wrong stop (CVE top-20 ranking, untouched by C).

The owner accepted C on 2026-10-30 as a widening of FiGHT retrieval, not as an
improvement of investigation quality overall: `wrong_stop` rises from 3/13 to 4/13,
protocol irrelevant items rise to 7, and C1b's verdict depends on spelling. These stay
open quality gaps.

**Synthetic queries, measured.** The protocol need and stop under C1 and C1 + C1b
(the FiGHT order is the same in both), the words a direct search warned no technique
holds, and the subject check under C1 + C1b and under C2. Every synthetic query issued a
`fight_direct_search` step with no block, so its `fight_terms` are all of its search terms
(§2.1 of the design). The matched and listed counts are the same in every stage, since
the order decides only which matches the limit keeps:

| Query | Matched / listed | C1: need, stop | C1 + C1b: need, stop | Unheld words | Subject in top 10 / 20 (C1b → C2) |
|---|---|---|---|---|---|
| `SS7 location tracking attacks` | 60 / 20 | found, `sufficient` | found, `sufficient` | — | 4/6 → 5/8 |
| `IMSI catcher threats` | 16 / 16 | found, `sufficient` | not_found, `needs_unmet` | `catcher` | 7/12 → 8/12 |
| `fake base station attacks` | 60 / 20 | found, `sufficient` | found, `sufficient` | — | 9/14 → 8/17 |
| `network slicing attacks` | 146 / 20 | found, `sufficient` | found, `sufficient` | — | 0/2 → 3/4 |
| `NRF service discovery abuse` | 124 / 20 | found, `sufficient` | found, `sufficient` | — | 3/4 → 7/8 |
| `SEPP roaming interconnect threats` | 31 / 20 | found, `sufficient` | found, `sufficient` | — | 5/5 → 5/5 |
| `authentication vector theft from the home network` | 148 / 20 | found, `sufficient` | found, `sufficient` | — | 6/12 → 5/7 |
| `LTE downgrade attacks` | 34 / 20 | found, `sufficient` | found, `sufficient` | — | 1/3 → 3/3 |
| `GTP-U TEID guessing` | 16 / 16 | found, `sufficient` | found, `sufficient` | — | 3/4 → 4/4 |
| `GTP tunnel attacks against the UPF` | 60 / 20 | found, `sufficient` | found, `sufficient` | — | 5/8 → 8/8 |
| `UPF user plane threats` | 71 / 20 | found, `sufficient` | found, `sufficient` | — | 10/19 → 10/20 |
| `UDM threats` | 20 / 20 | found, `sufficient` | found, `sufficient` | — | 3/9 → 5/9 |
| `AMF attacks` | 53 / 20 | found, `sufficient` | found, `sufficient` | — | 2/5 → 8/10 |
| `SIP IMS signalling attacks` | 36 / 20 | found, `sufficient` | not_found, `needs_unmet` | `signalling` | 3/4 → 5/6 |
| `SIP IMS signaling attacks` | 64 / 20 | found, `sufficient` | found, `sufficient` | — | 4/5 → 6/6 |
| `PFCP session manipulation threats` | 38 / 20 | found, `sufficient` | not_found, `needs_unmet` | `pfcp` | 0/0 → 0/0 |
| `Bluetooth pairing attacks` | 28 / 20 | found, `sufficient` | not_found, `needs_unmet` | `bluetooth`, `pairing` | 0/0 → 0/0 |
| `MQTT broker threats` | 3 / 3 | found, `sufficient` | not_found, `needs_unmet` | `mqtt`, `broker` | 0/0 → 0/0 |
| `WPA3 Wi-Fi handshake attacks` | 29 / 20 | found, `sufficient` | not_found, `needs_unmet` | `wpa3` | 1/1 → 1/1 |
| `srsRAN vulnerabilities` (mixed) | 14 / 14 | found, `needs_unmet` | not_found, `needs_unmet` | `srsran` | 0/0 → 0/0 |

- **C1b's gain:** the PFCP, Bluetooth, MQTT, WPA3 and srsRAN queries, whose subject FiGHT
  does not hold, no longer meet the protocol need on generic matches. **Its cost:**
  `IMSI catcher threats` is judged a gap although 12 of its 16 techniques name IMSI; the
  step's warning names `catcher`, and the techniques stay listed. **Its sensitivity:**
  the two SIP queries differ only in spelling and get opposite verdicts. A need C1b
  leaves `found` is not shown to be semantically sufficient.
- **C2's order:** subject techniques in the top 10 sum to 66 → 91 and in the top 20 to
  113 → 128. It gains most on `AMF attacks`, `NRF service discovery abuse`,
  `network slicing attacks` and `GTP tunnel attacks against the UPF`, and loses on
  `authentication vector theft from the home network` (top 20: 12 → 7) and
  `fake base station attacks` (top 10: 9 → 8). No outcome or stop changes with the order.
- **Exclusion table:** every query issued no FiGHT step and recorded its block:
  `aka attacks`, `EAP-AKA' threats`, `5G, aka NR GTP threats` and `EPS AKA crash` under
  both scopes (`excluded_term`); `5Géaka threats` (`term_reads_as_topic`, `aka`);
  `CVE-2024-37877 GTP threats` under `mixed` (`cve_id_named`), which ran its exact
  lookup only. The protocol need is `unsupported` in each, except the last, which
  derives no protocol need.

## C follow-up — mixed-script words

**Problem.** ADR 0002 §8 strips the tokens of every excluded term from the CVE search
terms, but it sees only the exclusions the topic registry reports, and the two sides read
words differently. The CVE side (`domain/text.tokenize`) reads a word as a run of
`[0-9a-z]`; the registry read it as a run of any Unicode letters and digits, after
deleting format characters (Cf). So `5Géaka threats` was one registry word, `5géaka`,
reporting nothing, while `cve_search` sent `5g aka threats` with no `excluded_term`
warning; only C's `term_reads_as_topic` check kept the word from FiGHT. The same leak
came from any accented or other-script letter, non-ASCII digit or Hangul filler written
against `aka` (`éaka`, `ㅤaka`, `٥aka`, `αaka`), from U+02BC (`EAP-AKAʼ threats` sent
`eap aka threats`; its top hit, CVE-2026-78126, is on the irrelevant list of
`5g-aka-implementations`), from a Cf between an ASCII word and `aka`
(`x\u200baka attacks` sent `x aka attacks`), and from such a word alone (`éaka`
searched `aka` instead of stopping `excluded_terms_only`). The leak is on the query side
only: all 16,276 records holding `aka` hold it as a standalone word.

**The rule** (`topics/normalization.py`; contracts `2.0.0-dev.31`, policy `m7b.3`). The
registry reads the CVE search tokens as whole words, with the exceptions under Known
limits:

- A word boundary falls wherever a run of ASCII letters and digits meets a non-ASCII word
  character (a non-ASCII letter or digit, a modifier letter such as U+02BC, a Hangul
  filler) with nothing between. A run of non-ASCII letters and digits stays one word, and
  each ideograph is one word.
- A format character (Cf: zero-width space, soft hyphen) is a hard boundary no alias joins
  across. It is neither deleted before splitting nor read as joining whitespace. This is
  an intended tightening: `5g\u200baka` and `5G\u00ad-AKA` no longer resolve 5G-AKA and
  report the excluded `aka`. Ordinary spaces, hyphens and underscores are unaffected
  (`5G-AKA`, `5G AKA`, `5gaka`, `5G-AKA协议` still resolve).
- A local property, pinned by a test: for every query, `TOKEN.findall(normalize_query(q))`
  equals the ASCII words of `split_terms(q)`, in order. It is about the once-normalized
  query; the search terms themselves (`list_query_terms`) normalize twice, so it does not
  make every excluded word the CVE search sends a reported one.

The existing pieces then apply unchanged: the §8 strip, the `excluded_term` warning, the
`excluded_terms_only` stop, C's `excluded_term` FiGHT block, the gate vocabulary (a model
plan searching `aka` for `5Géaka threats` is rejected `term_outside_vocabulary`), the
validator and the audit. `5Géaka threats` now searches `5g threats` with the warning and
is blocked `excluded_term` (`aka`); `EAP-AKAʼ threats` searches `threats`; `éaka` stops
`excluded_terms_only` with the warning. The CVE tokenizer and the BM25 index are
unchanged. `term_reads_as_topic` stays: reading the registry code shows it is still
reached by cards the schema allows (the first known limit below), where it is FiGHT's only
guard. The gold row `5Géaka` in `eval/gold/m3_topic_queries.yaml` now expects
`excluded: [aka]`.

**Rejected options**, measured on store `nvd-2026-10-27` and FiGHT 3.1.0 with the options
applied in memory to 09cb28b, deterministic runs with default budgets:

- **A, strip each term the registry reads alone:** `eap` still leaks from `EAP-AKAʼ`, the
  strip gives no warning, the interpretations of 2 baseline cases change
  (`5g-aka-threats` and `5g-aka-implementations` lose `aka`; answers identical), and the
  validator needs a change.
- **B, block the run** when an excluded word (B_excl) or any topic word (B_any) is read
  alone: `5Géaka threats` stops outright with no warning, B_any needs a new stop basis,
  and neither is better than the rule on any probe.
- **C, a Unicode `tokenize`:** the BM25 tokens of 303,899 of 396,211 records change
  (vocabulary 407,024 → 411,504 terms, mean length 120.93 → 117.78), the CVE order
  changes in 8 of 13 baseline cases, `naïve parser crash` goes from found to not_found,
  and every leak shape unblocks FiGHT (`EAP-AKAʼ threats` sends `eap` to FiGHT).
- **D, the word rule without the Cf rule:** misses `x\u200baka attacks`; in 20,000 seeded
  fuzz queries 235 still sent an excluded token, against 0 under D2 measured with Cf as a
  joinable separator (apart from the whole-word spellings below); not re-measured with Cf
  as a hard boundary.

Measured cost of the rule before implementation (in memory, Cf then joinable rather than
a hard boundary): relevance unchanged for all 396,211 records; one FiGHT index word
changes (`özeren`, in 2 strings); 13 of 13 baseline cases byte-identical apart from the
version fields; 29 of 30 synthetic queries unchanged (only `5Géaka`); of 71 non-holdout
gold queries only the `5Géaka` row of `m3_topic_queries.yaml` changes.

Known limits, not addressed here. There is no end-to-end guarantee that every excluded
word the CVE search sends is reported:

- The CVE search terms normalize the query twice, and `normalize_query` is not
  idempotent. Confirmed under the current Unicode data: `na\u00df\u0301 threats` reads in
  the registry as `nass` but searches `nas`; `x H\u0302\u0331 attacks` reads `\u0125` as a
  non-ASCII word but searches `h`. With a card excluding `NAS` or `h`, no exclusion is
  reported and the CVE side sends the word; `term_reads_as_topic` blocks FiGHT, and
  nothing strips the word on the CVE side. No packaged card has such an exclusion, which
  does not make every valid card safe. Follow-up: make the query normalization
  idempotent, as its own measured change.
- The strip removes the excluded term's tokens, not the query's own words, so
  `eapaka threats` and `epsaka crash` send `eapaka` and `epsaka` (no record holds
  either; `term_not_indexed`).
- A Cf inside an excluded phrase splits it. `EAP\u200b-AKA' threats` reads `eap` and
  `aka'`: `aka` is still reported, warned and stripped, and FiGHT is still blocked, but
  the phrase is not stripped as a whole, so `eap` reaches the CVE search
  (`eap threats`; `EPS\u200bAKA crash` sends `eps crash`). The extra words can bring in
  unrelated results; they do not make the exclusion of `aka` fail. This follows from
  the owner's choice of Cf as a hard boundary (2026-10-30) and is accepted. Stripping by
  the reported exclusion's span would not fix it, since the reported exclusion is `aka`
  alone; recognising a split phrase as a whole would be its own change.
- A Cf inside an excluded word splits the word itself, so the exclusion is not recognised
  at all and the query is treated as free text:
  `a\u200bka attacks` reads `a`, `ka` and sends `ka attacks`, with no exclusion reported
  and no warning, and under `mixed` or `protocol_context_only` a direct FiGHT search of
  `ka`, `attacks` runs; `e\u00adps aka crash` reports `aka` and sends `e ps crash`.
  Invisible characters can therefore change what an exclusion covers.
- Ordinary accented words still fragment on the CVE side (`café` searches `caf`).

**Measured** against a clean dev.30 run of 09cb28b (store `nvd-2026-10-27`, FiGHT 3.1.0,
default budgets, `gold-sets --check` passed). The fix's working-tree diff has SHA-256
`9008e3c1a1e1c3dd8f5b59746f4c2a1015f40da47d444c906d520bf6197cee3b`; runs under
`runs/d2-stages/` (`dev30/planner-c_p2xx4e`, `d2/planner-h2_u8st4`).

- **13 baseline cases:** every evidence set equal to dev.30 apart from version fields,
  identifiers and timings; the figures are unchanged (`wrong_stop` 4/13, protocol
  coverage 0.556, protocol irrelevant items 7).
- **C's 27 synthetic and exclusion queries:** unchanged except `5Géaka threats`, whose
  block becomes `excluded_term` (`aka`).
- **Leak probes**, 27 queries under all three scopes (81 runs): no run sends the excluded
  `aka`; the only runs that send the word are `5G-AKA threats` and `5G AKA threats`, where
  it belongs to the resolved alias. Every accent, other-script, non-ASCII-digit,
  Hangul-filler, U+02BC and Cf-before-a-word shape now reports the exclusion, warns and
  strips it (`5Géaka threats` sends `5g threats`; `EAP-AKAʼ threats` sends `threats`;
  `éaka` and `ㅤaka` alone stop `no_evidence` instead of searching `aka`), and none reaches
  FiGHT. `5gakaé threats` resolves 5G-AKA. As decided, `5g\u200baka attacks` no longer
  resolves 5G-AKA and reports `aka` (under `mixed` it stops `budget_exhausted` instead of
  `sufficient`), and `a\u200bka attacks` loses its exclusion (above). The ASCII controls
  (`aka attacks`, `EAP-AKA' threats`, `5G-AKA threats`, `5G AKA threats`, `5gaka threats`)
  and the accented non-telecom queries (`Café WiFi router overflow`,
  `Müller GmbH gateway`, a Spanish query, `naïve parser crash`) are unchanged.
