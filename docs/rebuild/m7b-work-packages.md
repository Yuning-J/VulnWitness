# M7b — work packages after the first model run

The first model-planner run ([`m7b-results-2026-10-28.md`](m7b-results-2026-10-28.md))
traced the gaps in its answers to retrieval, request interpretation and the stop rule
rather than to planning. The owner agreed the order D (the evaluation corrections in that
record), A1 (fast lexical search), A2 (terms no record holds, and an admission rule against generic-only matches), B
(per-request evidence needs and the stop rule), C (FiGHT search from the question's own
terms); each package is measured on its own. Development reads the `baseline` cases and
synthetic queries only; the `holdout` cases, read once in the first run, are read again
only after the agreed packages.

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
