# ADR 0027 — Fold British spellings to American ones for lexical matching

Status: proposed (2026-11-17). Amends ADR 0002 §8 (term matching) for matching only.

## Context

The M7b holdout's `nas-threats` request reported a sufficient answer as a gap in all five
runs (`false_gap` 5/10). The direct FiGHT search warned `term_not_indexed` for `signalling`,
because FiGHT spells it `signaling`. The packaged FiGHT excerpt has 17 `signaling` and 1
`signalling` ([m7b results](../m7b-results-2026-10-30.md)). The same split runs through CVE
descriptions: CNAs write `authorisation`, `sanitised` and `behaviour` beside `authorization`,
`sanitized` and `behavior`.

## Decision

`domain/text.py` holds `SPELLING_FOLDS`, a fixed table of British word parts and their
American forms (`signall`→`signal`, `authoris`→`authoriz`, `behaviour`→`behavior`, …).
`fold_spelling` replaces each part wherever it occurs inside an ASCII token, including
longer names: `centreon`→`centeron`, `workcentre`→`workcenter` and
`wptravelly`→`wptravely`. It is a substring replacement table, not a dictionary of words.

- **CVE BM25 index:** tokens from descriptions, affected vendor and product names, and
  CWE IDs, plus query tokens, are folded alike. A query word is
  scored as its fold, once, but `matched_terms` and `term_not_indexed` name it in the
  query's own spelling.
- **FiGHT search:** technique words are folded word by word, and each sent term's alias key
  is built from folded words, so `signalling` and `signaling` share one key. Matched terms
  and unindexed terms keep the sent spelling. The first spelling sent counts
  once.

The table leaves out pairs where either spelling is also another word (`analyses`,
`fulfil`/`fulfill`, `programme`/`program`). No American form contains its British form,
so folding is idempotent. Stored source text, vendor/product names and CPE strings retain
their spelling. Exact product-field matching, source-named candidate matching and
topic-card alias matching do not fold spellings; BM25's vendor/product tokens do. CPE
strings are not indexed as BM25 fields.

## Consequences

- Records and techniques written in either spelling match a query in the other. A
  record holding both spellings counts them as one term.
- Rankings change only for queries or records containing a folded word. The M7b gold sets
  were not re-run here; the next evaluation run should record their Coverage@20 and
  `false_gap` against the 2026-10-30 figures.
- A cross-encoder reranker (P1-9's second half) is not built. The 2026-10-31 recall
  diagnosis of the six baseline cases found 127 of 130 required misses ranked beyond the
  answer limit, but 117 belong to free5gc and open5gs-amf, whose required sets exceed the
  limit of 20 (the `product` inventory lists them all). In gtp-mobile-core the top 20 are
  filled by records labelled allowed; only oai-cn5g loses places to records matching
  generic words alone, which a lexical rule can address without a model. The relevance
  assessor experiment, which judged returned candidates, moved Coverage@20 from 0.768 to
  0.753.
