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
`fold_spelling` replaces each part inside an ASCII word.

- **CVE BM25 index:** indexed words and query words are folded alike. A query word is
  scored as its fold, once, but `matched_terms` and `term_not_indexed` name it in the
  query's own spelling.
- **FiGHT search:** technique words are folded word by word, and each sent term's alias key
  is built from folded words, so `signalling` and `signaling` share one key. Matched terms
  and unindexed terms keep the sent spelling. As before, the first spelling sent counts
  once.

The table leaves out pairs where either spelling is also another word (`analyses`,
`fulfil`/`fulfill`, `programme`/`program`). No American form contains its British form,
so folding is idempotent. Topic-card aliases, product names and CPE fields are not folded.

## Consequences

- Records and techniques written in either spelling now match a query in the other. A
  record holding both spellings counts them as one term.
- Rankings change only for queries or records containing a folded word. The M7b gold sets
  were not re-run here; the next evaluation run should record their Coverage@20 and
  `false_gap` against the 2026-10-30 figures.
- A cross-encoder reranker (P1-9's second half) is not part of this ADR.
