# ADR 0023 — Source-named product candidates

Status: proposed (2026-11-16). Builds on the product query (`2.0.0-dev.42`), ADR 0011
(triage) and ADR 0020 (NVD's mirrored source data).

## Context

`product` answers "which CVEs are recorded for this vendor and product?" from NVD's
vulnerable CPE matches, plus description mentions for records with no CPE data. NVD no
longer enriches most new CVEs (ADR 0020: 62% of the October 2026 sample is `Deferred` and
84% has no CPE configuration). Such a record is found only when its description names the
product as consecutive whole tokens and, with a vendor given, also names the vendor.

Store format 4 keeps the CNA's own `affected[]` entries, which name vendor and product for
almost every new record, often with CPEs. VulCPE (arXiv 2505.13895) reports that more than half
of vendor names differ between sources, so exact names alone miss them; but turning a
fuzzy name match into an inventory match would contradict the inventory's meaning.

## Decisions

1. `ProductQueryResponse` gains `source_named_total` and `source_named_candidates` (at
   most 50, newest CVE IDs first, the same on every page). A candidate is a record that
   neither the CPE path nor the description path matched, but whose CNA or ADP affected
   entry names the requested vendor and product.
2. Names compare case-folded, with runs of spaces, hyphens and underscores read as one
   underscore. An entry names a pair through its own vendor and product text or through
   any of its CPEs' vendor and product components. Both requested names must hold on the
   same entry.
3. Each candidate gives the CVE ID, the naming source, its verbatim vendor and product text
   and NVD's status. Candidates are not items: they never enter `total_available`,
   `matched_products`, ordering, triage selection, exports or version notes, and their
   affectedness is not evaluated.
4. Text output lists them after the inventory under a heading that says they are not in it.

## Consequences

- An analyst triaging Open5GS sees the unenriched CVEs its CNA names, instead of an
  inventory that silently stops at the CPE data.
- Fuzzy or alias matching (e.g. CIRCL cpe-guesser) is not built; a candidate list from
  exact normalized names is the bounded step this ADR takes.
