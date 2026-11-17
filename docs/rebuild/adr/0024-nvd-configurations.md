# ADR 0024 — Keep NVD configurations that say more than the product list

Status: proposed (2026-11-17). Extends ADR 0020 (store format 4) and ADR 0008 (importer).

## Context

The affected product list holds each named NVD CPE match marked `vulnerable`. The
configuration tree supplies three further kinds of information:

- **AND configurations.** NVD writes "firmware X is vulnerable when it runs on hardware Y" as
  an AND of a vulnerable node and a non-vulnerable, running-on node. The product list
  alone cannot express that condition.
- **Open ranges.** A match with only `versionEndExcluding` states that every earlier version
  is affected. NVD often writes it when the first affected version is unknown, and research
  on NVD ranges ([VERCATION](https://arxiv.org/pdf/2408.07321)) finds many such ranges too
  wide. Version notes must make the open side visible.
- **Unnamed CPEs.** A vulnerable CPE can name no vendor or product
  (`cpe:2.3:h:qualcomm:-:-:…`), although the record's other matches are usable
  (`docs/rebuild/PLAN.md`).

Of 4,616 NVD 2.0 records from 2026 (the ADR 0020 sample), 1,778 have a configuration and
679 have an AND configuration with a running-on platform. No 2.0 configuration has more than
two nodes or nested nodes. One record has 299 such configurations and one node has 101
matches. Of the CPE matches with a range, 1,115 have only an end, 707 have both bounds and 1
has only a start.

## Decisions

1. **Store format 4 holds `configurations` and `omitted_configurations`.** A configuration is
   kept only when it says more than `affected`: an AND of nodes or several matches within
   a node, a negated node, a non-vulnerable match, or a vulnerable CPE naming no vendor or
   product. A plain OR of named, vulnerable
   CPEs is `affected` already and is not repeated. Caps: 512 configurations per record, 8
   nodes per configuration and 128 matches per node. Beyond those caps, configurations and
   matches are counted, not stored. Format 4 is unreleased; its pinned schema includes
   these fields and the platform summary. NVD 1.1 trees are not kept, since
   1.1 is archival only.
2. **NVD 2.0 retains unnamed CPEs.** Such a match is left out of `affected` and
   kept in `configurations`, so the record and its named products are imported. NVD 1.1
   refuses a record with an unnamed vulnerable CPE because it retains no configuration tree.
3. **Nothing evaluates a configuration.** Affectedness stays `unknown`. A version-note hit
   carries:
   - `range_gaps` (`no_lower_bound`, `no_upper_bound`);
   - `required_platforms`, the running-on CPEs an AND configuration or node pairs with the
     matched CPE **and version range**. At most 16 unique names are stored in feed order,
     and `omitted_platforms` counts the rest;
   - wording that says "only together with" only when that exact CPE/range has no
     platform-free occurrence; mixed occurrences are described as alternatives.
   The record's `platform_conditions` summarizes these pairings and the platform-free
   occurrence flag before any configuration, node or match cap, including plain OR
   configurations omitted from the retained tree. Tree truncation cannot erase a pairing
   or reduce its omitted-platform count. These source pairings do not evaluate a tree.
   Lookup text and the session report list the kept configurations.
4. **The configuration text is untrusted source text**, like `affected` and
   `source_affected`.

## Consequences

- A firmware hit on a device-specific CVE says which hardware NVD pairs it with, and a
  "before X" hit says the first affected version is not stated. Neither changes a
  sufficiency or applicability decision.
- In the sample, 15% of records keep a configuration (p50 4 matches, p99 478).
- Re-importing a store that excluded the 18 unnamed-CPE records includes those records.
  Store diffs show them as `added`.
