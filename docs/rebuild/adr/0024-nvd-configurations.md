# ADR 0024 — Keep NVD configurations that say more than the product list

Status: proposed (2026-11-17). Extends ADR 0020 (store format 4) and ADR 0008 (importer).

## Context

The importer turned each NVD CPE match marked `vulnerable` into an affected product and
dropped the rest of the configuration tree. Three kinds of information were lost:

- **AND configurations.** NVD writes "firmware X is vulnerable when it runs on hardware Y" as
  an AND of a vulnerable node and a non-vulnerable, running-on node. Without the tree, the
  firmware looked vulnerable on any hardware.
- **Open ranges.** A match with only `versionEndExcluding` states that every earlier version
  is affected. NVD often writes it when the first affected version is unknown, and research
  on NVD ranges ([VERCATION](https://arxiv.org/pdf/2408.07321)) finds many such ranges too
  wide. VulnWitness showed these hits like any other.
- **Unnamed CPEs.** 18 records in the real store were refused at import because a vulnerable
  CPE named no vendor or product (`cpe:2.3:h:qualcomm:-:-:…`), although their other matches
  were usable (`docs/rebuild/PLAN.md`).

Of 4,616 NVD 2.0 records from 2026 (the ADR 0020 sample), 1,778 have a configuration and
679 have an AND configuration with a running-on platform. No 2.0 configuration has more than
two nodes or nested nodes. One record has 299 such configurations and one node has 101
matches. Of the CPE matches with a range, 1,115 have only an end, 707 have both bounds and 1
has only a start.

## Decisions

1. **Store format 4 gains `configurations` and `omitted_configurations`.** A configuration is
   kept only when it says more than `affected`: an AND, a negated node, a non-vulnerable
   match, or a vulnerable CPE naming no vendor or product. A plain OR of named, vulnerable
   CPEs is `affected` already and is not repeated. Caps: 512 configurations per record, 8
   nodes per configuration and 128 matches per node. Beyond those caps, configurations and
   matches are counted, not stored. Format 4 was not yet released, so the pinned format-4
   schema digest changes instead of adding a format 5. NVD 1.1 trees are not kept, since
   1.1 is archival only.
2. **Unnamed CPEs no longer refuse a record.** Such a match is left out of `affected` and
   kept in `configurations`, so the record and its named products are imported.
3. **Nothing evaluates a configuration.** Affectedness stays `unknown`. A version-note hit
   now carries:
   - `range_gaps` (`no_lower_bound`, `no_upper_bound`);
   - `required_platforms`, the running-on CPEs an AND configuration pairs with the matched
     CPE. At most 16 are stored, and `omitted_platforms` counts the rest;
   - wording that says both in plain text.
   Lookup text and the session report list the kept configurations.
4. **The configuration text is untrusted source text**, like `affected` and
   `source_affected`.

## Consequences

- A firmware hit on a device-specific CVE now says which hardware NVD pairs it with, and a
  "before X" hit says the first affected version is not stated. Neither changes a
  sufficiency or applicability decision.
- In the sample, 15% of records keep a configuration (p50 4 matches, p99 478). The average
  record, all format-4 fields included, is about 4.9 kB of JSON.
- The 18 refused records are imported after a re-import. Store diffs show them as `added`.
