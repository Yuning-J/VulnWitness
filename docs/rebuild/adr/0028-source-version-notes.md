# ADR 0028 — Source version notes beside the unknown verdict

Status: accepted (2026-11-17). Builds on ADR 0003 (affectedness stays unknown), ADR 0020
(NVD's mirrored CNA/ADP data), ADR 0023 (source-named product candidates) and the NVD
version note (`nvd_version_note.py`).

## Context

Where a caller names a version (`product --version`, an investigation's "product version"
mentions, triage findings), VulnWitness compares it with NVD's CPE version conditions and
publishes an `NvdVersionNote`: a hit, a no-hit or unknown, worded as a note and never as
affectedness. NVD's conditions are missing for a growing share of records (ADR 0020).

Store format 4 keeps each CNA's and ADP's own `affected[]` data: version entries with
`lessThan`/`lessThanOrEqual`, `versionType`, status `changes` inside a range (backport
exceptions) and a product's `defaultStatus`. Measured on the NVD 2.0 feed of 2026-10-27
(427,002 records, read 2026-11-17):

| | Records |
|---|---|
| With at least one source version entry | 426,173 |
| With an entry both of whose bounds compare by the numeric dotted-segment rule, `versionType` not `git` | 170,941 |
| Without any NVD CPE configuration | 91,234 |
| …of which with such a comparable source entry | 62,480 |
| With a status change inside a range | 13,961 |

Version types across 1,646,360 entries: none given 833,837, `custom` 352,944, `semver`
236,333, `git` 129,111, `rpm` 63,119, `original_commit_for_fix` 22,935, others under 4,000.
`defaultStatus`: absent 457,578, `unaffected` 180,258, `affected` 110,822, `unknown` 106,319
products.

So for two thirds of the records NVD never configured, the CNA's own data can be compared
with a named version. Letting that comparison set applicability would contradict ADR 0003:
the data is the source's claim, its version strings follow no shared scheme, and a wrong
`affected` or `not_affected` would flow into priority decisions and OpenVEX.

## Decisions

### 1. A source version note per source, beside the NVD note

Wherever an `NvdVersionNote` is produced, the output also carries `source_version_notes`:
one `SourceVersionNote` per `source_affected` block that has a product matching the
mention, in feed order. Products match by the name rule of the entry point that produced
the NVD note, applied to the source product's vendor and product text and to its CPEs'
components with ADR 0023's normalization. Two sources that disagree get two notes; nothing
reconciles them.

A block's matching products are read together as one product. NVD's mirror splits one
product's versions over many entries (the Linux CNA's records arrive as one entry per
version), so an entry that does not cover the version says nothing against one that does.

The field is absent for a store before format 4 and an empty tuple when no block matches.

### 2. How a source's versions are read

The version entries follow the CVE record format's `versions[]` semantics:

- An entry with `lessThan` or `lessThanOrEqual` is a range from `version` (inclusive) to
  that bound. A `version` of `0`, `unspecified` or `*` and a bound of `*` leave that side
  open; CNAs use all three for an open start (`unspecified` is Mozilla's and huntr's
  convention). An entry without either bound states only its exact `version`.
- A bound or exact version ending in `.*` (`5.10.*`, the Linux CNA's convention) stands
  for every version with that prefix: `lessThanOrEqual: 5.10.*` covers all of 5.10,
  `lessThan: 5.10.*` stops before it.
- Inside a covering range, the status is the range's status changed by every entry of
  `changes` whose `at` is at or below the named version, applied in version order.
- A version no entry covers takes the matching products' `defaultStatus`.
- Entries identified by commit are skipped: `versionType` `git` or
  `original_commit_for_fix`, or bounds that are all abbreviated or full hexadecimal
  hashes (NVD's mirror labels the Linux CNA's commit ranges `custom`). They restate a
  release range in commits and cannot be compared with a release version.

Versions compare by the NVD note's numeric dotted-segment rule. Any release entry whose bounds or
change points fall outside the rule (e.g. `1.2.3-rc1`, `11.2.7-h8`, or a range written
into `version` as `>=2.0, <2.4.1`) is uncomparable. Change points take no wildcard.

### 3. Outcomes

| Outcome | When |
|---|---|
| `states_affected` | The version's status, read as in §2, is `affected`. |
| `states_unaffected` | The status is `unaffected`. |
| `no_statement` | Every entry compares and none covers the version, with `defaultStatus` absent or `unknown`; or the covering entries state `unknown`. |
| `unknown` | One of the reasons below. |

`unknown` reasons, the first applying in this order: `conflicting` (covering entries, or
without one the default statuses, differ), `truncated` (a matching product has omitted
versions or changes), `version_not_comparable` (the named version or any release entry
falls outside the rule), `no_version_data` (no release entry, and either commit entries
only or no `defaultStatus`). One uncomparable or truncated entry makes the whole note
`unknown`, so a partial reading never stands alone.

Each note gives the source, the outcome, the matched products verbatim, and the covering
entries with their applied changes. Its wording names the source as
the author ("CNA/ADP <source> states version 5.4.2 is affected: range 5.0 to below 5.4.3")
and ends with: "This is <source>'s statement; VulnWitness has not set applicability."

### 4. What does not read the notes

Applicability, the `affectedness` check, the asset register, priority facts and policies,
OpenVEX statements, triage selection and ordering, and report-card applicability read no
source version note. The asset register records no deployed version, so register-driven
outputs (priority, VEX, report cards) never produce a note. Adding a version to the
register is outside this ADR.

### 5. Checked like the NVD note

A session claim may state a source version note's outcome. It is checked against the
recorded note by mention, source and outcome, as an NVD version note claim is, and
investigation validation recomputes source notes as it recomputes NVD notes. No claim
kind turns a source note into an applicability.

## Consequences

- An analyst asking about a version of an unconfigured product sees what each CNA and ADP
  says about it, and which of their data could not be compared, instead of only "NVD has
  no condition".
- Release version schemes outside the numeric rule (hotfix suffixes, pre-releases,
  `rpm` epochs) stay unknown. Commit entries are skipped; commit-only data gives
  `unknown/no_version_data`. Per-scheme comparison is a later decision that this note
  shape can absorb as new comparable cases.
- Tests use fixture records shaped after real CVEs: a range with a backport change, a
  `git`-only kernel record, a `defaultStatus: unaffected` product, two disagreeing
  sources, and a truncated product. Before merge, a re-imported format-4 store reports the
  outcome distribution for a sample of `product --version` queries.
