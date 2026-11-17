# ADR 0028 — Source version notes beside the unknown verdict

Status: proposed (2026-11-17). Builds on ADR 0003 (affectedness stays unknown), ADR 0020
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

The field is absent for a store before format 4 and an empty tuple when no block matches.

### 2. How one product's versions are read

The version entries follow the CVE record format's `versions[]` semantics:

- An entry with `lessThan` or `lessThanOrEqual` is a range from `version` (inclusive) to
  that bound; `version` `0` and a bound of `*` leave that side open. An entry without
  either bound states only its exact `version`.
- Inside a covering range, the status is the range's status changed by every entry of
  `changes` whose `at` is at or below the named version, applied in version order.
- A version no entry covers takes the product's `defaultStatus`.

Versions compare by the NVD note's numeric dotted-segment rule. `git` and
`original_commit_for_fix` entries are never compared; any other entry whose bounds or
change points fall outside the rule (e.g. `1.2.3-rc1`, `11.2.7-h8`) is uncomparable.

### 3. Outcomes

| Outcome | When |
|---|---|
| `states_affected` | The version's status, read as in §2, is `affected`. |
| `states_unaffected` | The status is `unaffected`. |
| `no_statement` | Every entry compares, none covers the version, and `defaultStatus` is absent or `unknown`. |
| `unknown` | One of the reasons below. |

`unknown` reasons, the first applying in this order: `conflicting` (covering entries or
matching products give different statuses), `truncated` (a matching product has omitted
versions or changes), `version_not_comparable`, `no_version_data`. A block's note is
`unknown` whenever any matching product's reading is, so an uncomparable or truncated
product never lets a sibling's answer stand alone.

Each note gives the source, the outcome, the matched product's verbatim vendor and
product, and the covering entry with its applied changes. Its wording names the source as
the author ("CNA <source> states version 5.4.2 is affected: range 5.0 to below 5.4.3")
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
- Version schemes outside the numeric rule (hotfix suffixes, pre-releases, `rpm` epochs,
  `git` commits) stay unknown. Per-scheme comparison is a later decision that this note
  shape can absorb as new comparable cases.
- Tests use fixture records shaped after real CVEs: a range with a backport change, a
  `git`-only kernel record, a `defaultStatus: unaffected` product, two disagreeing
  sources, and a truncated product. Before merge, a re-imported format-4 store reports the
  outcome distribution for a sample of `product --version` queries.
