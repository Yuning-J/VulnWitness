# ADR 0020 — NVD's mirrored CNA/ADP data, KEV detail and store format 4

Status: proposed (2026-11-16). Builds on ADR 0008 (importer), ADR 0009 (stores), ADR 0015
(CNVD entries), ADR 0016 (priority decisions) and ADR 0019 (public-exploit references).

## Context

NVD changed how it enriches records on 2026-04-15. KEV-listed CVEs, software the US federal
government uses and EO 14028 critical software are enriched; everything else is "Lowest
Priority" and the earlier backlog was moved to "Not Scheduled". NVD's site now shows new
status labels, but its 2.0 API and feeds keep the old values: "Not Scheduled" is still
`Deferred`, "Enriched" is `Analyzed` and "Modified After Enrichment" is `Modified`
([NVD vulnerability status](https://nvd.nist.gov/vuln/vulnerability-status), read
2026-11-16).

A sample of 4,616 CVEs from the live 2.0 API (published 2026-01-05..12, 2026-06-01..08
and the first 2,000 of 2026-10-01..08), read on 2026-11-16:

| Published | Deferred | With NVD CPE configuration | Analyzed without NVD's own CVSS v3 |
|---|---|---|---|
| 2026-01 (996) | 42% | 54% | 51% of 463 |
| 2026-06 (1,620) | 37% | 57% | 79% of 807 |
| 2026-10 (2,000) | 62% | 16% | 71% of 304 |

Exact CPE matching, NVD's own CVSS v3 and NVD's `Exploit` tags therefore cover a shrinking
share of new CVEs. The same feed now carries other sources' data that VulnWitness dropped:

- `affected[]` ("CVE Affected v1.0", added 2026-06-17): each CNA or ADP's affected products,
  with vendor, product, package name and URL, CPEs, `defaultStatus` and versions with
  `lessThan`/`lessThanOrEqual` and `versionType`. 99% of the June and October samples carry
  it; 342 products in the whole sample carry a `packageURL`.
- `metrics.ssvcV203`: SSVC v2.0.3 decision points. 93% of the June and October samples carry
  them, almost all from CISA's ADP container in the role "CISA Coordinator". Across the whole
  sample: exploitation `none` 3,343,
  `poc` 994, `active` 13; automatable `yes` 1,118; technical impact `total` 1,337.
- `cveTags`: e.g. `disputed`, `unsupported-when-assigned`, `exclusively-hosted-service`.
- `cisaVulnerabilityName` and `cisaRequiredAction` beside the KEV dates.

The KEV catalog's `vulnerabilityName`, `requiredAction`, `notes`, `cwes` and `forensicTriage`
columns are validated and hashed into the KEV anchor (ADR 0008 §6) but were not kept on
`KevEntry`. BOD 26-04 (2026-06-10) makes forensic triage part of the remediation timeline.

## Decisions

### 1. Keep the mirrored data on the record, attributed to its author

`CveRecord` holds three mirrored fields, each in feed order, and `KevEntry` holds five details:

- `source_affected`: one block per `affected[]` entry with its `source` (the CNA or ADP
  identifier as NVD gives it). Products and versions keep the CVE format's names in
  snake case. Each version keeps its `changes` entries (`at`, `status`) in feed order,
  including backport exceptions inside the stated range. `programFiles` and
  `programRoutines` are not kept.
- `ssvc`: each assessment's source, role, SSVC version, timestamp and the three decision
  points CISA scores (`exploitation`, `automatable`, `technical_impact`). Other decision
  points are not kept.
- `cve_tags`: each tag list with its source.
- `KevEntry.vulnerability_name`, `required_action`, `notes`, `cwe_ids` and
  `forensic_triage` (`yes`/`no` as CISA gives it). NVD's mirror supplies the name and
  required action; an explicit KEV catalog row still supersedes it (ADR 0008).

All of it is source text and named untrusted in tool descriptions. None of it is NVD's
analysis, and none of it changes affectedness, product matching, ranking or any checker
verdict in this ADR.

### 2. Bounded, counted, and strict on shape

NVD mirrors `affected[]` unbounded: one sampled record lists 1,468 products, another 376
versions of one product. A stored block keeps the first 64 products and each product its
first 64 versions, each version its first 64 status changes, and each product its first
16 distinct nonempty CPEs, modules and platforms. Each tag block keeps its first 16
distinct nonempty tags. `omitted_products`, `omitted_versions`, `omitted_changes`,
`omitted_cpes`, `omitted_modules`, `omitted_platforms` and `omitted_tags` count values
beyond their respective caps; duplicate and empty names do not count as omissions.

A malformed mirrored block is dropped independently: an affected block with an invalid
version/status, purl or overlong name, an SSVC assessment with invalid or repeated
decision points, or a tag block without a source does not discard the CVE or another
source's blocks. Sources are required for affected, SSVC and tag blocks. The import
report's `dropped_mirrored_blocks` counts affected, SSVC and tag blocks separately across
successfully normalized input entries, including superseded candidates, once per input
entry. A malformed top-level mirrored collection counts as one dropped block. Malformed
fields outside these mirrored collections still reject the record through the normal
normalization failure codes.

### 3. Store format 4

Stores declare `store_format_version: 4`. A reader accepts formats 1 to 4 and refuses a
record of an earlier format that carries any format-4-only field.
Earlier stores stay readable and serve records without the new data; re-import to get it.
Format 4 is unreleased. Its persisted shape includes version status changes and omission
counts in place, with `STORE_FORMAT_SCHEMA_SHA256` matching the published persisted
schemas; these fields do not introduce another format number.

### 4. Show it with its author

- Lookup text adds KEV required action and forensic triage, one line per SSVC assessment,
  CVE tags, a count of source-stated affected products and their version conditions with
  status changes and omitted-change counts.
- Report cards add "Mirrored source data": KEV detail, SSVC and tags as facts, and a folded
  list of source-stated affected versions, including status changes and omitted-change
  counts, that says VulnWitness compared none of them.
- `store coverage` counts records with source CVSS, source affected data, source affected
  versions, purls, SSVC and SSVC exploitation `poc` and `active`. It declares the store
  format and reports format-4-only counters as null for formats 1–3; source-CVSS remains
  countable in every format.

## Consequences

- New CVEs without NVD enrichment keep CNA product names, version ranges, purls and CISA's
  SSVC in the store, so later work can use them: query-side product candidates, tiered
  affectedness and SSVC-based priority facts, each under its own decision.
- cvelistV5 is not imported. NVD's mirror is used while it carries the CNA and ADP
  containers; a direct cvelistV5 overlay stays open if NVD's mirror lags or is dropped.
