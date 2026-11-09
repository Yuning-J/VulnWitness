# ADR 0016 — Priority decisions under a named policy

Status: accepted (2026-11-08). Builds on ADR 0010 (sessions), ADR 0011 (triage), ADR 0012
(reports), ADR 0014 (local UI) and ADR 0015 (CNVD entries).

## Context

Prioritising a vulnerability asks three questions of a CVE: does it affect our asset
(triage), how urgent is it (priority), and what obligation applies (compliance). ADR 0015 keeps each authority's verdict with its provenance. This ADR turns
recorded verdicts into a recommendation that states its reasons, so the same inputs always
give the same answer.

Official bases, as checked on 2026-11-08:

- **GB 44495-2024 (China, vehicles).** Clause 7.1 (1) covers external connection systems,
  meaning systems with remote-control functions and authorised third-party applications.
  These must not have "high and above" vulnerabilities that an authoritative platform
  published six months earlier and that are not yet handled. The in-vehicle software
  update system carries the same requirement. Handling includes removing the
  vulnerability or putting mitigations in place.
  - Sources: the MIIT explanation of draft amendment No. 1 (August 2025), whose text was
    read; the official record of amendment No. 1, published and effective on 2026-01-28
    (std.samr.gov.cn).
  - The draft explanation is historical. The final amendment text has not been read, so
    the current wording ("权威漏洞平台" or "汽车行业权威漏洞平台") and the type-approval
    transition periods remain to be verified.
- **GB 44495 application guide** (§3.3.1, §3.3.26). Its index text was read through a
  search tool; the full file could not be downloaded. It says:
  - authoritative platforms include NVDB-CAVD;
  - "high" follows the platform's own scoring rules;
  - "six months" means 180 calendar days before vehicle sample delivery;
  - a handling plan with a reasonable deadline counts as handling.

  Status: index text checked; the full document is still to be obtained.
- **NVDB-CAVD.** No public page reachable on 2026-11-08 states how its data can be
  accessed or what grade scale it uses. VulnWitness has no CAVD input.
- **CISA BOD 26-04** (issued 2026-06-10), read on cisa.gov:
  - It binds US federal civilian agencies and revokes BOD 22-01 and BOD 19-02.
  - Its Table 1 sets remediation timelines from public exposure, KEV listing, automatable
    and technical impact. The timelines run from 3 days with forensic triage to "fix on
    system upgrade".
  - It does not bind an automaker. It is cited only as a public example of a
    decision-table policy.

The facts VulnWitness records per CVE:

- whether the CVE is in the imported KEV snapshot;
- NVD's own CVSS v3 score and its status;
- the CNA scores;
- the CNVD grades.

It does not have CAVD records, exploitation evidence beyond KEV, automatable or
technical-impact values, CNVD publication dates, or any asset inventory.

## Decisions

### 1. Two outputs, kept apart

Each (asset, CVE) pair gets two separate results:

- **Action recommendation.** One of `act`, `attend`, `track` or
  `manual_triage_required`, from a named VulnWitness policy. A recommendation is never a
  compliance statement, and its reasons never say a regulation requires the action.
- **Compliance status.** One per regulation the asset's markets bring in:
  `basis_insufficient`, `not_applicable`, `not_met` or `met`. It is never inferred from
  the recommendation.

With no authoritative-platform input, the GB 44495 vulnerability status is
`basis_insufficient` for every in-scope asset. Its reason names what is missing:

- the platform record;
- its grade;
- its publication date;
- the reference date;
- the handling evidence.

CNVD grades are triage reference and never stand in for the authoritative platform's
grade.

### 2. Explicit inputs only

- **A recorded session (ADR 0010).** Its lookups are the only source of CVE facts.
  Evaluation calls no service and loads no store.
- **An asset register (YAML, `format_version: 1`, written by the analyst).**
  - Per asset: its name, its markets, and its GB 44495 system category
    (`external_connection`, `software_update`, `other` or `unknown`).
  - Per (asset, CVE): applicability (`affected`, `not_affected` or `unknown`), with a
    justification, who assessed it and when.
  - The register is validated at the boundary. Unknown never counts as `not_affected`.
- **A policy file.** A packaged YAML decision table with `format_version: 1`.
- **A reference date (`--as-of`).** Required; nothing reads the clock. It is the date the
  evaluation is made for, using the given inputs; it does not reconstruct history. When
  the session's data was retrieved after that date, the artifact says the evaluation
  used information from after the reference date.

### 3. The facts the policy reads

| Fact | Values | Source |
|---|---|---|
| applicability | `affected`, `not_affected`, `unknown` | asset register |
| system category | `external_connection`, `software_update`, `other`, `unknown` | asset register |
| KEV | `listed`, `not_listed_in_snapshot`, `unknown` | recorded lookup and the dataset's KEV input |
| high grade | `present`, `absent`, `none_available` | NVD's own CVSS v3 and CNVD grades in the recorded lookup |

- KEV is `unknown` when the dataset imported no KEV snapshot or the lookup does not say.
  `not_listed_in_snapshot` names the snapshot's retrieval date, and it is never read as
  "not exploited".
- The high-grade fact is `present` when NVD's own v3 severity is HIGH or CRITICAL or any
  CNVD entry is 高. It is `absent` when grades exist and none is high. It is
  `none_available` when no authority grade is usable.
- A CNA score never stands in for NVD's (ADR 0015 §5).

### 4. The demonstration policy `cn-auto-demo`

This is VulnWitness's own triage policy, not a regulation. The rules are ordered, and the
first rule whose conditions all hold wins:

1. applicability `unknown` → `manual_triage_required` (applicability not assessed);
2. `not_affected` → `track`, citing the analyst's justification;
3. `affected`, KEV `listed`, category `external_connection` or `software_update` → `act`;
4. `affected`, KEV `listed` → `attend`;
5. `affected`, category `unknown` → `manual_triage_required` (system category unknown);
6. `affected`, category `external_connection` or `software_update`, high grade
   `present` → `attend`. The reason names which authority's grade triggered the rule; a
   CNVD 高 is "the CNVD high grade triggered this policy rule";
7. `affected`, KEV `unknown` → `manual_triage_required` (KEV status unknown);
8. `affected`, category `external_connection` or `software_update`, high grade
   `none_available` → `manual_triage_required` (no usable grade);
9. otherwise → `track`.

A grade alone never produces `act`. When positive evidence escalates a pair (rules 3, 4
and 6), the result still lists every input that remained unknown.

### 5. Identity, explanation and determinism

The decision artifact (`priority.json`) carries:

- the product contract `schema_version` and the program version;
- the policy's name, its `format_version` and the SHA-256 of its canonical content;
- the session's dataset identity and the digests of the responses it used;
- the asset register's SHA-256;
- the reference date and the after-reference-date flag.

Each result gives:

- the matched rule and its conditions;
- every fact it used, with its value and evidence IDs;
- every fact that was unknown;
- every earlier rule that did not match, with the conditions that failed. Because the
  first match wins, these failed conditions are exactly what would have to change for an
  earlier rule to apply.

No hypothetical re-evaluation is performed. Rule order, result order (asset name, then CVE
ID) and JSON serialisation are fixed, so the same inputs give byte-identical output.

### 6. Where it runs

```sh
vulnwitness prioritise SESSION --assets FILE --policy cn-auto-demo --as-of DATE
```

- The command writes `priority.json` into the session atomically, as `triage.json` is
  written.
- The session report and the local UI show a "Priority decisions" section, with the
  compliance status shown separately.
- MCP and REST tools are not part of this ADR.

### 7. Acceptance

The demonstration uses four cases on the real store, each answering four questions: why
this recommendation, where the evidence comes from, what is unknown, and what change
would alter it. The cases are:

1. a KEV-listed CVE, `affected`, `external_connection` → `act`;
2. NVD has no own v3 score and CNVD grades 高, `affected`, in scope → `attend`, with the
   reason naming CNVD;
3. the analyst records `not_affected` → `track`;
4. `affected`, not KEV-listed and category `unknown` → `manual_triage_required`.

Regression tests use frozen synthetic sessions and registers, not the live store. They
also cover:

- both grades missing;
- KEV `unknown`;
- KEV `listed` with category `unknown` (rule 4);
- a CNA primary score present without NVD's own score (it gives no high grade);
- the after-reference-date flag;
- byte-identical output on repeated runs.

## Consequences

- No claim of automated compliance. CAVD access and the final GB 44495 amendment text
  are preconditions for any `met` or `not_met`.
- New schemas for the asset register and the decision artifact, and a contract version
  bump.
- Further markets add policy files and regulation entries, not new code paths.
