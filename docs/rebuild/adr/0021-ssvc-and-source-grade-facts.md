# ADR 0021 — SSVC, source-grade and forensic-triage priority facts

Status: proposed (2026-11-16). Builds on ADR 0016 (priority decisions), ADR 0019
(public-exploit references) and ADR 0020 (NVD's mirrored source data).

## Context

ADR 0016's policy reads NVD's own CVSS v3 and CNVD grades for its high-grade fact, and
ADR 0019 reads NVD's `Exploit` reference tags. Both depend on NVD analysts. In the October
2026 sample of ADR 0020, 62% of new records are not scheduled for NVD enrichment, and 71%
of the enriched ones have no NVD-owned CVSS v3. For most new CVEs, both facts are
therefore `none_available` or `not_referenced_in_record`, which says nothing about the CVE.

Store format 4 keeps two sources that do cover them:

- CISA's SSVC decision points from its ADP container (role "CISA Coordinator"), on 93% of
  the June and October samples: `exploitation` (`none`, `poc`, `active`), `automatable`
  (`yes`, `no`) and `technical_impact` (`partial`, `total`). Vulnrichment publishes them
  under CC0.
- CVSS metrics from the CNA or another ADP. ADR 0015 §5 keeps them apart from NVD's own,
  and ADR 0016 §3 forbids letting one stand in for NVD's.

KEV also has a `forensicTriage` column (ADR 0020), which BOD 26-04 ties to remediation.

## Decisions

### 1. Five new facts, from the recorded exact lookup only

| Fact | Values | Source |
|---|---|---|
| exploitation | `active`, `poc`, `none`, `unknown` | the CISA Coordinator SSVC assessment on the exact record |
| automatable | `yes`, `no`, `unknown` | same assessment |
| technical_impact | `total`, `partial`, `unknown` | same assessment |
| source_high_grade | `present`, `absent`, `none_available` | CVSS v3.x or v4.0 metrics not owned by NVD (`nvd@nist.gov` or `NVD`) |
| forensic_triage | `yes`, `no`, `unknown` | the record's KEV entry |

- The SSVC facts read the first assessment in feed order whose role is `CISA Coordinator`.
  Each records that assessment's source, role and time. With no such assessment, or no
  exact lookup, they are `unknown`. `exploitation none` is CISA's assessment at its stated
  time, not a statement that no exploit exists.
- `source_high_grade` is `present` when any non-NVD CVSS v3.x or v4.0 metric has severity
  HIGH or CRITICAL, and names each triggering scorer with its CVSS version. It is `absent`
  when such metrics exist and none is high, and `none_available` when none exists. It is a
  separate fact: `high_grade` keeps ADR 0016's meaning, and `cn-auto-demo` does not read
  the new fact.
- `forensic_triage` is `unknown` when the CVE is not KEV-listed or the KEV source did not
  carry the column.
- Every known value cites the record's NVD (or KEV) evidence IDs; nothing is fetched.

### 2. A second demonstration policy, `exploitation-demo`

A packaged VulnWitness policy that reads the new facts. It is not CISA's SSVC decision
tree and not BOD 26-04's Table 1, whose final text VulnWitness has not encoded. The rules
are ordered; the first match wins:

1. applicability `unknown` → `manual_triage_required`;
2. `not_affected` → `track`, citing the analyst's justification;
3. `affected`, KEV `listed` → `act`;
4. `affected`, exploitation `active` → `act`;
5. `affected`, exploitation `poc`, automatable `yes` → `act`;
6. `affected`, exploitation `poc` → `attend`;
7. `affected`, technical impact `total`, automatable `yes` → `attend`;
8. `affected`, exploitation `unknown`, KEV `unknown` → `manual_triage_required`;
9. otherwise → `track`.

`cn-auto-demo` is unchanged and still decides from ADR 0016's facts; its decisions list
the new facts as inputs and, when unknown, among the unknown facts.

### 3. Reports

The priority report adds the new facts to its fact table, names the SSVC assessor and time,
and the source-grade scorers, and states that `exploitation none` is not "no exploit".

## Consequences

- Policies can tell a CVE with a public proof of concept from one with none known even when
  NVD never enriches it.
- A pre-release contract change: `priority.json` artifacts written before this change no
  longer validate and are regenerated with `prioritise --force`.
- `source_high_grade` uses the scorer's own label; a CNA's high score is that CNA's view.
