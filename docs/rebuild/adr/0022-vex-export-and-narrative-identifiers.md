# ADR 0022 — OpenVEX export and narrative identifier checks

Status: proposed (2026-11-16). Builds on ADR 0010 (sessions and checks) and ADR 0016
(priority decisions).

## Context

Two gaps from the November 2026 survey of comparable tools and research:

- **Interchange.** Dependency-Track, Trivy, Grype and vendor PSIRTs exchange applicability
  as VEX (OpenVEX, CycloneDX VEX, CSAF VEX). VulnWitness's asset register already holds the
  analyst's `affected` / `not_affected` / `unknown` judgement with a justification, but it
  only leaves VulnWitness as HTML, Markdown or `priority.json`.
- **Narrative.** Session checks verify structured claims and leave free narrative
  unchecked. Hallucination studies of LLM-written threat intelligence (e.g. HalluCVE) find
  invented or mismatched CVE IDs, especially past a model's training cut-off. An ID is an
  exact token; whether the session ever returned it can be checked without judging the
  sentence around it.

## Decisions

### 1. `vulnwitness vex`

- Input: the asset register, an author, an issue date (`--as-of`) and optionally a session
  whose checked `priority.json` is quoted. Output: an OpenVEX v0.2.0 JSON document.
- Status mapping: `affected` → `affected`; `not_affected` → `not_affected` with the
  analyst's justification as `impact_statement` (no justification enum is inferred from
  free text); `unknown` → `under_investigation`.
- An affected statement's `action_statement` quotes the recorded recommendation and reason
  ("VulnWitness policy … recommends …"), or states that none was recorded.
- Products are `urn:vulnwitness:asset:<percent-encoded name>`; the register has no purls.
- `@id` hashes the register, the priority artifact, author and date; no clock is read.
- VulnWitness never derives a VEX status from source data; ADR 0003's rule that verified
  affectedness stays `unknown` without a verified source is unchanged.

### 2. `narrative_identifiers` in the session check report

- Every effective finding's `statement` is scanned for CVE, CWE and CNVD IDs (ASCII
  digits, bounded tokens). Each is matched against the IDs in the session's successful
  recorded responses.
- The report gives the counts and lists unrecorded IDs by finding (at most 200, with the
  full count). Text output and the HTML/Markdown report show them as warnings.
- It is advisory: it never changes `verified`, the exit code or a claim status, and a
  recorded ID is not evidence that the sentence is right.

## Consequences

- Assessments can flow into SBOM tooling without re-entry.
- An agent's narrative naming an ID it never retrieved becomes visible at check time.
- CycloneDX VEX and CSAF VEX output are not built; OpenVEX was chosen for its small,
  stable statement model.
