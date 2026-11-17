# ADR 0022 — OpenVEX export, narrative identifier checks and session seals

Status: proposed (2026-11-16). Builds on ADR 0010 (sessions and checks) and ADR 0016
(priority decisions).

## Context

Assessment interchange and narrative integrity serve separate needs:

- **Interchange.** Dependency-Track, Trivy, Grype and vendor PSIRTs exchange applicability
  as VEX (OpenVEX, CycloneDX VEX, CSAF VEX). VulnWitness's asset register holds the
  analyst's `affected` / `not_affected` / `unknown` judgement with a justification.
  HTML, Markdown and `priority.json` serve local triage; OpenVEX provides structured
  assessment exchange using local asset identifiers.
- **Narrative.** Session checks verify structured claims and leave free narrative
  unchecked. Hallucination studies of LLM-written threat intelligence (e.g. HalluCVE) find
  invented or mismatched CVE IDs, especially past a model's training cut-off. An ID is an
  exact token; whether the session ever returned it can be checked without judging the
  sentence around it.

## Decisions

### 1. `vulnwitness vex`

- Input: the asset register, an author, an issue date (`--as-of`) and optionally a session
  whose checked `priority.json` is quoted. Output: an OpenVEX v0.2.0 JSON document.
  The session check must pass and the priority artifact's register digest must match
  the supplied register. No assessment may be dated after the document's issue date.
- Status mapping: `affected` → `affected`; `not_affected` → `not_affected` with the
  analyst's justification as `impact_statement` (no justification enum is inferred from
  free text); `unknown` → `under_investigation`.
  The analyst's justification for `affected` and `unknown` is carried in `status_notes`;
  an unknown assessment without a justification says applicability remains unknown.
- An affected statement's `action_statement` quotes the recorded recommendation and reason
  ("VulnWitness policy … recommends …"), or states that none was recorded.
- Products are `urn:vulnwitness:asset:<percent-encoded name>`; the register has no purls.
  Tools matching VEX products to SBOM components by purl or CPE need an explicit mapping
  from these local asset identifiers before they can apply the assessments.
- `@id` hashes the register, the priority artifact, author and date; no clock is read.
- VulnWitness never derives a VEX status from source data; ADR 0003's rule that verified
  affectedness stays `unknown` without a verified source is unchanged.

### 2. `narrative_identifiers` in the session check report

- Every effective finding's `statement` is scanned for CVE, CWE and CNVD IDs (ASCII
  digits, bounded tokens). Each is matched against the IDs in the session's successful
  recorded responses' returned knowledge. Request echoes, interpretations, query-based
  diagnostics, unavailable affectedness requests and verification reports are excluded.
- The report gives the counts and lists unrecorded IDs by finding (at most 200, with the
  full count). Text output and the HTML/Markdown report show them as warnings.
- It is advisory: it never changes `verified`, the exit code or a claim status, and a
  recorded ID is not evidence that the sentence is right.

### 3. `session seal` and `session verify-seal`

- OWASP's MCP Top 10 (MCP08) names the absence of audit integrity. A session's own digests
  show consistency, not that no one rewrote a response and its digest together.
- `seal` writes `seal.json`: format version, `hmac-sha256`, a 16-hex-digit key ID derived
  from the key, the SHA-256 of `session.json`, `priority.json` when present and every entry
  under `calls/` and `responses/`, and an HMAC over the canonical list. Each selected entry
  must be a regular file; links and other file types are refused. `verify-seal` recomputes
  both and names changed, added and removed files. Adding, editing or removing `priority.json`
  after sealing invalidates the seal, including regeneration that changes its bytes;
  verify or reseal after running `prioritise`.
- Editable files (`findings.yaml`, `triage.json`) are not sealed. The key
  is read from a file outside the session, 32 to 4096 bytes, and never written anywhere.
- An HMAC proves integrity only to key holders; a public signature (e.g. Sigstore) is not
  built.

## Consequences

- Assessments can be exchanged as OpenVEX using local asset identifiers. Applying them
  in purl/CPE-matching SBOM tools requires a separate asset-to-component mapping.
- An agent's narrative naming an ID it never retrieved becomes visible at check time.
- CycloneDX VEX and CSAF VEX output are not built; OpenVEX was chosen for its small,
  stable statement model.
