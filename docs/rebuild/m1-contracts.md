# v2 contracts after M1

Schema version `2.0.0-dev.1` (pre-release until M7). Snapshots: `schemas/v2/`
(`search_request`, `search_response`, `cve_record`, `evidence_anchor`, plus a
`manifest.json` of SHA-256 hashes). Regenerate with `vulnwitness schema export`;
`tests/contract/test_schema_snapshots.py` fails on any drift.

## Where each invariant is enforced

| Invariant | Enforced by |
|---|---|
| A CVE record is `record_kind: cve`, `protocol_design_claim: not_established`, `formal_seed_eligible: false` | `Literal` types on `CveRecord` (`domain/cve.py`); JSON Schema `const`; construction fails otherwise |
| A CVE candidate is scoped `implementation_vulnerability` | `validate_search_response` (`domain/validation.py`) |
| `formal_protocol_finding` is never originated | `find_anchor_violations`, `find_claim_violations` |
| An anchor for a CVE record or from NVD/CISA KEV is `implementation_vulnerability`, and a CVE candidate cites only such evidence (CVE evidence cannot be relabeled as protocol context) | `find_anchor_violations`, `find_candidate_violations`; `InMemoryKnowledgeRepository` rejects such anchors at construction |
| A claim cites only anchors of its own scope (no CVE behind a protocol-context claim, no protocol context behind an implementation claim) | `find_claim_violations` |
| An asserted claim never rests on inferred evidence | `find_claim_violations` |
| An inferred anchor names its `inference_method`; an asserted one does not | `EvidenceAnchor` model validator |
| Every cited evidence ID resolves; every candidate has an anchor for its own record (no invented IDs) | `find_candidate_violations`; `SearchService` raises if a retriever returns an ID the repository lacks; `InMemoryKnowledgeRepository` rejects records citing unknown evidence |
| Missing source data stays missing | optional/empty fields, reported per candidate in `missing_fields` |
| An anchor's evidence ID binds every provenance field: `ev:` and the first 24 hex digits of the SHA-256 of the canonical JSON of all other anchor fields (source name and type, record, URI, version, retrieval time, content hash, locator, excerpt, scope, assertion kind, inference method, terms, trust level), so changing any of them changes the ID | `derive_evidence_id` (`domain/evidence.py`), applied by every adapter through `seal_evidence_anchor`; `find_anchor_violations` recomputes it |
| Every anchor, CVE record and FiGHT technique a response serves is one the service's configured sources hold, field for field (a technique apart from the `matched_fields` and `matched_terms` of the search that found it) | `find_served_violations` (`find_uncatalogued_anchor_violations`, `find_uncatalogued_record_violations`, `find_uncatalogued_technique_violations`) against the `EvidenceCatalog` (`domain/evidence_catalog.py`), an `InMemoryEvidenceCatalog` built in the composition root: `SearchService` checks against one of its bundle's records and anchors, the topic-context and investigation services against one of the CVE records and anchors and the FiGHT source's techniques and anchors |
| Responses are replayable | `result_sha256` over canonical JSON, recomputed and checked by the validator; injected fixture timestamps; ties broken by CVE ID |
| Fixture integrity | manifest SHA-256 per file; `FixtureIntegrityError` on mismatch; evidence IDs derived by the loader, never authored |

The validator runs on every `SearchService.search` result before it is returned;
a violation raises `EvidenceValidationError` instead of producing output.

`result_sha256` and evidence IDs are integrity, not authenticity: they show a
response is internally consistent, but anyone holding it can alter an anchor,
recompute its ID, rewrite the citations and reseal the hash, or rewrite what a
record or technique says behind its genuine anchors (an anchor's `content_sha256`
hashes the raw source entry, not the served record). Served content is authentic
when each anchor, CVE record and FiGHT technique equals the one the service's
`EvidenceCatalog` holds under its ID; the service re-checks this before
returning. A consumer holding a response checks one anchor by comparing it with
what the `get_evidence` knowledge tool serves, the catalog's anchor under that ID, and
`vulnwitness verify` (`verify_evidence_set`) runs the validator, the decision-path audit
and replay on a knowledge evidence set handed back (ADR 0003 §10).

## Search behavior

- Exact channel: CVE IDs found in the query (case-insensitive) are looked up
  directly. Found IDs rank above all other candidates in request order; unknown
  IDs produce an `unknown_cve_id` warning and no candidate.
- Lexical channel: BM25 over descriptions, vendors, products and CWE IDs, run on
  the query's search text (`extract_search_text`): the query minus its CVE IDs, the
  words of any ID likeness its words form (`CVE of 2021-44228`), and the low-signal
  words `cve` and `cves`, which the index itself keeps. Each hit records its raw
  score, matched fields and matched terms.
- Fusion: reciprocal-rank fusion (k = 60). `relevance_score` is relevance only;
  severity stays in `record.cvss`.
- Status: `ok` with candidates, `no_match` without. The remaining statuses exist
  in the frozen taxonomy and are emitted once backends that can fail exist (M2).

## Known M1 limitations

- `5gaka` finds nothing lexically (one token); topic resolution is M3.
- `SourceType` only has `synthetic_fixture`; values arrive with their adapters.
- Claims are modelled and validated but not yet produced; they appear in the
  M4 investigation result.
