# M2 retrieval and normalization

Schema version `2.0.0-dev.4` (pre-release). The core stays offline and
deterministic; semantic retrieval is an explicit optional capability.

## Search semantics

- `SearchFilters` supports vendor, product, package URL, CWE, CVSS severity,
  vulnerability origin, publication year and KEV membership. Values within a
  field are ORed; populated fields are ANDed. Every request constraint lives in
  a field type, with strict booleans, JSON-Schema integers (whole numbers; no
  strings or booleans) and patterns ECMA-262 and pydantic read alike, so the
  committed request schema accepts exactly the requests the model accepts
  (`tests/contract/test_request_schema_agreement.py`): at most 20 unique values
  per field, bounded lengths (CWE IDs 16 characters, names 128, purls 512), CWE
  IDs and severities in canonical upper case. Values are kept exactly as sent;
  vendors, products and purls match case-insensitively inside the structured
  index. A purl filter names a package without version, qualifiers or subpath and
  matches every version of it.
- The lexical and semantic channels read the query's search text
  (`extract_search_text`: the query without its CVE IDs, without the words of any ID
  likeness its words form, and without the low-signal words `cve` and `cves`) and run
  only when it holds a search term; a text of only IDs, ID likenesses, stopwords and
  low-signal words is neither matched nor embedded. A query with neither terms nor
  CVE IDs, including a whitespace-only one and a bare `cve` or `CVEs`, is answered
  `no_match` with a `no_searchable_terms` warning, whatever channels and filters were
  requested: it calls no lexical, semantic or graph channel.
- Filters only constrain. The structured channel runs first; its matching set is
  passed into the exact-ID, lexical, semantic and graph channels. Each applies its
  `limit` to records that satisfy the filters, or reports `unavailable` when it
  cannot (a semantic adapter whose store cannot take the filter set). A structured hit is attached to
  each surviving candidate as an inspectable reason but neither creates a
  candidate nor adds relevance. A requested CVE ID the filters exclude produces an
  `excluded_by_filters` warning.
- If the structured backend fails, the search stops: no other channel runs, no
  candidate is returned, and the status is that backend's failure status. A
  failed filter never widens the result to unfiltered matches.
- A channel that returns a record outside the filter set, or a record no
  repository holds, makes the search raise `EvidenceValidationError`. Every match
  is checked, including those the limit would drop. An outcome that lists one CVE
  twice, or a non-finite score, is rejected at construction.
- The graph channel is opt-in with `graph_expand=true`. Its seeds are the records
  the exact-ID, lexical and semantic channels matched. It follows only relations a
  record asserts: CWE, and the vendor, vendor/product, CPE and package (purl
  without version) of products not marked `unaffected`. The lexical index likewise
  indexes only those products' vendor and product names. Each graph hit lists its
  `graph_paths`
  (seed, relation, value). It performs no inferred CVE-to-protocol mapping.
- Fusion orders candidates in tiers: exact-ID hits in request order, then direct
  lexical/semantic matches, then graph-only neighbours, each tier by reciprocal-
  rank fusion with CVE-ID tie-breaks. Graph neighbours fill only the places direct
  matches leave free.
- Every backend returns `RetrievalOutcome(status, matches, failure)`. A failed
  outcome cannot carry matches, a successful one cannot carry a failure, and a
  failure is a typed `BackendFailure` reason such as `search_failed`. The server
  publishes its own fixed sentence for the reason (`BackendFailureDetail`), never an
  adapter's text or exception text, so no local path or adapter prose reaches a
  response and the result hash is machine-independent. Adapters log the full
  exception.
- Any unavailable, incomplete or failed backend prevents `ok`/`no_match`. If a
  candidate was found or another retrieval channel (exact-ID, lexical, semantic or
  graph) succeeded, the status is `partial`; otherwise it is `backend_error`,
  `incomplete_index` or `source_unavailable`, in that order of precedence. A
  successful structured filter alone does not make a response `partial`, because
  filters only constrain.

## Evidence scope

An anchor whose authoritative record is a CVE ID, or whose source is NVD or CISA
KEV, must be scoped `implementation_vulnerability`. The repository rejects such
an anchor at construction and the validator rejects it in any claim set or
response, so CVE evidence cannot be relabeled to support a protocol-context
claim. A CVE candidate may cite only `implementation_vulnerability` evidence.

## Optional semantic adapter

`cve_kgrag.adapter_discovery` is the only dynamic-loading location. When typed
settings enable semantics, it resolves the `semantic` entry point in group
`cve_kgrag.adapters`; the listing is injectable. A missing extra, a load failure
or more than one installed `semantic` adapter returns an unavailable retriever;
there is no silent lexical fallback under a semantic label.

The semantic adapter reads the chunked collection CVE-KGRAG's pipeline builds
(`cve_documents`, entry IDs `CVE-…_chunk_N`, CVE ID in `cve_id` metadata; ADR 0006)
and ranks each CVE by its nearest chunk (`adapters/semantic/chunk_hits.py`).
`VectorSemanticRetriever` takes an injected collection and text encoder; the
registered entry point (`chroma_retriever.py`) wires a persistent Chroma client
(telemetry off) and a sentence-transformer into it. Filters reach the store as a
`cve_id` metadata constraint. `limit` bounds the chunks fetched, so several chunks of
one CVE can leave fewer than `limit` CVEs. An empty answer, filtered or not, is an
index gap and is reported as `incomplete_index`. A chunk whose `cve_id` is not a
canonical, bounded CVE ID is a malformed hit, and a store error becomes `error`.

A semantic hit's raw score is `1 / (1 + distance)`, monotonic in the store's
distance whatever its metric (the pipeline's collection uses Chroma's default
squared L2). Non-finite or negative distances are rejected. The operator names the
store directory; CVE-KGRAG's pipeline produces it (ADR 0006). Only the Chroma/sentence-transformer wiring is not exercised
offline (the `semantic` extra is not installed in the default lane).

## NVD normalization

`NvdNormalizer` is a pure adapter for NVD JSON 1.1 `CVE_Items[]` entries and NVD
API 2.0 `cve` objects. Callers pass a `SourceSnapshot` (URI, retrieval time,
version) for the NVD document and, optionally, a `KevSource` (catalog entry plus
the catalog's own snapshot). It:

- validates at the boundary: a present field of the wrong JSON type, a
  non-numeric CVSS score, a malformed CPE or timestamp raises
  `NvdNormalizationError`, and so does any value the canonical models reject;
  absent fields stay absent;
- raises `RejectedCveError` for API 2.0 `vulnStatus: Rejected` and for 1.1
  descriptions starting with `** REJECT **` (the 1.1 feed has no status field);
- keeps every CVSS metric with its scorer; derives 3.0 versus 3.1 from the
  vector; reads CVSS 2.0 severity beside `cvssData` (2.0) or from
  `baseMetricV2.severity` (1.1);
- turns only CPE matches marked `vulnerable` into affected products; the other
  matches in a configuration name a platform and imply nothing about it, and
  matches under a `negate` node are skipped (`negate` must be a boolean);
- unescapes CPE components; keeps vendor, product and version bounds; rejects a
  CPE whose vendor or product is a logical value (`*`, `-`). A version
  containing a wildcard is kept as written in `exact`;
- attributes 2.0 descriptions to `sourceIdentifier` and 1.1 descriptions to the
  assigner; takes 1.1 reference sources from `refsource`;
- maps NVD 2.0's mirrored `cisaExploitAdd`/`cisaActionDue` to a KEV entry with
  no ransomware claim; an explicit KEV catalog entry supersedes it and adds its
  own authoritative anchor carrying the catalog's URI, retrieval time and
  version.

Each NVD anchor hashes the whole source entry, configurations included, and its
evidence ID derives from every anchor field (M1 contracts). The hash covers the
raw entry, not the normalized record, so final validation re-checks each served
record against the evidence catalog as well (M1 contracts). All tests
use synthetic `CVE-9999-*` data.

## Deliberate deferrals

- CSAF ingestion, the legacy-data importer, service-wide settings and
  operational migration commands are M6 work.
- The CLI reaches the exact-ID and lexical channels, and the semantic channel with
  `--semantic` (M6 WP2); filter and graph options arrive with the full CLI in M6.
- CVE→CWE→CAPEC→ATT&CK derivation belongs to the reviewed M3 topic/threat-context
  layer and is not part of this graph.
