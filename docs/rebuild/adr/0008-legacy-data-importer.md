# ADR 0008 — Read-only legacy-data importer

Status: accepted (M6 WP9). Applies to `cve-kgrag migrate legacy` and the corpus store it
writes; WP10 activates and serves that store. It restates and refines the M6 plan's
importer decisions (below, "Deviations") and the repository split plan's WP9 scope
(CVE-KGRAG `docs/rebuild/repository-split-plan.md`, WP9). It agrees with CVE-KGRAG's
migration map on public `main` (`b64eef3`, the `export_kg_for_rag*.py` row): legacy
exports may be read as derived data, never as a source of record.

## Context

The legacy pipeline in CVE-KGRAG downloads raw NVD and CISA KEV data and derives
documents, graphs and a Chroma store from it. v2 reaches legacy behaviour only through
the data it produces (ADR 0001 §5, ADR 0006 §4). Its evidence anchors hash the raw
source entry, so it imports only raw source data: the legacy derived exports are lossy
or wrong (CVE-KGRAG baseline findings 12-19) and would carry those defects under an NVD
label.

No raw source file and no derived export is on the development machine: the legacy
corpus paths hold one-byte placeholders, and the only real file is an 8.9 KB analytics
summary (baseline finding 24). The importer is therefore proven against authored
synthetic inputs (`CVE-9999-*`), and a real run is the operator's, with the dry run as
its safeguard.

## Decisions

### 1. Inputs

- **Imported:** NVD JSON 1.1 and 2.0 feeds (year, `recent` and `modified` series), as
  plain JSON, gzip, or a zip holding exactly one non-directory member, unencrypted,
  stored or deflated; the cap applies to the bytes actually decompressed, never the
  declared size. And the CISA KEV catalog CSV. NVD entries go through `NvdNormalizer`.
- **Recognised by content**, never by file name alone:
  - NVD 2.0: a top-level object with `"format": "NVD_CVE"`, `"version": "2.0"` and a
    `vulnerabilities` array.
  - NVD 1.1: `"CVE_data_type": "CVE"`, `"CVE_data_format": "MITRE"`,
    `"CVE_data_version": "4.0"` and a `CVE_Items` array. The 1.1 feeds declare the CVE
    JSON 4.0 schema, never "1.1".
  - KEV: the CSV header of §6.
- **Derived and refused files.** A manifest input whose content is a legacy derived file
  (`enhanced_documents_*`, the three `rag_exports/cve_documents_for_rag.json` variants,
  CPE parsing results, graph exports, mapping files, analytics and summaries, classified
  by a bounded structural fingerprint) fails the run as `derived_file_declared_as_source`.
  With `--legacy-root DIR`, the importer also walks that tree read-only and reports, by
  kind, the derived files it recognises and the files it refuses to deserialize
  (pickles, `.npy` files, model archives, by extension and magic bytes), without
  importing any. The report cites their formats from CVE-KGRAG by commit (`b64eef3`).
  The walk is bounded like every other input (§8): it follows no symbolic link, descends
  at most 32 levels, examines at most 100,000 directory entries, reads at most an 8 KiB
  prefix of a file to check magic bytes, and reads at most 1 MiB of a file and 256 MiB
  in total to fingerprint structure. A permission error, an entry that changes or
  disappears during the walk, and an exceeded bound each have a fixed reason code, and an
  exceeded bound fails the run, dry run included: no partial report is returned.
- **Out of scope:** CSAF and the legacy collect, process and export commands (PLAN.md
  follow-ups); NVD API 2.0 response pages; the Chroma store, which the semantic channel
  reads in place (ADR 0006 §5); CWE, CAPEC and ATT&CK sources; Neo4j.

### 2. The input manifest

The operator lists every input in a YAML file passed as `--inputs`; nothing is imported
by scanning a directory.

```yaml
format_version: 1
inputs:
  - source: nvd
    path: feeds/nvdcve-2.0-2024.json.gz
    retrieved_at: "2026-10-24T08:30:00Z"
  - source: nvd
    path: renamed-feed.json.gz
    retrieved_at: "2026-10-24T08:35:00Z"
    artifact: {format: "2.0", series: year, year: 2023}
  - source: cisa-kev
    path: feeds/known_exploited_vulnerabilities.csv
    retrieved_at: "2026-10-24T08:40:00Z"
```

- `source` is a closed enum of source-registry IDs: `nvd` or `cisa-kev`. At most one
  `cisa-kev` input.
- `artifact` is typed: `format` the string `"1.1"` or `"2.0"` (a number is refused),
  `series` `year`, `recent` or `modified`, and `year` for the year series (2002 onwards;
  the 2002 feed also holds CVE-1999 to CVE-2001). It is never a free `source_uri`. A
  standard file name (`nvdcve-{1.1|2.0}-{YYYY|recent|modified}.json[.gz|.zip]`) gives
  the artifact; any other name must declare it; when both exist they must agree. The
  format the content declares (§1) must agree with the artifact.
- `retrieved_at` is required on every input, when the operator actually obtained the
  file. The manifest loader reads timestamps as strings, so the value is validated as a
  contract `Timestamp`: RFC 3339 with an offset and at most six fractional digits. A
  naive time, a space separator or more digits are refused. It must not precede the
  feed's own generation time (§3) nor lie in the future of the injected clock.
- Paths resolve relative to the manifest's directory. Only regular files are accepted:
  symlinks, directories, devices and FIFOs are refused. Two entries naming the same
  resolved file, or two files with the same SHA-256, are refused.
- The manifest is read with the strict YAML loader with aliases forbidden
  (`forbid_aliases=True`, checked as the document is composed); every other caller of
  the loader keeps its behaviour until WP10 checks a full upstream FiGHT snapshot. The
  manifest's size (1 MiB), entry count (128) and path length (1,024 characters) are
  capped.
- A manifest that is not valid is a usage error (exit 2), reported in the server's words.

### 3. Provenance

Every anchor's provenance fields feed its evidence ID, so they are fixed as follows.

- `source_uri`: the canonical upstream URL of the concrete artifact, built from the
  artifact and a URL template the source registry holds: the published gzip form for
  NVD (`…/nvdcve-2.0-2024.json.gz`), whatever container the operator supplied. The 1.1
  feeds are retired upstream, so their URL is an identifier. Never a local path.
- Two hashes are recorded per input in the store manifest: `input_file_sha256`, of the
  file's bytes as supplied, and for NVD `payload_sha256`, of the decompressed JSON
  payload's bytes; with the container (plain, gzip or zip).
- `source_version`: for NVD, `sha256:<payload_sha256>`, so the same payload gives the
  same evidence IDs whether it came as gzip, zip or unpacked JSON, and downloading the
  gzip at `source_uri` and unpacking it lets anyone check the version. For KEV, which
  has no container, `sha256:<input_file_sha256>`.
- `retrieved_at`: the operator's declared time. Never the file's modification time, the
  import time or the feed's generation time.
- The terms URL and the URL templates come from the source registry
  (`knowledge/sources.yaml`), injected into the normalizer by composition; the
  normalizer keeps no constant of its own. WP9 adds the templates to the registry and
  replaces its `version_strategy` text with the `sha256:` rule.
- The feed's own generation time (2.0 `timestamp`, 1.1 `CVE_data_timestamp`) is kept as
  `source_generated_at` in the store manifest's input list, read as UTC when it carries
  no offset and truncated to microseconds; the KEV CSV has none (null).
- NVD 2.0 entries keep the source type `nvd_api_2`, which names the 2.0 schema the feeds
  share with the API.

The same file obtained at two times gives two sets of evidence IDs: an evidence ID binds
the full provenance, not only the content. The input SHA-256 still shows both runs read
the same bytes.

### 4. Import identity and idempotence

- `inputs_manifest_sha256`: SHA-256 of the manifest's raw bytes, recorded for audit only.
- `import_identity_sha256`: SHA-256 of the validated inputs sorted by `source`, artifact
  and input file SHA-256, each with its `input_file_sha256`, `payload_sha256`, `source`,
  artifact, container and `retrieved_at`; the digest of the source registry entries
  used (terms URLs and URL templates); the importer version (the distribution version
  and the store format version); and the contract version. No local path and no raw manifest hash.
- Reordering, reindenting or commenting the manifest, or moving the files, changes
  neither the identity nor the records and anchors files; the store manifest still
  records the raw manifest's hash.
- An existing target whose manifest records the same import identity is verified and
  left as it is (exit 0, "already imported"); if it fails verification, the run is
  refused (exit 1) and the store is never repaired in place. Any other existing target
  is refused and never overwritten. The same bytes with another `retrieved_at` are
  another import.

### 5. NVD entries for the same CVE

1. Each candidate gives its CVE ID, its last modification, its format and its state. The
   importer reads the modification time itself (`cve.lastModified` in 2.0, millisecond
   precision without an offset, read as UTC; `lastModifiedDate` in 1.1, minute precision
   with `Z`) and compares instants exactly. The state is rejected when the normalizer
   raises `RejectedCveError` (2.0 `vulnStatus` `Rejected`; 1.1 a description starting
   `** REJECT **`), which is caught before `NvdNormalizationError`: a rejected entry is a
   valid withdrawal, not a malformed one.
2. Per CVE ID only the candidates at the latest modification time are kept.
3. Among those:
   - all semantically equal: an identical duplicate;
   - not all equal, with both formats present: the 1.1 candidates are dropped, then the
     2.0 candidates are compared;
   - the remaining candidates equal: one is chosen;
   - still unequal: the CVE is `conflicting_duplicate` and gets no record and no anchor.
4. Semantic equality compares the normalized `CveRecord` without `evidence_ids` and
   provenance, all other fields kept (descriptions and their sources, CVSS, CWE,
   affected products, references, NVD's mirrored KEV fields). A rejected candidate's
   state is `{cve_id, state: rejected}`; active and rejected are unequal.
5. Among equal active candidates the anchor comes from, in order: the 2.0 one; the
   latest `retrieved_at`; the smallest `source_uri`; the smallest `source_version`; the
   smallest `content_sha256`. The order only makes the choice stable; it claims no
   artifact is more authoritative.
6. A rejected winner withdraws the CVE: it gets no record and no anchor, and an older
   active candidate never revives it.
7. Fail closed: a latest-time candidate whose CVE ID is readable but which cannot be
   normalized excludes the CVE (`malformed_winning_candidate`), and so does a duplicate
   group holding a candidate with a missing or invalid modification time
   (`unorderable_candidate`). A malformed candidate certainly older than a valid winner
   is skipped and counted. A CVE with a single candidate and no modification time is
   imported, as the normalizer allows.
8. Superseded and identical candidates get no anchor; the report counts them by reason.

### 6. KEV

KEV enrichment runs after §5, on the final NVD records only.

| Case | Outcome |
|---|---|
| A KEV CVE with no NVD candidate | no record or anchor; `kev_without_nvd_record` |
| Its NVD winner is rejected | no record or anchor; `kev_for_rejected_nvd_record` |
| Its NVD CVE was excluded by §5 | no record or anchor; `kev_for_excluded_nvd_record` |
| A servable NVD record | KEV fields merged, with their own KEV anchor |
| Repeated rows, equal | deduplicated; counted as identical duplicates |
| Repeated rows, unequal | the KEV input is invalid |

- **Columns.** The column set is fixed and its order free. Always present: `cveID`,
  `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`,
  `requiredAction`, `dueDate`. May be absent, in snapshots older than CISA's addition of
  them: `notes`, `knownRansomwareCampaignUse`, `cwes` (when each was added cannot be
  checked offline, so all three are optional). A missing required column, an
  unknown, repeated or empty column name, a row whose width differs from the header, or
  a blank line makes the input invalid.
- **Values.** `cveID` (a CVE ID) and `dateAdded` (`YYYY-MM-DD`) are required; `dueDate`
  (`YYYY-MM-DD`) and `knownRansomwareCampaignUse` (`Known` or `Unknown`, either case)
  may be empty and must be valid when not; every other column may be empty. Every
  present column takes part in row comparison and in the anchor's content hash. Values
  are compared exactly as parsed, without trimming.
- **Reading.** UTF-8 with one leading BOM accepted (`utf-8-sig`), the `csv` module's
  `excel` dialect with `strict=True` and `newline=""`; file size (16 MiB) and row count
  (50,000) capped.
- An invalid KEV input fails the whole migration and publishes no target. The report
  offers two ways on: fix the file, or remove the KEV input from the manifest and run
  again, which the store manifest then records.
- An explicit KEV entry supersedes the CISA fields NVD 2.0 mirrors: CISA is the source of
  record. Only entries attached to a final record get an anchor; its locator names the
  CVE in the catalog.
- For `kev_without_nvd_record` the report suggests adding the year feed that covers the
  CVE; a recent or modified feed covers it only while the CVE is inside that feed's
  window.

### 7. Failure policy

- An NVD entry that cannot be normalized, outside §5's fail-closed cases, is skipped and
  counted by a reason code with a locator (the input's position in the sorted input list
  and the entry's index), never its content. The normalizer raises its errors with a
  typed reason code, and only the code reaches the report: its message text, which can
  quote input, never does.
- A file-level fault fails the whole migration: an unreadable file, bad compression, an
  unrecognised format, a derived file declared as a source, a cap exceeded, or an invalid
  KEV input.
- A run with zero importable records exits 1.
- Exit codes: 0 imported or already imported; 1 refused or failed; 2 usage error,
  including an invalid manifest. `--dry-run` reports everything a real run would and
  exits the same way, creating no target.

### 8. Resource bounds

- NVD feeds are parsed as a stream (`ijson`, in a new `migration` extra; without it the
  command refuses with the missing-extra sentence and exit 1, as `mcp` and `api` do).
  Numbers are parsed as `json.loads` parses them (`use_float=True`), and non-finite
  numbers (`NaN`, `Infinity`) are refused on every path, so an entry hashes the same
  however it was read; a contract test pins that. Top-level fields are collected from
  the event stream wherever they appear.
- A single entry is capped at 16 MiB of decompressed bytes. The parser reads through a
  counting stream that knows where the current entry began and raises from its own
  `read` once the entry has consumed more than the cap, so neither a long entry nor one
  huge string token is ever held whole: memory stays within the cap plus one read
  buffer. Entries are assembled from the parser's events, not with `ijson.items`, which
  builds an entry before it can be measured. An entry over the cap fails the file.
- Candidates are staged on disk in a `sqlite3` database: CVE ID, modification time,
  format, state, semantic hash and the normalized payload. §5 and §6 are resolved by
  queries, and the store is written in CVE ID order (lexical). Neither the manifest
  order nor the number of files changes the records and anchors.
- Caps, as code constants with fixed reason codes, never echoing a path or input
  content: 128 inputs; per file 512 MiB decompressed and 256 MiB compressed; 8 GiB
  decompressed in total; 1,000,000 NVD candidates; the KEV caps of §6; the
  `--legacy-root` bounds of §1; and 16 GiB for the whole staging directory, the SQLite
  database, its journal or WAL and its temporary sort files together. Whether 512 MiB
  fits a current 2.0 year feed is checked on the first real run; the cap is a constant,
  changed by a later decision if a measured feed exceeds it.
- An operator lane (not CI) builds 250,000 synthetic records and records the migration's
  peak RSS, temporary disk and run time.

### 9. The store and the write protocol

- The target directory holds `manifest.json` (`CorpusStoreManifest`), the records and
  the anchors as canonical JSON sorted by CVE ID and evidence ID, each file pinned by
  SHA-256 in the manifest. The manifest records `synthetic: false`, a creation time
  from the injected clock, the importer and contract versions, both identity hashes,
  each input in sorted order (source, artifact, container, `source_uri`,
  `source_version`, `retrieved_at`, `source_generated_at`, bytes) and the counts.
- `--target` is required and has no default. Paths are resolved, `..` and symlinks
  included. The target must not equal, contain or lie inside the manifest, any input, or
  the `--legacy-root`, and its parent directory must hold no input, so nothing is ever
  created next to an input.
- Two sibling directories on the target's file system hold a run's work: the store
  takes shape in `.<name>.partial-<random>`, and the staging database lives in
  `.<name>.staging-<random>`. Once the store files are written and fsynced, the staging
  directory is deleted, the partial directory is read back and verified with
  `load_corpus_store`, and it is renamed into place. On failure only this run's two
  directories are removed. A dry run stages
  in a temporary directory under the system temporary directory, removed afterwards.
- `load_corpus_store` verifies every checksum, refuses any file the manifest does not
  pin, re-derives every evidence ID, applies the record-to-anchor rules, refuses
  `synthetic: true` and confines every file path to the store directory.
- **Rollback.** A migration writes nothing but its new target: no input and no existing
  store changes, which the tests prove by content and modification time. (Creating and
  renaming the target changes its parent directory's own metadata; nothing else there
  changes.) The store manifest and the report record the rollback as fixed values,
  `rollback_kind: delete_unactivated_target` and `rollback_scope:
  before_activation_only`, with the server's fixed instruction: "Before activation,
  remove the newly created target directory. After activation, use the WP10 store
  rollback operation." The report names the store by its `import_identity_sha256` and
  its manifest's SHA-256, so the operator can tell which directory to remove. WP9 has no
  delete command and never rolls back by itself; an activated store is rolled back only
  through WP10.

### 10. Contracts

`2.0.0-dev.25` publishes `corpus_store_manifest.schema.json` and
`migration_report.schema.json`. The report holds counts by reason code, bounded
locators, the derived and refused files found by kind, the rollback instruction, and
no input text.

### 11. Handed to WP10

- Activation, serving, and `store rollback` to the previously active store.
- The `cve_search` capability version binding the active store's manifest in place of
  the fixture's, so sets sealed against one store verify only against it.
- Load-time and serving memory budgets, the `api` process's two deployments over one
  bundle included.
- The alias policy for a full FiGHT snapshot.
- The `KEV-` chunk IDs a legacy Chroma store may hold.
- A store digest in the planner evaluation's identity, for M7b.

## Deviations from the M6 plan and the split plan

| Plan | This ADR | Why |
|---|---|---|
| ADR number 0007 | 0008 | 0007 became the HTTP surfaces ADR |
| `--input PATH...` | `--inputs` YAML manifest | per-input `retrieved_at` and artifact; exact declared input set |
| `store_id` from input checksums, normalizer and schema version | `import_identity_sha256` with `retrieved_at` and the registry digest | evidence IDs bind the declared provenance |
| NVD API 2.0 pages | out of scope | legacy downloaded feeds only; an API page has no artifact identity |
| `json.loads` with a per-file cap | streaming parse, staging database, per-entry and total caps | a byte cap bounds input, not memory |
| `RollbackRecord`, `rollback.json`, `ROLLBACK.md` | fixed rollback values and instruction in the report and the manifest | the migration writes nothing but its target; deleting it before activation is the rollback |
| Derived files detected among inputs | refused as declared sources; reported from `--legacy-root` | inputs are declared, not scanned |
| Contracts at `dev.23` | `dev.25` | WP5 to WP7 used dev.21 to dev.24 |

## Consequences

- Only raw source data enters v2, under the source's own terms; the legacy exports never
  do.
- Every anchor is reproducible from the declared inputs; one declared input set gives
  the same records and anchors whatever its order.
- The importer needs the `migration` extra (whose lock entry needs network access once)
  and disk for its staging database; serving needs neither.
