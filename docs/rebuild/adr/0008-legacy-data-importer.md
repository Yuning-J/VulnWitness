# ADR 0008 — Read-only legacy-data importer

Status: accepted (M6 WP9). Applies to `cve-kgrag migrate legacy` and the corpus store it
writes; WP10 activates and serves that store. It restates and refines the M6 plan's
importer decisions (below, "Deviations") and the repository split plan's WP9 scope
(CVE-KGRAG `docs/rebuild/repository-split-plan.md`, WP9). It agrees with CVE-KGRAG's
migration map on public `main` (`b64eef3`, the `export_kg_for_rag*.py` row): legacy
exports may be read as derived data, never as a source of record. §2, §4, §9, §10 and
§11 are amended by ADR 0009 (store activation and serving): a store's format version,
not the contract version, decides whether it can be read, and its records and anchors,
not its manifest, name the dataset it serves.

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
- **Whole feeds only.** An NVD input must declare how many entries it holds and hold
  exactly that many: a 2.0 feed has `startIndex` 0 and a `totalResults` equal to the
  entries read (both JSON integers); a 1.1 feed has a `CVE_data_numberOfCVEs` equal to
  them, as decimal text. Anything else fails the run as `incomplete_feed`, so a page of a
  larger API result, or a feed some tool cut short while keeping it valid JSON, never
  passes for the whole artifact and leaves its missing CVEs looking absent from NVD.
  `resultsPerPage` is not checked: only the declared total and start say whether a
  result is whole.
- **Derived and refused files.** A manifest input whose content is a legacy derived file
  (`enhanced_documents_*`, the three `rag_exports/cve_documents_for_rag.json` variants,
  CPE parsing results, graph exports, mapping files, analytics and summaries, classified
  by a bounded structural fingerprint) fails the run as `derived_file_declared_as_source`,
  whichever source it is declared as: every input's first decompressed bytes are
  fingerprinted before it is read. A graph export is told by its top-level `nodes` key
  alone, since its node list can run past the fingerprinted prefix.
  With `--legacy-root DIR`, the importer also walks that tree read-only and reports, by
  kind, the derived files it recognises and the files it refuses to deserialize
  (pickles, `.npy` files, model archives, by extension and magic bytes), without
  importing any. The report cites their formats from CVE-KGRAG by commit (`b64eef3`).
  The walk is bounded like every other input (§8): it follows no symbolic link it lists,
  descends at most 32 levels, examines at most 100,000 directory entries (counted as each
  directory is listed), reads at most an 8 KiB prefix of a file to check magic bytes, and
  reads at most 1 MiB of a file and 256 MiB in total to fingerprint structure. A missing
  root, a permission error, an entry that changes or disappears during the walk, and an
  exceeded bound each have a fixed reason code, and each fails the run, dry run included:
  no partial report is returned. Directories are listed by path, so the walk assumes the
  operator's tree holds still: a directory replaced by a symbolic link between being
  listed and being entered is not detected.
- **Out of scope:** CSAF and the legacy collect, process and export commands (PLAN.md
  follow-ups); NVD API 2.0 response pages; the Chroma store, which the semantic channel
  reads in place (ADR 0006 §5); CWE, CAPEC and ATT&CK sources; Neo4j. A page of a larger
  API result fails as `incomplete_feed`. A whole API result has a feed's shape, so
  content cannot tell it from a feed: the artifact the operator names or declares is
  trusted, as it is for which year a feed covers, and an API query narrower than the
  artifact (a date or keyword filter) is not detected.

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
  naive time, a space separator or more digits are refused, and so is an instant UTC
  cannot express (year 1 with an eastern offset, year 9999 with a western one). It must
  not precede the feed's own generation time (§3) nor lie in the future of the injected
  clock.
- Paths resolve relative to the manifest's directory; a path holding a NUL is invalid.
  Only regular files are accepted: symlinks, directories, devices and FIFOs are refused,
  the manifest itself included. Two entries naming the same
  resolved file, or two files with the same SHA-256, are refused.
- The manifest is read with the strict YAML loader's declaration variant
  (`load_declaration_yaml`), which refuses every alias as the document is composed and
  keeps timestamps as text. Every other caller of the strict loader keeps its behaviour:
  for a FiGHT snapshot, the catalog review is the alias gate (ADR 0009 §11). The
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
- The terms URLs and the URL templates come from the source registry
  (`knowledge/sources.yaml`). Composition injects the terms URLs into the normalizer,
  which keeps no constant of its own; the templates build `source_uri` when the inputs
  are resolved. WP9 adds the templates to the registry and
  replaces its `version_strategy` text with the `sha256:` rule.
- The feed's own generation time (2.0 `timestamp`, 1.1 `CVE_data_timestamp`) is kept as
  `source_generated_at` in the store manifest's input list, read as UTC when it carries
  no offset and truncated to microseconds; it is null for the KEV CSV, which has none,
  and for a feed that states none.
- NVD 2.0 entries keep the source type `nvd_api_2`, which names the 2.0 schema the feeds
  share with the API.

The same file obtained at two times gives two sets of evidence IDs: an evidence ID binds
the full provenance, not only the content. The input SHA-256 still shows both runs read
the same bytes.

### 4. Import identity and idempotence

- `inputs_manifest_sha256`: SHA-256 of the manifest's raw bytes, recorded for audit only.
- `import_identity_sha256`: SHA-256 of the validated inputs sorted by `source`, artifact
  and input file SHA-256, each with its `input_file_sha256`, `payload_sha256`, `source`,
  artifact, container and `retrieved_at`; the digest of the source registry entries used
  (terms URLs and URL templates); the importer version (the distribution version and the
  store format version); and the contract version. No local path and no raw manifest
  hash.
- Reordering, reindenting or commenting the manifest, or moving the files, changes
  neither the identity nor the records and anchors files; the store manifest still
  records the raw manifest's hash.
- An existing target whose manifest records the same import identity is verified and
  left as it is (exit 0, "already imported"); if it fails verification, the run is
  refused (exit 1) and the store is never repaired in place. Any other existing target
  is refused and never overwritten. The same bytes with another `retrieved_at` are
  another import. The identity names the import, not the dataset: the dataset a store
  serves is named by the digest of its records and anchors (ADR 0009 §2), so two imports
  with different identities and byte-identical files serve one dataset. An anchor
  records the `retrieved_at` of the input it cites, so another `retrieved_at` is another
  dataset too whenever that input supplies an anchor; an input none of whose entries
  wins (§5) changes the import, not the dataset. The content digest decides.
- The importer alone recomputes the identity, for an existing target; the store reader
  never does. A run under another contract version is another import: it reports
  `target_exists` for a store written under the earlier one, and that store stays
  readable and servable (§9).

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
  them: `notes`, `knownRansomwareCampaignUse`, `cwes`, `forensicTriage` (when each was
  added cannot be checked offline, so all four are optional; CISA's schema lists none of
  them as required). A missing required column, an
  unknown, repeated or empty column name, a row whose width differs from the header, or
  a blank line makes the input invalid.
- **Values.** `cveID` (a CVE ID) and `dateAdded` (`YYYY-MM-DD`) are required; `dueDate`
  (`YYYY-MM-DD`) and `knownRansomwareCampaignUse` (`Known` or `Unknown`, either case)
  may be empty and must be valid when not. `forensicTriage`, when its column is present,
  is exactly `Yes` or `No` in every row: case-sensitive, untrimmed, never empty. CISA's
  schema defines only those two meanings (whether BOD 26-04 requires forensic triage), so
  any other value is an upstream change to review before importing; the column is kept
  in the row and its anchor but not mapped into `KevEntry`, since no investigation reads
  it. Every other column may be empty. Every
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
  window (`kev_advice`, a fixed sentence set exactly when that count is above zero).

### 7. Failure policy

- An NVD entry that cannot be normalized, outside §5's fail-closed cases, is skipped and
  counted by a reason code with a locator (the input's position in the sorted input list
  and the entry's index), never its content. A run failure names its input by its index
  in the manifest when it fails while the inputs are resolved, and by its position in the
  sorted list afterwards (`manifest_index`, `input_position`). The normalizer raises its
  errors with a typed reason code, and only the code reaches the report: its message
  text, which can quote input, never does.
- A file-level fault fails the whole migration: an unreadable file, a file that changed
  between being resolved and being copied for reading, bad compression, an unrecognised
  format, an NVD input that is not a whole feed, a derived file declared as a source, a
  cap exceeded, or an invalid KEV input. So does a target that cannot be resolved or
  whose parent is not a writable directory (`target_unusable`), and a staging database,
  input copy or store file that cannot be written (`staging_failed`,
  `store_write_failed`), a full disk included: every failure the run can state is
  reported, never a traceback.
- A run with zero importable records exits 1.
- Exit codes: 0 imported or already imported; 1 refused or failed; 2 usage error,
  including an invalid manifest. `--dry-run` reports everything a real run would and
  exits the same way, creating no target: it checks the target's parent as a real run
  does, though it stages elsewhere.

### 8. Resource bounds

- NVD feeds are parsed as a stream (`ijson`, in a new `migration` extra; without it the
  command refuses with the missing-extra sentence and exit 1, as `mcp` and `api` do).
  The backend is named (`yajl2_c`), never chosen by ijson. Numbers are parsed as
  `json.loads` parses them (`use_float=True`), so an entry hashes the same however it
  was read; a test pins that. What the backend cannot read as `json.loads` would is
  refused as `invalid_json`, never altered: `NaN` and `Infinity`, a number past the float
  range, an integer of magnitude 2^63 or more (the backend's limit, so the smallest signed
  64-bit integer too), invalid UTF-8, a lone surrogate
  escape (a high one without its low escape is caught before the parser, which would
  turn it into `?`). Top-level fields are collected from the event stream wherever they
  appear, each key and value counted against the entry cap; a feed has at most 32
  top-level members, each key at most 256 characters, or it is not a feed.
- A single entry is capped at 16 MiB of decompressed bytes. The parser reads through a
  counting stream that knows where the current entry began and raises from its own
  `read` once the entry has consumed more than the cap and one parser buffer (64 KiB), so
  neither a long entry nor one huge string token is ever held whole: the bytes read for
  one entry stay within the cap plus three buffers, since the parser marks an entry's
  start up to one buffer late and reads one more before the stream refuses. Entries are
  assembled from the parser's events, not with `ijson.items`, which builds an entry
  before it can be measured; the assembler also counts each entry's keys and values,
  never more than their encoded bytes, so an entry within the cap is always accepted,
  and refuses a repeated key and nesting past 64 levels. An entry's memory is a bounded
  multiple of its encoded bytes, largest (about 25 times) for an entry of many empty
  containers. An entry over a cap fails the file.
- Candidates are staged on disk in a `sqlite3` database without a journal: CVE ID,
  modification time, format, state, semantic hash, provenance for the tie-break, the
  content hash and the raw entry, from which the winner is normalized again with its
  final provenance and KEV entry. Candidates are read back grouped by CVE ID through an
  index; §5 is applied per group and §6 against the KEV catalog held in memory (at most
  16 MiB), and the store is written in CVE ID order (lexical). Neither the manifest
  order nor the number of files changes the records and anchors.
- Caps, as code constants with fixed reason codes, never echoing a path or input
  content: 128 inputs; per file 1 GiB decompressed and 256 MiB for a gzip or zip file
  (a plain JSON file is its own payload, so the 1 GiB cap bounds it); 8 GiB
  decompressed in total; 1,000,000 NVD candidates; the KEV caps of §6; the
  `--legacy-root` bounds of §1; and 16 GiB for the whole staging directory, the copy
  of the input being read included (§9). Before an input is copied there must be room
  for its inspected size, the copy never grows past that size, and the directory is
  measured every 1,024 rows or 64 MiB staged, again at the end of each input while its
  copy is still there, and once the last anchor is staged; between two measurements it
  can pass the cap by what that interval stages. A dry run stages the anchors too, so it
  meets the cap where a real run would. A zip's end record must declare one member and a
  central directory no larger than one member needs before `zipfile` reads it. The
  per-file cap is a constant; operator measurements are recorded in `PLAN.md`.
- An operator lane (not CI) builds 250,000 synthetic records and records the migration's
  peak RSS, temporary disk and run time.

### 9. The store and the write protocol

- The target directory holds `manifest.json` (`CorpusStoreManifest`), the records and
  the anchors as canonical JSON sorted by CVE ID and evidence ID, each file pinned by
  SHA-256 in the manifest. The manifest records `synthetic: false`, a creation time
  from the injected clock, the store format version, the importer version, the
  contract version the store was created under, both identity hashes, each input in
  sorted order (source, artifact, container, `source_uri`, `source_version`,
  `retrieved_at`, `source_generated_at`, bytes) and the counts.
- **Two version axes.** `store_format_version` decides whether a reader can read a
  store written by its own or an earlier importer; this reader reads format 1 and
  refuses any other integer as `store_format_unsupported`, read before the rest of the
  manifest is parsed. The manifest's `schema_version` is provenance: a well-formed
  contract version, never compared with the version the reader serves. Moving the
  contract version therefore leaves every existing store readable and its manifest
  bytes unchanged; a contract change that alters what a store persists, as below, is
  also a format change.
- The format version moves, and stores are re-imported, only when what a store
  persists, or what the reader accepts of it, changes: a field added to, removed from,
  renamed in or narrowed in the manifest, `CveRecord` or `EvidenceAnchor` (an older
  store would present an added field as one no source supplied, and an evidence ID
  hashes every field its anchor serializes); a change to how a persisted field
  serializes; any narrowing of a value set those models use (a source type, scope,
  trust level, CVSS version, pattern or bound); a change to evidence ID derivation; or
  a reader rule made stricter (a validator on any of the three models, the anchor and
  record-to-anchor rules, the ID order, the pinned file set, or the manifest and line
  caps). Adding a value to a value set keeps format 1.
- Format 1 is read in one direction: a reader reads every format-1 store its own or an
  earlier importer wrote. A store holding a value added later fails an earlier
  reader's checks as `store_invalid`. The `2.0.0-dev.25` reader at `28e5b4d` compares a
  manifest's `schema_version` and rollback instruction with its own, so it reads no
  store written from `2.0.0-dev.26` on. Before an operator downgrades the program, they
  use the newer program to activate a store the earlier release can read; the runbook
  says so.
- Two tests guard format 1 (ADR 0009 §15). A format-1 store written by the
  `2.0.0-dev.25` importer is committed under `tests/` and never regenerated; a test
  verifies and loads it in full, so it is the backward-compatibility proof for what it
  holds. A pinned digest of the three models' published schemas fails on any change to
  them; it is a reminder to judge the change, not a proof. A stricter reader rule is a
  format change whether or not either test fails.
- `--target` is required and has no default. Paths are resolved, `..` and symlinks
  included, and compared by file identity (device and inode), so two spellings of one
  directory, such as two cases of a name on a case-insensitive file system, match. The
  target must not equal, contain or lie inside the manifest, any input, or the
  `--legacy-root`, and its parent directory must hold no input, so nothing is ever
  created next to an input. A symbolic link at the target that resolves nowhere,
  dangling or looping, is an existing entry and is refused, never followed. With
  `CVE_KGRAG_STORE_ROOT` set, the target must not be the root or lie under it unless the
  root is its parent and its last component is a valid store name (exit 1,
  `target_in_store_root`), and a target under the root needs a root that is a directory
  and not a symbolic link (`store_root_unusable`; ADR 0009 §4).
- Two sibling directories on the target's file system hold a run's work: the store
  takes shape in `.<name>.partial-<random>`, and the staging database lives in
  `.<name>.staging-<random>`. Once the store files are written and fsynced, the staging
  directory is deleted, the partial directory is read back and verified with
  `verify_corpus_store`, given mode 0755 (its files are 0644; both modes are set
  explicitly, so the umask of the run never narrows them), and renamed into place;
  the target's parent is opened before the rename so the rename can be synced. Any entry
  at the target just before the rename is refused (`target_exists`); one that appears
  after that check and before the rename fails the rename if it is a file or a
  non-empty directory (`store_write_failed`); an empty directory there is replaced, as
  `rename(2)` does, and this window is not closed. On failure only this run's two
  directories are removed. A dry run stages in a temporary directory under the system
  temporary directory, removed afterwards.
- `verify_corpus_store` and `load_corpus_store` run the same checks; the first keeps only
  an index of anchor IDs in memory, the second keeps every record and anchor for
  serving. They read the store as untrusted input: the manifest within 4 MiB, each line
  within 64 MiB, and a file's size checked against its pin before its lines are read.
  They verify every checksum and size, refuse a manifest pinning a file twice, any file
  it does not pin and any store file that is not a regular file, re-derive every
  evidence ID, apply the record-to-anchor rules, refuse `synthetic: true` and confine
  every file path to the store directory. Neither compares the manifest's
  `schema_version` or its rollback instruction with this program's.
- Every file the importer or the reader opens is opened without following a symbolic link
  and without blocking, and refused unless it is a regular file, so a FIFO declared as
  an input or the manifest, or found in a store, fails at once instead of waiting for a
  writer.
- An input is hashed when it is resolved. Before it is read, it is copied into the
  run's staging directory, hashed as it is copied, and the copy must hold exactly the
  resolved bytes, or the run fails as `input_changed` (or `staging_failed` when the copy
  cannot be written). A KEV input's container and 16 MiB cap are checked before it is
  copied. The fingerprint, the parse and the KEV read all use the copy, which is removed
  once the input is read. So the store
  manifest's `input_file_sha256`, `payload_sha256` and `source_version` always describe
  one set of bytes, the ones imported, whatever happens to the operator's file during
  the run: re-hashing that file instead could not stop it being rewritten in place
  between the hash and the parse.
- **Rollback.** A migration writes nothing but its new target: no input and no existing
  store changes, which the tests prove by content and modification time. (Creating and
  renaming the target changes its parent directory's own metadata; nothing else there
  changes.) The store manifest and the report record the rollback as fixed values,
  `rollback_kind: delete_unactivated_target` and `rollback_scope:
  before_activation_only`, with the server's fixed instruction: "Before activation,
  remove the newly created target directory. After activation, use `cve-kgrag store
  rollback`." The report, fresh output of the run, must carry exactly these three
  values. The manifest describes the store as it was created: the reader accepts the two
  values above and any bounded instruction text, so rewording the instruction never
  makes a store unreadable, and no command presents a manifest's instruction as current
  guidance; the CLI and the runbook state the supported rollback. The report names the
  store by its `import_identity_sha256` and its manifest's SHA-256, so the operator can
  tell which directory to remove, and from `2.0.0-dev.26` names the dataset it holds by
  its `corpus_content_sha256` (ADR 0009 §2). `migrate` has no delete command and never
  rolls back by itself; an activated store is rolled back with `cve-kgrag store
  rollback` (ADR 0009 §7).

### 10. Contracts

`corpus_store_manifest.schema.json` and `migration_report.schema.json` are published
from `2.0.0-dev.25`. The manifest schema pins `store_format_version` to 1, and from
`2.0.0-dev.26` (ADR 0009 §15) gives `schema_version` and the rollback instruction as
bounded strings with no default, so a later contract version leaves it unchanged. The
report holds counts by reason code, bounded locators, the derived and refused files
found by kind with the commit their formats are cited from, the KEV advice, the rollback
kind, scope and instruction, and no input text.

### 11. Handed to WP10

- Activation, serving, and `store rollback` to the previously active store.
- The `cve_search` capability version naming the active store's dataset by its corpus
  content digest in place of the fixture's (ADR 0009 §2), so a sealed set verifies
  against any store holding byte-identical records and anchors and is refused by any
  other.
- Load-time and serving memory, measured on synthetic feeds, and one data plane shared
  by the `api` process's two deployments (ADR 0009 §12); budgets wait for real feeds.
- The alias policy for a full FiGHT snapshot.
- The `KEV-` chunk IDs a legacy Chroma store may hold.
- The corpus content digest in the planner evaluation's identity, for M7b.

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
