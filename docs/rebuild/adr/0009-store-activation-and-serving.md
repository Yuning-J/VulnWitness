# ADR 0009 — Store activation and serving

Status: accepted (M6 WP10). Applies to `cve-kgrag store`, to how every surface chooses
the records and evidence it serves, and to the operator FiGHT snapshot. It takes the
corpus store ADR 0008 writes and settles what ADR 0008 §11 hands over. It restates and
refines the M6 plan's WP10 scope (below, "Deviations"). It amends ADR 0008 §2, §4, §9,
§10 and §11: a store's format version, not the contract version, decides whether it can
be read (§15), and the corpus content digest, not the manifest, names the dataset it
serves (§2). It amends ADR 0003 §10, §11 and Consequences (`verify` and `mcp` serve the
active store), ADR 0004 §1 (the store and FiGHT snapshot settings, and the semantic
channel's state when a store is served, §14) and ADR 0006 §5 (legacy `KEV-` chunks,
§14).

## Context

`cve-kgrag migrate legacy` writes a verified corpus store: a directory whose
`manifest.json` pins `records.jsonl` and `anchors.jsonl` (ADR 0008 §9). Nothing serves
it yet. Every surface takes its records and evidence from
`composition.load_served_bundle()`, which returns the packaged synthetic fixture; the
`cve_search` capability version names the fixture by `fixture_id@version` and its
manifest hash; and the MCP server's instructions say it serves "the packaged synthetic
fixture". The FiGHT source is the packaged excerpt on every surface, and the catalog in
`knowledge/fight_snapshots.yaml` already pins the full upstream file an operator may
supply (`m3-topics-and-threat-context.md` deferred that snapshot to M6).

The M6 requirements and the owner's M6 decisions bind this ADR. Activation is explicit
and follows validation, and startup never migrates (requirement D9); the service serves
a migrated store (requirement D11). Owner decision 15 (index scope): the index is the
validated corpus store, and building its lexical and graph structures in memory at
startup is not a rebuild on disk. Owner decision 16: a configured store that is missing
or invalid refuses to start, with no fallback to the fixture. Owner decision 17: the
operator FiGHT snapshot ships in M6. §17 says how the M6 exit audit records these.

The measurements below were taken on synthetic feeds
(`scripts/operator/build_synthetic_feeds.py`: one CPE and a short description per
record) . The load, verification and memory
figures are lower bounds for real NVD records; the `graph_expand` figures (§12) are a
worst case, never NVD performance.

## Decisions

### 1. The served-dataset seam

- Every composition function that takes the served records, the evaluation runner and
  the CLI take a `ServedCorpus` Protocol (`ports/`): `records`, `evidence` and
  `describe_served_dataset() -> ServedDataset`. `FixtureBundle` and `CorpusStore` both
  implement it; neither converts into the other (`FixtureManifest` requires
  `synthetic: true`, a store's manifest `synthetic: false`).
- `ServedDataset` is a domain model: `kind` (`synthetic_fixture` or `corpus_store`) and
  `cve_search_version`. `InvestigationDeployment` carries it, and the interfaces layer
  reads it through a public toolbox accessor, never through composition or an adapter.
- The fixture's `cve_search` version stays `fixture_id@version+sha256:<manifest hash>`.

### 2. A store's three identities

Each digest has one job.

- `store_manifest_sha256` names the physical store one import wrote: the SHA-256 of the
  manifest bytes the reader parsed, read once so no second read can differ. It equals
  the migration report's `store_manifest_sha256`. `ACTIVE` records it, and activation,
  rollback and startup use it to refuse a store replaced under its name.
- `import_identity_sha256` names the import and its provenance (ADR 0008 §4), for
  idempotence and audit. The manifest declares it and the reader never recomputes it.
  No serving surface returns it; `store status` and the migration report show it.
- `corpus_content_sha256` names the logical dataset, what the surfaces search. It is the
  SHA-256 of `canonical_json_bytes` (sorted keys, no whitespace, as for evidence IDs) of
  the value below, which lists the records file, then the anchors file, each with the
  SHA-256 and size its pin gives. It is shown indented for reading:

  ```json
  {
    "identity_version": 1,
    "files": [
      {"role": "records", "sha256": "…", "size_bytes": 0},
      {"role": "anchors", "sha256": "…", "size_bytes": 0}
    ]
  }
  ```

  Nothing else is in it: no creation time, rollback text, input path, manifest digest,
  contract version or importer version.

A store's `cve_search` version is `corpus-store-v1@sha256:<corpus_content_sha256>`,
where `v1` is the `identity_version`.

- The reader derives the content digest from the manifest's pins only after it has
  checked every file against them, in the pass that verifies or loads the store. Every
  caller (startup, the `store` commands, the importer's report) takes the content digest
  from that pass, together with the manifest digest of the same read. The manifest
  carries no content digest and none is ever read from it, so a format-1 store written
  under `dev.25` gets one without a format change, and a hand-built store cannot claim
  another dataset's version.
- The served dataset is built from the records and anchors alone: no manifest field
  reaches a search result, an evidence record or a capability other than through this
  version. That is what makes the content digest the dataset's name, and a test pins
  it: two stores with the same files and different manifests answer alike.
- Verification compares capability versions exactly, so:
  - a store restored from a backup of its directory is the same store and the same
    dataset;
  - a re-import whose records and anchors are byte for byte the same is another store
    and the same dataset, and every set sealed against the first, `no_match` included,
    still verifies;
  - a store whose records or anchors differ in any byte is another dataset, and sets
    sealed against the first are refused;
  - a store whose manifest alone differs must be activated again (`ACTIVE` records the
    manifest digest) and serves the same dataset.
- Moving the contract version changes none of the three for an existing store. A set
  still verifies only under the contract version it was sealed with: its
  `schema_version` and its `investigation_id` name that version (ADR 0002).

### 3. Settings

ADR 0004 §1 lists these variables with the others.

- `CVE_KGRAG_STORE_ROOT`: an absolute directory path, always read with the other
  settings. Unset, every surface serves the packaged fixture. A relative or otherwise
  invalid value is a usage error naming the variable.
- `CVE_KGRAG_FIGHT_SNAPSHOT_PATH` and `CVE_KGRAG_FIGHT_SNAPSHOT_SHA256`: both or neither.
  Neither serves the packaged excerpt. The path is absolute, the hash 64 lower-case hex
  characters; one without the other is a usage error. The pairing is an explicit check
  in `load_settings`, not a model validator, whose error has no field location.
- Settings read only the environment and open nothing (ADR 0004); whether the pinned
  hash is a catalogued snapshot is checked when the snapshot is loaded (§11).
- Errors name variables, never values.

### 4. Where stores live

- A store lives directly under the root, named by one path component that matches
  `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` and is not `ACTIVE` in any letter case. A name
  therefore never starts with a dot, so migration's hidden `.<name>.partial-*` and
  `.<name>.staging-*` siblings and the root's own `.lock` and temporary files are never
  a store, and on a case-insensitive file system no store can shadow `ACTIVE`. The
  store must be a directory, not a symbolic link to one (`lstat`).
- The root must be a directory, checked with `lstat`: a symbolic link at the root path
  is refused, while links among its parent directories are followed. A root that is
  missing, not a directory, a symbolic link or unreadable is `store_root_unusable`, for
  startup (§9) and the `store` commands (§8) alike.
- Operators migrate with `--target <root>/<name>`. With the root set, `migrate legacy`
  refuses a target that is the root or lies under it unless the root is its parent and
  its last component is a valid name (exit 1, `target_in_store_root`), so a migration
  never writes into an existing store, whose reader refuses any file it does not pin.
  The target and the root are compared as ADR 0008 §9 compares paths, resolved and by
  file identity, so another spelling of the root, such as another letter case on a
  case-insensitive file system, is still the root.
- Before that comparison, `migrate legacy` applies the root rule above to the root as
  configured, with `lstat`, whenever the target lies under the root's resolved path. A
  root that breaks it fails the run with `store_root_unusable` before anything is
  written, so a migration never succeeds into a root that serving and the `store`
  commands then refuse; a regression test migrates into a symbolic-link root. A target
  outside the root is not checked against it. `migrate` never reads `ACTIVE`.
- No command output prints the root.

### 5. The `ACTIVE` record

- `<root>/ACTIVE` is canonical JSON of a typed model with its own
  `active_format_version: 1`: the active store's name and manifest SHA-256, and the
  previous store's, or null. It is a local file this program alone writes and reads,
  not a published contract, so a contract version change never makes it unreadable.
- `ACTIVE` is read within `MAX_ACTIVE_BYTES` (4 KiB, far above the largest record of
  two 64-character names and two digests), checked while reading: at most one byte
  more than the cap is read, and a file over it is unreadable. Tests pin a record of
  exactly the cap and one of a byte more.
- `ACTIVE` is in one of three states. It is absent; it is readable; or it is unreadable:
  not a regular file, a symbolic link, over the cap, not canonical JSON of the model, of
  another `active_format_version`, or naming a store that breaks §4 or two equal names.
- Startup serves the named store only if its manifest still hashes to the recorded
  digest, so a store replaced under the same name is refused.
- Startup, `status`, `activate`, `rollback` and the importer's check of an existing
  target read a manifest through one function, which returns the parsed manifest and
  the SHA-256 of the bytes it parsed; no digest is taken over a re-serialized manifest.

### 6. Writing `ACTIVE`

- Every operation that changes `ACTIVE` holds a non-blocking `flock` on `<root>/.lock`
  from reading `ACTIVE` to replacing it; a second operation exits 1 (`store_lock_held`:
  another store operation is running). Without the lock, two activations could record a
  wrong previous store and a later rollback would land on it. `.lock` is opened with
  `O_NOFOLLOW` and created when absent, must be a regular file, and gets mode 0644 set
  explicitly, so the umask of the run never narrows it.
- The write has a check, a point of no return and a confirmation. Check: the root is
  opened as a directory and synced once, so a root that cannot be opened or synced
  fails before anything changes; this lowers the chance of a later sync failure but
  does not rule it out. Then the new record is written to a temporary file
  `.ACTIVE.tmp-<random>` (`O_EXCL`, mode 0644 set explicitly) and synced. The point of
  no return is the `os.replace` onto `ACTIVE`. Confirmation: the root is synced again.
- Any operating-system error before the replace (on `.lock`, which cannot be created
  or opened or is not a regular file, on the root's check, or on the temporary file)
  leaves `ACTIVE` as it was, removes the temporary file and exits 1 with
  `active_write_failed`, a read-only root included.
- An error in the confirming sync leaves the outcome unknown: `ACTIVE` may already
  name the new store, and whether the change survives a crash is not known. The
  command exits 1 with `active_write_unconfirmed`, which tells the operator to run
  `store status`; it never claims the record is unchanged. A failed `os.replace` itself
  is `active_write_failed`, since the rename either happened or did not.
- The file operations reach the store activation code through an injected file-system
  seam, so tests fail each point (the check, the temporary write, the replace and the
  confirming sync) and assert the reason code and what `ACTIVE` then holds.
- `activate` and `rollback` read the record under the lock. For `activate`, an absent
  record starts a first activation, with no previous store; `rollback` with no record
  exits 1 with `no_previous_store`. An unreadable one refuses the operation
  (exit 1, `active_unreadable`) and is left as it is: it may have been written by a
  later release, so replacing it could lose that release's rollback target. The runbook
  says to inspect it and remove it by hand before activating again.

### 7. Validation and rollback

- `store validate NAME` and `store activate NAME` check the name (§4) and run
  `verify_corpus_store`: every checksum, size, evidence ID and record-to-anchor rule.
  At 250,000 synthetic records verification uses time and memory.
- Activation records the store active before it as the previous store, whatever state
  that store is in now; a rollback verifies it again before using it.
- Rollback is one level: the previous store becomes active and the record keeps no
  previous store. A previous store created under an earlier contract version is a
  valid target, as long as its format is one this reader reads (§15). The previous
  store is verified again and its digest checked, since it may have changed or gone
  since. With no previous store, rollback exits 1; serving the fixture again means
  unsetting `CVE_KGRAG_STORE_ROOT`.
- Activating the store already active verifies it again and keeps the previous store:
  `ACTIVE` is replaced only if the manifest digest differs, so rollback still lands on
  the store active before it.
- Activation runs only verification, not the checks composition runs when it builds the
  in-memory indexes, so a test pins that every store `verify_corpus_store` accepts also
  builds them.

### 8. The `store` commands

- `cve-kgrag store validate NAME | activate NAME | rollback | status`, implemented in
  `adapters/store/store_activation.py` beside the store reader (`application/` may not
  import adapters; WP9's orchestration sits in `adapters/migration` the same way).
- Exit codes: 2 for a usage error, which includes an unset root (naming the variable)
  and a name that breaks §4, printed as a usage message. 1 for any other failure,
  printed as one line with its reason code and never a path: `store_root_unusable` (§4),
  `store_missing`, `store_changed`, `store_invalid`, `store_format_unsupported`,
  `active_unreadable`, `store_lock_held`, `active_write_failed` (nothing changed: the
  lock, the root's check or the new record failed before the replace, or the replace
  itself failed), `active_write_unconfirmed` (the confirming sync failed after the
  replace; run `store status`) or
  `no_previous_store`. 0 otherwise.
- `status` prints a `StoreStatus` JSON document. Its `active_record` is `ok`,
  `no_active_store` or `active_unreadable`. With a readable record, it gives the active
  store, and the previous one or null, each with its name, the digest `ACTIVE` records
  and a closed condition: `ok` when the manifest still hashes to that digest and the
  store verifies, `store_missing`, `store_changed`, `store_format_unsupported` or
  `store_invalid`. For the active store these are the startup reasons
  `active_store_missing`, `active_store_changed`, `store_format_unsupported` and
  `store_invalid` (§9).
- Only an `ok` store also shows its import identity, its corpus content digest and
  `cve_search` version, and the contract version it was created under. `status`
  verifies each store whose manifest matches before it shows that store's digest, so
  the version shown is the one startup would serve; at 250,000 synthetic records that
  is up to two verifications. `activate` and `rollback` reuse the
  verification they have just run, and print the status after their change.
- `status` exits 0 when the record is readable and the active store is `ok`, and 1
  after printing otherwise; a previous store that is not `ok` does not fail it. No
  output names the root, and no manifest free text appears.
- The importer's fixed rollback instruction names this command: "After activation, use
  `cve-kgrag store rollback`." Each manifest keeps the instruction its importer wrote,
  so a `2.0.0-dev.25` store carries that release's wording; the reader accepts any
  bounded instruction text and no command prints it (ADR 0008 §9).

### 9. Startup

- `load_served_corpus(store_root)` returns the fixture when the root is unset. Otherwise
  it reads `ACTIVE` (a regular file, never followed through a link), loads the named
  store with `load_corpus_store` and checks its digest against the record. Any failure
  raises `StoreUnavailable` with a closed reason code and never a path or file content:
  `store_root_unusable`, `no_active_store`, `active_unreadable`, `active_store_missing`,
  `active_store_changed`, `store_invalid` or `store_format_unsupported`. An operating
  system error reports the code of the file it concerns: the root, `ACTIVE` or the
  store.
- `store_format_unsupported` comes from the manifest's `store_format_version`, read
  before the rest of the manifest is parsed: an integer other than 1 is a format this
  release cannot read, such as one a later release wrote. The operator activates a store
  this release can read, or re-imports with this release. A missing or malformed format
  version is `store_invalid`.
- A root without `ACTIVE` refuses to start: serving the fixture there would silently
  serve synthetic data to an operator who configured real data (owner decision 16).
- A one-shot command exits 2 with one line; `mcp`, `mcp --http` and `api` print
  `cve-kgrag <command> cannot start: store unavailable: <reason>` and exit 2 before
  binding an HTTP port. Stdio completes its handshake before loading and exits on load
  failure. The order is settings, then the HTTP token, then the extra and runner, then
  the store, then the FiGHT snapshot (§11), so a core install without an extra exits 1
  before it touches any data, and a broken store is reported before a broken snapshot.
- Startup reads `ACTIVE` and the store and writes nothing anywhere under the root, so a
  read-only root serves. It never migrates or rebuilds anything on disk; building the
  in-memory indexes is not a rebuild (owner decision 15).
- `/ready` answers as for the fixture: a server that listens has loaded its store.

### 10. Which commands load what

"Active store or fixture" is the served dataset of §9: the active store when the root is
set, the packaged fixture otherwise. "Configured snapshot or excerpt" is the FiGHT source
of §11: the operator snapshot when one is configured, the packaged excerpt otherwise.

| Command | CVE records and evidence | FiGHT |
|---|---|---|
| `search`, `lookup` | active store or fixture | not loaded |
| `topic`, `investigate` | active store or fixture | configured snapshot or excerpt |
| `capabilities` | active store or fixture | configured snapshot or excerpt |
| `evidence`, `verify` | active store or fixture | configured snapshot or excerpt |
| `mcp`, `mcp --http`, `api` | active store or fixture | configured snapshot or excerpt |
| `eval planner` | always the packaged fixture | per gold case: the packaged excerpt or unavailable |
| `demo` | always the packaged fixture | not loaded |
| `resolve` | not loaded (topic cards only) | not loaded |
| `affectedness` | not loaded (the affectedness port only) | not loaded |
| `migrate legacy` | only the inputs its manifest declares | not loaded |
| `store …` | the named or active store, read directly, not through §9 | not loaded |
| `schema` | not loaded | not loaded |

- Every command reads the one typed settings boundary (ADR 0004), which checks values
  and opens nothing. A command opens, verifies or probes a store or a snapshot only if
  its row loads it, so a configured store or snapshot that is missing or broken fails
  only the commands that use it.
- Tests pin both directions. Against a store root whose store is missing or corrupt,
  `resolve`, `affectedness`, `demo`, `eval planner`, `migrate legacy` and `schema` run.
  Against a configured snapshot that is missing or not catalogued, every command whose
  row loads no configured snapshot runs: `search`, `lookup`, `demo`, `eval planner`,
  `resolve`, `affectedness`, `migrate legacy`, `store …` and `schema`.
- `eval planner` and `demo` stay on the fixture: their gold cases and demo queries name
  fixture CVEs, and the evaluation identity names no dataset, so reports from two
  datasets would compare as equal. M7b adds the corpus content digest to the evaluation
  identity (ADR 0008 §11).
- Both write one fixed line to standard error, once per run whatever the settings,
  saying they use the packaged synthetic fixture and not the store root; `eval
  planner`'s line also says it uses the FiGHT source each gold case names and not a
  configured snapshot. The line names no path, no setting's value and no manifest text.
  Their standard output stays byte for byte the same, and a test runs both with
  `CVE_KGRAG_STORE_ROOT` set and checks they serve the fixture. The report's own
  `dataset` and `corpus_content_sha256` come with the M7b identity change, so the report
  format moves once.
- Requirement D11 is read accordingly: every surface that serves CVE records, search or
  evidence serves the migrated store; the evaluation and demo tools, which are fixed to
  the fixture, and the commands that use no corpus are outside it.
- `eval planner --out` inside the store root is a usage error, as it is inside the
  package: a result directory inside a store makes the reader refuse that store.

### 11. The operator FiGHT snapshot

- Not configured and configured are kept apart. With neither variable set, the commands
  that use FiGHT (§10) serve the packaged excerpt. With both set, they serve that
  snapshot or refuse to start, exit 2: there is no fallback to the excerpt and no FiGHT
  shown as unavailable instead. Commands that load no FiGHT never open the snapshot, so
  a broken one does not fail them.
- The snapshot is opened once per process through `open_regular_file`, which refuses a
  symbolic link and anything but a regular file. Every check runs on the bytes of that
  one open, never on a second open of the path: a read within a 4 MiB cap checked while
  reading (the catalogued full file is 1.1 MiB), then the SHA-256 against the
  configured hash, then the catalog lookup, then the strict YAML parse.
- A failure gives one fixed reason code in the line `cve-kgrag <command> cannot start:
  FiGHT snapshot unavailable: <reason>`, with no traceback, path, file content or
  exception text: `fight_snapshot_missing` (no such file),
  `fight_snapshot_not_regular_file` (a symbolic link or anything but a regular file),
  `fight_snapshot_unreadable` (any other operating-system error while opening or
  reading it, such as `EACCES`, `EMFILE` or `EIO`), `fight_snapshot_too_large`,
  `fight_snapshot_hash_mismatch`, `fight_snapshot_not_catalogued` or
  `fight_snapshot_invalid` (the catalogued bytes do not parse). Tests cover a file
  without read permission and a read that fails part way.
- `mcp --http` and `api` load the snapshot before they bind a port, and `mcp` on stdio
  loads it in the background after the protocol's initialization, along with the store.
  Static tool listings are available during loading; tool calls immediately return
  `data_loading` until the complete toolbox is published. A failure prints its reason
  and exits non-zero, and a client disconnect or Ctrl+C stops the process promptly.
- One process holds one loaded source, and every part of it that uses FiGHT holds that
  same instance: topic context, investigation, the MCP tools, `verify` and the REST
  verification route. A part on the excerpt would replay a set sealed under the full
  snapshot differently.
- The catalog is the one trust root: only a catalogued hash reaches the parser, and an
  operator-supplied catalog would move that root. Adding a snapshot to the catalog is a
  reviewed change that confirms the file holds no YAML anchor or alias, and that review
  is the alias gate. It settles the alias policy ADR 0008 §2 left to WP10: the strict
  loader keeps its behaviour for every caller, and no alias ban is extended to other
  YAML. The catalogued full file holds no anchor or alias.
- The library default, used by tests and `eval planner`, stays the packaged excerpt.
- Topic context lists at most 20 techniques; §11a makes its cuts visible.

### 11a. Truncated answers say so

With the full snapshot a topic can match more FiGHT techniques than a response lists:
the 5G-AKA terms match 30 techniques in the full file and 5 in the excerpt
(`m3-topics-and-threat-context.md`). Nothing in a response says so: the FiGHT source
drops its match count at the cut, and topic context reports `status: ok`,
`coverage: full` and the listed items, so a caller of `search_fight` at its default
limit of 10 sees 10 of 30 techniques as the whole answer. WP10 makes every such cut
visible; the cap of 20 stays and may be revisited later.

- `ThreatContextOutcome` carries `matched_count`: every technique of the loaded
  snapshot that named a term, before the cut. It is at least the techniques listed, 0
  exactly when none is listed, and always 0 on failure. The FiGHT source sets it; the
  outcome is internal and in no published schema. Topic context re-checks it against
  the items, as it re-checks the sent terms.
- `TopicContextWarningCode` gains two codes, each with a decimal subject, the
  convention of `unrelated_candidates_dropped`:
  - `protocol_context_truncated`: the techniques of the loaded snapshot that matched
    the terms the FiGHT search sent (a topic's terms, or a direct FiGHT search's
    `fight_terms`) and are not listed because of this response's bounds; listed plus
    subject is every technique the snapshot matched.
  - `candidates_truncated`: the CVEs topic context already holds, after dedupe and the
    relevance rule, that the section (`implementation_candidates`, or
    `excluded_implementation_candidates` under `protocol_context_only`) does not list,
    only because of its limit. It is not a count of every backend match: each template
    search returns at most `max_results_per_search`, and each retrieval channel cuts
    its own top-k before that, so more matches may exist unseen.
- `unrelated_candidates_dropped` counts the candidates the relevance rule removed, and
  `candidates_truncated` the relevant candidates kept and left out by the limit; the
  two never share a CVE. The warnings come in the order `excluded_term`,
  `topic_not_resolved` or `additional_topic_not_explored`, `source_snapshot_is_excerpt`,
  `term_not_indexed` (a direct FiGHT search's only), `protocol_context_truncated`,
  `unrelated_candidates_dropped`, `candidates_truncated`.
- A warning is given whenever the snapshot matched more techniques, or topic context
  holds more relevant candidates, than the section lists, whatever bound cut it: the
  limit, explicit or default, `max_results_per_search` for FiGHT, or the 20-item
  ceiling.
- A cut changes no status: a response or source outcome that lists fewer items than it
  holds stays `ok`. `SourceOutcome.coverage` is described as the coverage type of the
  loaded snapshot, `full` for the whole catalogued upstream file and `excerpt` for a
  reviewed cut of one; it never says the response lists every match.
- The response validator checks the warnings' structure and their relations to the
  response. Each of the two new codes appears at most once, with a positive decimal
  subject. `protocol_context_truncated` appears only beside an `ok` `mitre_fight`
  outcome, and the listed techniques plus its subject are at most the pinned snapshot's
  technique count. `candidates_truncated` appears only beside a non-empty candidate
  section. The validator cannot check a count, because a response does not carry the
  inputs to derive one: a count's truth rests on the controller that derived it and,
  for an evidence set, on replay, which re-runs the controller against the deployment's
  sources. No sealed response proves a total match count.

In an investigation, `answer_truncated` counts the items the adopted steps knew and the
answer does not list, each once:

- The adopted steps are those the answer is assembled from: the admitted steps of a run
  not stopped as `invalid_evidence`. A rejected, timed-out or discarded step never adds
  to the count, and neither does a repeated warning.
- Let K be the distinct CVEs the adopted steps kept: those a step listed and the
  answer's relevance rule keeps (a CVE the caller named is always kept), and those the
  topic step kept and left out at its limit, which topic context hands the investigation
  internally, beside the sealed response. Let L be the CVEs the answer lists, in
  `implementation_candidates` or, under `protocol_context_only`,
  `excluded_implementation_candidates`, and F the techniques the adopted step that
  searched FiGHT (the topic step or a direct FiGHT search) matched and did not list. The
  count is |K| − |L| + F. A CVE left out by the topic step
  and found again by a search step is one member of K, so it counts once whether or not
  the answer is cut again when it is assembled, and not at all if the answer lists it.
- A run issues at most one topic step and at most one step that searches FiGHT, and
  that step's limit is the per-call cap the answer also uses, so techniques have one
  source and F is exact.
- The count never includes what a CVE tool's own top-k or a retrieval channel cut. The
  answer's `unrelated_candidates_dropped` counts search-step relevance drops that are
  not in K, so it never shares a CVE with `answer_truncated`. The planner observes the
  new codes, never their subjects. `m4-bounded-investigation.md`'s account of
  truncation is rewritten to this rule.
- The evidence-set validator applies the topic-response rules to each step's topic
  warnings, allows `answer_truncated` at most once with a positive subject and never in
  a run with no adopted step, and checks the relations a set does carry: the count is at
  least the adopted steps' cut subjects together, and when the answer lists fewer
  CVEs than the per-call cap, it equals the FiGHT subject of the step that searched
  FiGHT (the topic step then left no CVE out). Replay requires the same counts from the sources now.

A `search` response is the best-ranked bounded result of the top-k each channel cut on
its own: never a complete list, and with no count of what lies beyond, since a count
would need every retriever port to change and a lexical match is any shared token.
`candidates_truncated` counts only candidates topic context already held, and
`answer_truncated` only the CVEs the adopted steps kept and the techniques the step that
searched FiGHT matched. The descriptions of `SearchRequest.limit`, of
`TopicContextRequest.limit` and `max_results_per_search`, and of
`FightSearchRequest.limit` say which of these holds for each, and a follow-up records a
matched count for `search`. §15 lists the schemas this section changes.

### 12. Memory and startup time

- The `api` process shares one read-only data plane between its two deployments, the
  toolbox's and the verification route's, and keeps request execution and admission
  apart. Shared, built once: the loaded records and anchors; the repository, the
  lexical and structured indexes, the relation graph and the `SearchService` over them;
  the one FiGHT source and its pinned snapshot; and the evidence catalog, a read-only
  lookup over the same records, anchors and techniques. Apart: each deployment's
  `ThreadedCallRunner`, its budgets and deadlines, its planner and execution context,
  the verification route's admission lock, and every request's trajectory, warnings,
  timing and result. Replaying a set therefore never counts against investigation
  admission, which only the call runner decides.
- Sharing is safe because what is shared holds no request state: `SearchService.search`
  keeps its channel log per call, the indexes and the catalog are read-only once built,
  the domain models are frozen, and the FiGHT source's search only reads its index. The
  two deployments share only when they serve the same corpus content digest, FiGHT pin
  and semantic state. `api` loads no semantic adapter; serving one would need its own
  concurrency contract, since a third-party retriever is not assumed thread-safe.
- Tests show the indexes and the FiGHT source are built once; an investigation runs
  while verification is blocked or at its admission limit, and verification runs while
  the investigation runner is full; concurrent searches and replays give the results a
  serial run gives; and both paths report the same `cve_search` and `mitre_fight`
  capability versions.
- Measured at 250,000 synthetic records: `load_corpus_store` loads the store;
  one deployment builds its indexes; `mcp`
  loads one deployment; `api` loads two separate deployments.
  Sharing the data plane removes the second deployment's index build; how much startup
  time and peak RSS that saves is measured again by the operator lane (§17), and the
  runbook states the measured figure. A full garbage collection can stall at that
  size; `gc.freeze()` is added only if the lane shows stalls.
- The runbook states the load and memory figures as lower bounds and names no host
  size until real feeds are measured. Health probes see connection refused while an
  HTTP server loads. MCP stdio completes initialization before loading, returns a
  `data_loading` tool error during loading, and announces ready only with a complete
  toolbox. HTTP servers announce data loaded separately from ready, which follows
  successful socket startup; a bind failure prints no ready notice.
- `graph_expand` over 250,000 synthetic records reaches the 10 s tool limit: expanding
  one seed visits every CVE that shares any relation with it, using extra memory
  at peak, and a search with limit 10 times out. These feeds are the graph's worst
  case (every record shares one CWE and one vendor), so the figures are a worst case,
  never NVD performance.
- WP10 changes no graph semantics and pins the present behaviour with tests:
  `graph_expand` defaults to `false`; a timed-out search tool call returns the typed
  `timed_out` failure and no candidates; an abandoned call keeps its place in the
  toolbox's call runner until its thread returns, so concurrent timeouts never pass the
  live-call cap. The runbook says that a timeout does not stop the running Python call,
  whose CPU and memory stay in use until it returns, and that the one-shot `search` has
  no tool limit and runs to completion. The real-store release check below records the
  decision for corpus stores.

### 13. Server instructions and attribution

- The MCP instructions are built from `ServedDataset.kind`, as one of two fixed texts:
  the fixture's, which says the server serves the packaged synthetic fixture, or the
  store's, which says it serves the dataset of an imported corpus store, named by
  `get_knowledge_capabilities`' `cve_search` version, followed by the NVD attribution
  sentence from the source registry ("This product uses data from the NVD API but is not
  endorsed or certified by the NVD.").
- No manifest text reaches them: the reader checks the manifest's free-text fields only
  against their length and character bounds, never for content, and the instructions are
  read by a language model. The store's text does not claim the data is real; a store
  imported from synthetic feeds is still a corpus store.

### 14. The semantic channel and legacy `KEV-` chunks

- With a store served, a run that requests the semantic channel (ADR 0004 §1: the
  channel enabled and the command run with `--semantic`) cannot have it until a
  collection can prove it was built from that store's dataset, and none can: a
  collection records no `corpus_content_sha256`, and the only check on its hits, that
  each CVE ID is one the repository holds, accepts a stale or unrelated collection whose
  IDs overlap the store, whose hits could then make an investigation `sufficient`
  through `semantic_only` relevance.
- So in store mode no command loads the semantic adapter or opens the collection,
  whatever `CVE_KGRAG_SEMANTIC_ENABLED` and `--semantic` say. A `capabilities` run that
  requests the channel reports `semantic_channel` unavailable with a new
  `SemanticUnavailableDetail`, `COLLECTION_NOT_BOUND` ("the semantic collection is not
  bound to the served corpus store"). A `search`, `topic` or `investigate` run that
  requests it answers without the channel and reports it unavailable with a new
  `BackendFailure`, `collection_not_bound`, the way an enabled channel whose adapter
  cannot be loaded is reported; the evidence-set validator accepts that reason beside
  the capability's. A run that does not request the channel reports `not_configured`, as
  with the fixture; ADR 0004 §1 holds the four-row table. The store check comes before
  adapter discovery, so in store mode a missing adapter reports `COLLECTION_NOT_BOUND`,
  not `ADAPTER_UNUSABLE`. Tests run each command with `--semantic` against a store and a
  collection whose IDs overlap it, and assert that no hit is used; and cover each row of
  the ADR 0004 table, including store mode with the channel enabled but no `--semantic`,
  and with `--semantic` but no adapter installed.
- The semantic index build follow-up builds a collection from a store and records its
  `corpus_content_sha256`; the channel becomes available in store mode only when that
  digest equals the served one. Such a collection holds neither `KEV-` chunks nor CVEs
  the store lacks.
- With the fixture served, the semantic channel reads the legacy collection ADR 0006 §5
  describes. Such a collection may also hold `KEV-` chunks, whose `cve_id` metadata is
  not a CVE ID. The channel refuses such a hit as malformed, so a query that reaches
  one reports the semantic channel as failed and the response as `partial`; ADR 0006
  §5 records this beside the collection format.
- `semantic_channel` has no version: a set sealed with `--semantic` does not verify
  (`m6-api-cli-and-migration.md`, WP2).

### 15. Contracts

Every versioned schema moves to `2.0.0-dev.26` through its `schema_version`. Beyond
that:

- `store_status.schema.json` is published (§8).
- `migration_report.schema.json`: the report carries the rollback instruction that names
  `cve-kgrag store rollback`, and a `corpus_content_sha256`, present exactly when the
  report names a store (`imported` or `already_imported`) and taken from the
  verification of that store, the one the run wrote or the existing one it found; and
  the failure codes `target_in_store_root` and `store_root_unusable` (§4).
- `SemanticUnavailableDetail` and `BackendFailure` gain `collection_not_bound` (§14),
  which changes `knowledge_capabilities.schema.json` and every schema that carries a
  channel outcome: `search_response`, `topic_context_response` and
  `knowledge_evidence_set`.
- `corpus_store_manifest.schema.json`: `schema_version` and the rollback instruction
  are bounded strings with no default (below). A `dev.25` manifest is a valid format-1
  manifest under it.
- `topic_context_response.schema.json` and `knowledge_evidence_set.schema.json`: the two
  truncation codes and the coverage description (§11a). In `knowledge_evidence_set`,
  `answer_truncated` keeps its code and its decimal subject, and its subject counts the
  items §11a defines, the topic step's cuts included.
- `search_request.schema.json`, `topic_context_request.schema.json` and
  `fight_search_request.schema.json`: the limit descriptions (§11a).
- `schemas/v2/manifest.json`, which pins every schema's hash.

The two version axes:

- The product contract version (`SCHEMA_VERSION`) versions what the surfaces send and
  receive; the store format version (`store_format_version`, 1) versions what a store
  persists, and decides whether a store can be read (ADR 0008 §9). Stores written under
  `dev.25` are served under `dev.26` without a re-import.
- The manifest's `schema_version` records the contract version the store was created
  under: a string of the contract version's shape
  (`^[0-9]+\.[0-9]+\.[0-9]+(-dev\.[0-9]+)?$`, at most 32 characters), never compared with
  `SCHEMA_VERSION`. Its rollback instruction is bounded text (1 to 512 characters, no
  hidden characters), never compared with the current sentence; every `dev.25`
  instruction meets that bound. Neither field has a default: the importer passes both,
  so from `dev.26` on `corpus_store_manifest.schema.json` does not change with the
  contract version. `rollback_kind` and `rollback_scope` keep their single values;
  adding a value keeps format 1, renaming one does not.
- The import identity keeps the contract version (ADR 0008 §4), passed in by the caller
  like the importer version, so a re-import under another contract is another import.
- `dev.26` changes no persisted shape. New stores record `2.0.0-dev.26` and the
  instruction that names `cve-kgrag store rollback`.
- The evaluation identity and `investigation_id` keep their shapes;
  `knowledge_capabilities` changes only by the semantic detail above, and a store's
  `cve_search` version differs from the fixture's only in value. A
  `dev.25` report has no content digest; the reader derives one for any format-1 store.

What moves the format version, and requires a re-import, is listed in ADR 0008 §9.
Two guards protect format 1:

- The compatibility store: a format-1 store written by the importer at `28e5b4d`
  (`2.0.0-dev.25`), committed under `tests/` with that commit recorded beside it. Its
  bytes never change and no test regenerates it with the current importer; the test
  pins the SHA-256 of every file in it, outside the store, so the store and the reader
  cannot both change while the test still passes. Its inputs are authored with the test
  helpers in `tests/support/legacy_inputs.py` (not the operator scale feeds) so that,
  for each field it persists, it holds every value-set member the `dev.25` importer can
  produce, a KEV entry included, and nothing that importer could not write; it records
  no local path. The test runs `verify_corpus_store` and `load_corpus_store` in full and
  checks the records and evidence IDs.
- The schema alarm: `STORE_FORMAT_VERSION` sits beside a pinned SHA-256 of the
  canonical published schemas of `CorpusStoreManifest`, `CveRecord` and
  `EvidenceAnchor`. A test fails when it differs, a change to a field description
  included; it proves nothing about compatibility and moves nothing by itself. The
  change is judged by hand and either re-pinned, with the reason it keeps format 1, or
  made a format change.

### 16. Verification across activations

- A process serves the store that was active when it started; activation and rollback
  take effect for a server when it restarts (no hot reload). A set therefore verifies
  against the dataset the process serves (ADR 0003 §10).

### 17. Operations and the M6 exit

- An operator measurement lane beside `scripts/operator/migration_scale.sh` migrates
  synthetic feeds into a store, activates it and records `load_served_corpus` and the
  `api` build's time and memory.
- The runbook covers migrate, validate, activate, status, roll back and restart; the
  re-import a store format change requires; removing an unreadable `ACTIVE` (§6); and,
  before a program downgrade, activating a store the earlier release can read (ADR 0008
  §9). `THIRD_PARTY_DATA.md` gains the operator FiGHT snapshot and an operator corpus
  store with the NVD notice.
- The M6 exit audit is the repository's requirement baseline for M6, since the rebuild
  brief and the requirements inventory are not committed. Every requirement ID from A1
  to H gets a self-contained entry: the ID; its source type (a sentence of the brief, an
  item derived by the inventory, or a split made by the M6 plan); the brief's sentence
  verbatim, or the item's full description; the interpretation adopted; where it is
  implemented and which tests show it; and its status and follow-ups. The audit also
  records owner decisions 15 to 17 in full.
- Entries cite the brief as "Owner-provided rebuild brief, 2026-10-13, §N" and the
  inventory as "M6 requirements inventory, reconstructed 2026-10-21 and owner-approved";
  an entry the M6 plan produced by a split, such as E4a or E4b, quotes and cites the
  brief sentence or inventory item that was split and records the split as a note.
  The audit, like everything else in the repository, names no local path under the
  owner's home directory, no session ID and no conversation content.
- D9 quotes brief §17. "Versioned directory" means a new directory the importer never
  overwrites, identified by its manifest digest and import identity; the indexes
  startup builds in memory, with nothing written to disk, are the owner's refinement
  (owner decision 15); a persisted semantic index must follow D9. D11 is a gap the
  inventory derived from the brief, not a sentence of it, and is read as §10 states.
  E4a and E4b each quote brief §15 and record that the M6 plan split E4 into E4a (HTTP
  settings, WP6) and E4b (store root and FiGHT snapshot settings, WP10).
- `PLAN.md` marks M6 done and records the follow-ups below.

## Follow-ups recorded

CSAF; an allowlisted refresh command; the semantic index build from a store, bound by
its `corpus_content_sha256` (§14), which also settles `KEV-` chunks; the `search_cves`
filtered seam; the Trustify adapter; the planner round-2 fix (`PLAN.md`, "Follow-up:
model planner adapter"); hot reload; removing old stores; the corpus content digest in
the evaluation identity (M7b); serving memory on real feeds (the importer's 1 GiB
per-file cap checks and pending import measurements are recorded in `PLAN.md`);
revisiting the 20-technique topic-context cap, whose cuts are reported (§11a); a matched
count for `search` responses; `gc.freeze()` if stalls are measured.

### The `graph_expand` real-store release check

The bounded check passed on 2026-10-31 on the 396,211-record NVD store whose
`corpus_content_sha256` is
`0dc90836bb0f02f748ef0bd758909711557cb85413110c58a14d5a4d55c15f3a`.
`scripts/operator/measure_graph_expand.py` fixes the criteria before running: every
ordinary query must finish inside the 10 s tool limit with a usable graph outcome;
high-degree queries must finish inside it or give an existing honest bounded outcome,
not hang or fail; and peak RSS must stay within 1 GiB of the recorded serving baseline.
It loads the store once, builds the existing shared serving data plane and both API
deployments, and measures synchronous search calls without a model or network. An
operator watchdog interrupts any call still running after 60 s and fails the check;
late successful returns also fail, since `result_limit_reached` bounds only the list
returned, not the graph traversal.

| Relation | Distinct values | Median degree | p99 degree | Max degree |
|---|---:|---:|---:|---:|
| CWE | 811 | 14 | 10,463 | 48,754 |
| Vendor | 36,595 | 1 | 78 | 17,280 |
| Product | 121,689 | 1 | 85 | 15,187 |
| CPE | 374,206 | 1 | 90 | 14,191 |
| purl | 0 | — | — | — |

Degrees count CVEs per relation value; p99 uses nearest rank. Ten typical seeds, two
lexical matches each for Open5GS, free5GC, Kamailio, OpenSIPS and OpenAirInterface named
in the permitted gold cases (M7b baseline only, or relevance), completed.
Ten high-degree seeds chosen from the four leading CWEs, three vendors and three
products (degrees 8,366–48,754) completed. All twenty finished within 10 s,
with an `ok` graph outcome, 10 returned candidates at limit 10, and the existing
`result_limit_reached` warning. There were no errors or watchdog interruptions.

Python `resource` reported a process peak RSS, equal
to the same process's serving startup peak. That is below the recorded API serving
baseline, so the fixed 1 GiB allowance passes as well.
All criteria pass; `graph_expand` remains available on corpus stores, with no tuning
or contract change. The operator's `measurement.json` and `summary.md` under
`~/data/cve-kgrag/runs/graph-expand/` retain the per-seed figures and CVE IDs without
record text. The check is bounded to these twenty single-CVE queries and does not
establish a bound for arbitrary multi-seed searches. See also the measured paragraph
in [`PLAN.md`](../PLAN.md).

## Deviations from the M6 plan

| Plan | This ADR | Why |
|---|---|---|
| capabilities report `store_id` and version | the `cve_search` version names the dataset by its content digest; the manifest digest names the physical store and the import identity the import | the plan's `store_id` became the import identity (ADR 0008), which names the import, not the dataset: a run under another importer or contract version moves it while the records and anchors can stay byte for byte the same, and those two files alone name the dataset; another `retrieved_at` is another dataset as well as another import only when it changes the anchors; the content digest decides |
| `application/store_activation.py` | `adapters/store/store_activation.py` | `application/` may not import adapters, and activation needs the store reader |
| `store validate DIR`, `activate DIR` | a store name under the root | one root governs who may activate; paths never appear in output |
| "resolves the active store, or the fixture" | a root without `ACTIVE` refuses to start | owner decision 16: no silent fallback to synthetic data |
| every surface serves the store | `eval planner` and `demo` stay on the fixture; `resolve` and `affectedness` load no records | gold cases and demo queries name fixture CVEs; the evaluation identity names no dataset until M7b |
| `SERVER_INSTRUCTIONS` built from the identity | one of two fixed texts, by dataset kind | no manifest text reaches a language model; capabilities already carry the identity |
| no contract change named; dev.24 | `dev.26`, `store_status` published; dev.25 stores served without re-import | contracts reached dev.25 in WP9; the store format version, not the contract version, gates reading |
| (not in the plan) NVD attribution | the store's instructions carry the NVD notice | the NVD terms ask for it on every service using NVD data |

## Consequences

- A configured deployment either serves exactly the store its operator activated, with
  the FiGHT snapshot they pinned, or refuses to start; it never falls back.
- Moving the contract version leaves existing stores servable; only a store format
  change requires a re-import, and the two format guards make one a deliberate
  decision.
- A set sealed under one contract version still does not verify under another.
- A real store makes servers consume startup time and memory at
  hundreds of thousands of records.
