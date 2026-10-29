# Operator runbook: corpus stores and the FiGHT snapshot

How to import, activate, serve and roll back a corpus store, and how to serve the full
MITRE FiGHT snapshot. The decisions behind each step are in
[ADR 0008](rebuild/adr/0008-legacy-data-importer.md) (the importer and the store format)
and [ADR 0009](rebuild/adr/0009-store-activation-and-serving.md) (activation and
serving).

## The store root

`CVE_KGRAG_STORE_ROOT` names an absolute directory that holds the corpus stores and
`ACTIVE`. Unset, every surface serves the packaged synthetic fixture (`CVE-9999-*`
records). Set, every surface that serves CVE records serves the store `ACTIVE` names, or
refuses to start: it never falls back to the fixture.

- A store lives directly under the root, named by one path component of letters,
  digits, `.`, `_` and `-`, starting with a letter or digit, at most 64 characters, and
  not `ACTIVE` in any letter case. Choose names that say what the store holds, such as
  `nvd-2026-10-26`.
- The root must be a directory, not a symbolic link (a link among its parent
  directories is fine). Startup reads the root and writes nothing under it, so a
  read-only root serves; `store activate` and `store rollback` need it writable.
- `ACTIVE` records the active store and the one active before it, each by name and by
  the SHA-256 of its manifest. A store replaced under its name is refused until it is
  activated again.
- No command prints the root's path.

A store has three identities, which the commands show:

- `store_manifest_sha256` names the physical store one import wrote; `ACTIVE` pins it.
- `import_identity_sha256` names the import and its provenance.
- `corpus_content_sha256` names the dataset the store holds. A server reports it in the
  `cve_search` capability version, `corpus-store-v1@sha256:<digest>`, and an evidence set
  verifies against any store holding byte-for-byte the same records and anchors.

## Fetch the inputs

Raw feeds, the input manifest, stores and evaluation results are data under NVD's and
CISA's terms, and evaluation results hold queries and model text: keep all of them
outside every repository, for example under `~/data/cve-kgrag/` (`feeds/`, `stores/`,
`runs/`), and never commit or push them. The repository's `.gitignore` catches a copy
made inside the checkout by mistake.

```bash
scripts/operator/fetch_feeds.sh ~/data/cve-kgrag/feeds/2026-10-27
```

The script downloads every NVD 2.0 year feed from 2002 to the current year, the
`modified` feed and the current KEV catalog from their official URLs into a new
directory, pausing between NVD requests and retrying failed transfers with backoff. It
checks each NVD feed against the SHA-256 its `.meta` file states for the decompressed
JSON, then writes `provenance.tsv` (each file's URL, retrieval time, file and payload
SHA-256 and size) and `inputs.yaml`, the input manifest for the import below. Both
appear only once every file has arrived and verified; a run that stops leaves them as
`.partial` files, and is repeated into a new directory. A full fetch downloads
about 270 MB.

## Import a store

Write an input manifest declaring each raw NVD feed and the CISA KEV catalog with the
time it was obtained (ADR 0008), or use the one `fetch_feeds.sh` wrote, then import into
a new directory directly under the root:

```bash
export CVE_KGRAG_STORE_ROOT=/srv/cve-kgrag/stores
uv run cve-kgrag migrate legacy --inputs inputs.yaml --dry-run \
  --target "$CVE_KGRAG_STORE_ROOT/nvd-2026-10-26"
uv run cve-kgrag migrate legacy --inputs inputs.yaml \
  --target "$CVE_KGRAG_STORE_ROOT/nvd-2026-10-26"
```

The report names the store by `store_manifest_sha256` and `import_identity_sha256`, and
its dataset by `corpus_content_sha256`. With the root set, a target that lies in the root
but is not a validly named store directly under it is refused (`target_in_store_root`),
and so is a root that is a symbolic link or not a directory (`store_root_unusable`).
Importing writes nothing but the new store, and never activates it. Before activation,
undoing an import is deleting its directory.

## Validate, activate and check

```bash
uv run cve-kgrag store validate nvd-2026-10-26   # verify it, change nothing
uv run cve-kgrag store activate nvd-2026-10-26   # verify it and record it active
uv run cve-kgrag store status                    # what ACTIVE records, each store checked
```

- `validate` and `activate` check every checksum, size, evidence ID and record-to-anchor
  rule; at 250,000 synthetic records that requires verification. `validate` prints the store's
  identity; `activate` and `rollback` print the status after their change.
- `activate` records the store active before it as the one `rollback` returns to.
  Activating the store already active verifies it again and keeps the previous store.
- `status` exits 0 when `ACTIVE` is readable and the active store is `ok`, whatever the
  previous store's condition, and 1 otherwise, after printing. A store is `ok` when its
  manifest still hashes to the digest `ACTIVE` records and it verifies; otherwise it is
  `store_missing` (`active_store_missing` for the active store), `store_changed`
  (`active_store_changed`), `store_format_unsupported` or `store_invalid`. `status`
  verifies each store whose manifest matches, so a large root takes up to two
  verifications.

Servers serve the store that was active when they started: restart `mcp`, `mcp --http`
and `api` after an activation or a rollback. There is no hot reload.

## Roll back

```bash
uv run cve-kgrag store rollback
```

Rollback makes the previous store active again, verified again under the digest
`ACTIVE` recorded for it, and records no previous store: it is one level. It refuses a
previous store that is missing, replaced or invalid, and changes nothing then. With no
previous store it exits 1 (`no_previous_store`). To serve the packaged fixture again,
unset `CVE_KGRAG_STORE_ROOT`; that serves synthetic data.

## When a store operation fails

Every failure exits 1 with one line naming its reason code; a usage error (no root, a
name that is no store name) exits 2.

| Reason | What happened | What to do |
|---|---|---|
| `store_root_unusable` | the root is missing, not a directory, a symbolic link or unreadable | fix the root or `CVE_KGRAG_STORE_ROOT` |
| `store_missing`, `store_changed`, `store_invalid` | the store is not there, was replaced under its name, or fails verification | re-import, or activate another store |
| `store_format_unsupported` | the store was written in a format this release does not read | re-import with this release, or activate another store |
| `store_lock_held` | another `activate` or `rollback` holds `<root>/.lock` | wait for it, then retry |
| `active_write_failed` | `ACTIVE` could not be written; it is unchanged | check the root is writable and has space, then retry |
| `active_write_unconfirmed` | `ACTIVE` was replaced but the change could not be synced | run `store status` to see what `ACTIVE` now names |
| `active_unreadable` | `ACTIVE` is not a record this release reads | see below |
| `no_previous_store` | `ACTIVE` records no store to roll back to | activate a store by name |

An unreadable `ACTIVE` is never replaced by `activate` or `rollback`: a later release may
have written it, and replacing it could lose that release's rollback target. Inspect it
(it is canonical JSON naming two stores and their digests); if this release should own
the root again, move it aside by hand and activate a store by name.

## Starting a server against a store

`search`, `lookup`, `topic`, `investigate`, `capabilities`, `evidence`, `verify`, `mcp`,
`mcp --http` and `api` load the active store. A root they cannot serve stops them with
exit 2 and the line `cve-kgrag <command> cannot start: store unavailable: <reason>`,
before a server binds a port. The reasons are `store_root_unusable`, `no_active_store`,
`active_unreadable`, `active_store_missing`, `active_store_changed`, `store_invalid` and
`store_format_unsupported`; `store status` says more. `resolve`, `affectedness`,
`migrate`, `store` and `schema` load no served store; `demo` always uses the packaged
fixture, and so does `eval planner` for an M7a gold file, each saying so on standard
error. `eval planner` with an M7b gold file runs on the active store and the operator
FiGHT snapshot
([`m7b-planner-evaluation.md`](rebuild/m7b-planner-evaluation.md#the-command)).

A server loads its store before it answers: health probes see connection refused while
it loads, and an MCP client on stdio waits for its initialize answer through the load.
The figures below are from synthetic records of one CPE and a short description each, so
real NVD records need more time and memory; they are lower bounds, not a sizing.

Measured by `scripts/operator/serving_scale.sh` on 250,000 synthetic records (a synthetic
store) , one run on 2026-10-26:

| What | Wall time | Peak resident memory |
|---|---|---|
| loading the active store | — | — |
| `api` startup: the store, then its two deployments over one shared data plane | — | — |
| the same two deployments, each over its own data plane, for comparison | — | — |

Sharing the data plane saves the second index build; it does not
lower the peak, which is reached while the store loads. `mcp` builds one deployment, as
the shared `api` build does once. Plan for more than these figures with real records,
and run the lane again on the host that will serve.

## The semantic channel against a store

With a store served, a run that asks for the semantic channel (`--semantic` with
`CVE_KGRAG_SEMANTIC_ENABLED`) gets it as unavailable, `collection_not_bound`: no Chroma
collection records the dataset it was built from, so none is opened. Without
`--semantic` it is `not_configured`, as with the fixture.

## Tool time limits

A tool call over MCP or the REST API stops waiting at its time limit and answers
`timed_out`, but the Python call it started keeps running, with its CPU and memory, until
it returns; it keeps its place under the toolbox's limit of calls in flight until then.
`--graph-expand` on a large store can reach that limit: on 250,000 synthetic records,
whose every record shares one CWE and one vendor, expanding one seed completed and a
search with limit 10 timed out. That is the graph's worst case, not NVD performance. The
one-shot `cve-kgrag search` has no tool limit and runs to completion.

## The operator FiGHT snapshot

By default every command that uses FiGHT serves the packaged six-technique excerpt. To
serve the full catalogued file, fetch `fight.yaml` at the commit the reviewed catalog
names (`src/cve_kgrag/knowledge/fight_snapshots.yaml`, the `coverage: full` entry), check
its SHA-256, and set both variables:

```bash
curl -fsSLo /srv/cve-kgrag/fight.yaml \
  https://raw.githubusercontent.com/mitre/FiGHT/097cd5f73811dc34916ef84d5acc3fe7aba70450/fight.yaml
sha256sum /srv/cve-kgrag/fight.yaml   # or shasum -a 256 on macOS; expect 59a9addb…a7a8
export CVE_KGRAG_FIGHT_SNAPSHOT_PATH=/srv/cve-kgrag/fight.yaml
export CVE_KGRAG_FIGHT_SNAPSHOT_SHA256=59a9addbd75d8680091797d66d5b237d9d026512990c61a6f51692ca94d2a7a8
```

A configured snapshot is served or the command refuses to start, exit 2, with
`cve-kgrag <command> cannot start: FiGHT snapshot unavailable: <reason>`:
`fight_snapshot_missing`, `fight_snapshot_not_regular_file`, `fight_snapshot_unreadable`,
`fight_snapshot_too_large` (over 4 MiB), `fight_snapshot_hash_mismatch`,
`fight_snapshot_not_catalogued` or `fight_snapshot_invalid`. It never falls back to the
excerpt. Only a hash the reviewed catalog lists is ever parsed: serving another FiGHT
file is a reviewed change to the catalog. With the full snapshot a topic can match more
techniques than a response lists; `protocol_context_truncated` counts the rest.

## Store formats, upgrades and downgrades

A store's `store_format_version` decides whether a release can read it; the contract
version it was created under is provenance only. This release reads format 1, including
stores written under `2.0.0-dev.25`, without a re-import. A release that changes the
store format says so in its notes; stores then need a re-import with that release.

Compatibility runs in one direction. The `2.0.0-dev.25` release (commit `28e5b4d`) reads
no store written from `2.0.0-dev.26` on. Before downgrading the program, use the newer
release to activate a store the earlier release can read, such as one it imported
itself; then downgrade and restart.

## Data terms

A store holds NVD and CISA KEV data under their terms
([`THIRD_PARTY_DATA.md`](../THIRD_PARTY_DATA.md)); keep stores and FiGHT snapshots out
of version control. A server over a store gives MCP clients the NVD notice: "This
product uses data from the NVD API but is not endorsed or certified by the NVD."
