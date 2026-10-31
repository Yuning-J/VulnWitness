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

## Refresh a store

Keep raw feeds, manifests, stores and run outputs outside every repository, for example
under `~/data/cve-kgrag/`. They contain data under NVD's and CISA's terms; evaluation
outputs can also contain queries and model text.

With the store root created, run from the checkout using its installed environment:

```bash
export CVE_KGRAG_STORE_ROOT=/srv/cve-kgrag/stores
.venv/bin/python scripts/operator/refresh_store.py \
  --feeds-dir ~/data/cve-kgrag/feeds/2026-10-31 --store nvd-2026-10-31 --activate
```

Then restart API and MCP services. They keep serving the store loaded at startup;
activation and rollback do not hot reload it. Rollback is the command below, followed
by another restart.

The refresh command checks the root and fresh store name, then runs these steps,
stopping on the first failure:

1. `fetch_feeds.sh` downloads NVD 2.0 year feeds from 2002 to the current year, the
   `modified` feed and CISA KEV into a fresh directory. It paces and retries requests,
   compares each decompressed NVD feed with its `.meta` SHA-256, and publishes
   `provenance.tsv` and `inputs.yaml` only after all downloads succeed. A full fetch
   downloads about 270 MB. Retry an interrupted fetch into a fresh directory.
2. `migrate legacy` imports into the fresh store under the root, printing its report
   and the three identities above. It never changes `ACTIVE`; a failed import stops
   the refresh before activation.
3. With `--activate`, `store activate` verifies every checksum, size, evidence ID and
   record-to-anchor rule, then records the store in `ACTIVE` and prints status.
   It preserves the previous store for rollback. A separate `store validate` is optional.

Use `--inputs /data/feeds/inputs.yaml` instead of `--feeds-dir` to import existing local
feeds without downloading. Omit `--activate` to leave `ACTIVE` untouched; the command
prints the separate activation command. No snapshot hashes need to be copied into
settings for a refresh. FiGHT still requires a reviewed catalog entry, as described below.

For individual checks and activation:

```bash
cve-kgrag store validate nvd-2026-10-31
cve-kgrag store activate nvd-2026-10-31
cve-kgrag store status
```

`validate` changes nothing. `activate` and `rollback` print status after changing
`ACTIVE`; activating the already active store verifies it again and keeps the previous
store. `status` exits 0 when the active store is `ok`, regardless of the previous
store's condition, and 1 otherwise. It verifies each store whose manifest matches the
recorded digest, so it can perform two verifications.

## Roll back

```bash
cve-kgrag store rollback
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

`search`, `lookup`, `product`, `topic`, `investigate`, `capabilities`, `evidence`, `verify`, `mcp`,
`mcp --http` and `api` load the active store. A root they cannot serve stops them with
exit 2 and the line `cve-kgrag <command> cannot start: store unavailable: <reason>`,
before an HTTP server binds a port; stdio reports the failure after its handshake. The
reasons are `store_root_unusable`, `no_active_store`,
`active_unreadable`, `active_store_missing`, `active_store_changed`, `store_invalid` and
`store_format_unsupported`; `store status` says more. `resolve`, `affectedness`,
`migrate`, `store` and `schema` load no served store; `demo` always uses the packaged
fixture, and so does `eval planner` for an M7a gold file, each saying so on standard
error. `eval planner` with an M7b gold file runs on the active store and the operator
FiGHT snapshot
([`m7b-planner-evaluation.md`](rebuild/m7b-planner-evaluation.md#the-command)).

HTTP servers load before binding: health probes see connection refused during loading.
MCP stdio answers `initialize` and static `tools/list` before loading finishes. Every tool
call during loading immediately returns the explicit `data_loading` tool error, “The
data is still loading; retry later.” Nothing is queued or retried automatically. A load
failure prints its reason and exits non-zero; closing stdin or Ctrl+C stops stdio
promptly even while the loader is blocked.

Every command that loads a configured store writes
`cve-kgrag <command>: loading store <name>; ...` to standard error once the store's checks
pass, then `cve-kgrag <command>: <dataset version> data loaded after <N> s` once its
indexes are built. Stdio prints `cve-kgrag mcp: <dataset version> ready after <N> s` only
once its complete toolbox is usable. HTTP servers print
`cve-kgrag <command>: ready on http://<host>:<port>` only after the port is bound and
serving; bind failures print no ready notice. Standard output stays the command's JSON
or the MCP protocol.

**Real data.** The figures for a full NVD store (the store of 2026-10-27)
 are in the README's
[Running on real data](../README.md#running-on-real-data) section: store loading
and peak resident memory. Size a host from those.

**Synthetic data.** The table below is from 250,000 synthetic records of one CPE and a
short description each, measured by `scripts/operator/serving_scale.sh` (a synthetic store)
on the same machine, one run on 2026-10-26. It compares builds against each other; it is
no sizing: loading the real store alone (`load_served_corpus`) differs from
the synthetic store:

| What | Wall time | Peak resident memory |
|---|---|---|
| loading the active store | — | — |
| `api` startup: the store, then its two deployments over one shared data plane | — | — |
| the same two deployments, each over its own data plane, for comparison | — | — |

Sharing the data plane saves the second index build; it does not
lower the peak, which is reached while the store loads. `mcp` builds one deployment, as
the shared `api` build does once.

## Product inventory queries

`cve-kgrag product --vendor openairinterface --product oai-cn5g-amf --version 2.0 --format text`
reads the active corpus directly through exact case-folded product fields, with a
description-token fallback only for records with no implicated products. Omit
`--product` for all products of the vendor. `--limit` defaults to 10 and is capped at
20; the answer counts `total_available` and shows every matched vendor:product pair
before the cap. Use `--format json` for records, bases and evidence anchors.

The server equivalents are authenticated `POST /api/v2/product` and MCP
`query_product_vulnerabilities`, taking `vendor`, `product`, `version` and `limit`.
Version annotates the retained NVD conditions without filtering CVEs or deciding
affectedness. `basis.kind` distinguishes `product_field` from `description_mention`;
mention-only results cannot confirm vendor ownership or version conditions. See
[Product vulnerabilities](../README.md#product-vulnerabilities) for the normalization,
grouping and coverage limits.

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
names (`src/cve_kgrag/knowledge/fight_snapshots.yaml`, the `coverage: full` entry), and
set its path:

```bash
curl -fsSLo /srv/cve-kgrag/fight.yaml \
  https://raw.githubusercontent.com/mitre/FiGHT/097cd5f73811dc34916ef84d5acc3fe7aba70450/fight.yaml
export CVE_KGRAG_FIGHT_SNAPSHOT_PATH=/srv/cve-kgrag/fight.yaml
```

At load the server computes SHA-256 and checks the reviewed catalog before parsing.
Optionally set `CVE_KGRAG_FIGHT_SNAPSHOT_SHA256` to an expected digest; a mismatch
refuses serving. The computed digest identifies the snapshot in capabilities, evidence
sets, evaluation reports and replay. Computing it never bypasses the catalog.

A configured snapshot is served or the command refuses to start, exit 2, with
`cve-kgrag <command> cannot start: FiGHT snapshot unavailable: <reason>`:
`fight_snapshot_missing`, `fight_snapshot_not_regular_file`, `fight_snapshot_unreadable`,
`fight_snapshot_too_large` (over 4 MiB), `fight_snapshot_hash_mismatch`,
`fight_snapshot_not_catalogued` or `fight_snapshot_invalid`. It never falls back to the
excerpt. Only a hash the reviewed catalog lists is ever parsed: serving another FiGHT
file is a reviewed change to the catalog. With the full snapshot a topic, or an
investigation's direct FiGHT search, can match more
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

## Weakness association mapping

The derived MITRE mapping is independent of the corpus store and FiGHT snapshot.
Use local official CWE XML, CAPEC XML and Enterprise ATT&CK STIX JSON. Pin the
release versions and input SHA-256 values in the operator's download inventory;
verify that inventory before building. The builder uses only standard-library XML
and JSON parsers, reads the inputs without modifying them, and contacts no service.

```sh
cve-kgrag mitre build --cwe /data/cwec_v5.0.xml --capec /data/capec_latest.xml \
  --attack /data/enterprise-attack.json --out /data/weakness-mapping.json
export CVE_KGRAG_MITRE_SNAPSHOT_PATH=/data/weakness-mapping.json
cve-kgrag capabilities
cve-kgrag lookup CVE-2026-12345
```

The output file must not exist: the builder refuses overwrites, including an input
path. Build each replacement at a fresh path. The command prints the file size,
SHA-256 and counts of linked CWEs and CAPECs, direct and inherited mappings,
deprecated CAPEC entries, and deprecated/revoked ATT&CK objects skipped. ATT&CK
skip counts include all STIX object types; flags are counted independently.
Mapping counts count source CAPEC/technique/parent-chain combinations, not CVEs.

The path must be absolute. Every serving command computes SHA-256 before parsing and
records it as the mapping's identity. Optionally set `CVE_KGRAG_MITRE_SNAPSHOT_SHA256`
to a lower-case expected digest (for example the one printed by the build). A supplied
expected value is compared strictly; a mismatch refuses serving. A digest without a
path is a settings error.

MITRE has no reviewed snapshot catalog. Without an expected digest,
`capabilities.weakness_associations.integrity` says “File identity recorded; no expected
SHA-256 supplied.” This does not verify that the file is unchanged. With an expected
digest it says “Compared with expected SHA-256.” The manifest-pinned packaged excerpt
also reports that comparison. Capabilities include coverage, `snapshot_sha256`, source
versions and input hashes, and build counts.

An unreadable, non-regular, oversized (over 32 MiB), invalid or mismatched file refuses
serving with an explicit `mitre_snapshot_*` reason; there is no excerpt fallback.
Restart API and MCP services after replacing the file or changing its settings. An
unset path serves the manifest-pinned packaged excerpt.

To reproduce the packaged excerpt, run the same build with `--cwe-id CWE-20
--cwe-id CWE-79 --cwe-id CWE-787 --cwe-id CWE-284 --cwe-id CWE-269 --cwe-id CWE-78
--cwe-id CWE-120`, using the full inputs pinned in the excerpt's `sources`. These
options select CWEs; CAPEC inheritance is resolved against the full CAPEC input.
The excerpt's skip counts describe those full inputs, while its mapping counts
describe the selected entries. Its notice is in `src/cve_kgrag/fixtures/mitre/NOTICE.md`.

Single-CVE `lookup` serves full `weakness_associations`. Every CVE path retains the
NVD record's evidence IDs and each catalogue hop's version and input digest.
Inheritance retains each explicit CAPEC `ChildOf` hop; deprecated CAPECs cannot
bridge it. Deprecated or revoked ATT&CK objects cannot
supply techniques. When no usable direct or inherited ATT&CK mapping exists in the
loaded snapshot, the path ends at CAPEC with `terminal_reason: "no_attack_mapping"`,
null `technique` and `technique_source`, and both source-labelled CVE → CWE → CAPEC
hops. These terminal reasons are not repeated in `missing_links`; unavailable
techniques or parents and missing CWE → CAPEC links remain reported there.
CWE-787 in CWE 5.0 has no related attack pattern, so no path is produced. This is
not filled from CAPEC's reverse CWE references or a parent CWE. A missing entry in
the packaged excerpt is reported as absent from that snapshot, not absent from the
full catalogue. NVD's noinfo/Other placeholders become an empty specific-CWE list
in record normalization and are reported as no specific CWE.

The 20-path cap applies across all CWEs on one CVE and includes full paths and paths
ending at CAPEC, with the exact omitted count. Direct mappings precede inherited
mappings, then paths ending at CAPEC, followed by lexicographic IDs and parent
chains. This deterministic order is not an importance ranking. Text investigations
point to `cve-kgrag lookup <CVE-ID>` for the full paths, sources and omitted counts.
Lookup JSON preserves the bounded paths and all missing links. The
derived-association note states: “This association is derived from official
catalogues. It is not evidence that the CVE was used with that technique. It is
not an attack path. No ATT&CK mapping describes only the loaded catalogue snapshot;
it does not mean the weakness has no attack technique or no way to be exploited.”

Under contract `2.0.0-dev.43`, search, topic and investigation candidates, including
excluded candidates in protocol-only responses, omit associations entirely. Only
single-CVE lookup attaches them, so they consume no investigation context bytes and
cannot change candidate admission. They do not enter retrieval, ranking, planner
inputs, evidence needs or FiGHT `protocol_context`. Every served association is
validated against the snapshot; a forged path or changed snapshot digest fails
validation.
