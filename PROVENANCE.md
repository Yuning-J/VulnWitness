# Provenance

This repository was split from https://github.com/Yuning-J/CVE-KGRAG at commit
`53d75e312a871184aba2e3a95ed8b4b5e46e0127` (the rebuild branch, based
on `772ea055fc9171dd8140e6fd65319626f04b7e5f`). That commit's code is identical to the
reviewed commit `8d0c47015cc19eff5ea05aa97bcb2e21f7761fe6`; the two commits after it
change documentation only.

History was not carried. This repository's first commit imports the files below and
already adapts them to this repository (ADR 0006). The original commits are archived by
the owner and are not published, in CVE-KGRAG or here; they are listed below by hash and
subject so that hashes cited in the docs can be traced.

## Carried

| Path | Git object at the split commit |
|---|---|
| `src/cve_kgrag/` (package, packaged knowledge in `knowledge/`, fixtures in `fixtures/`) | `17cea871f52f452718299cb0b0b2764fac0c1970` |
| `schemas/v2/` | `5be4f2085587d267f0dca05f3a03484931ffe015` |
| `eval/gold/` | `51a8d73393640773ea7eb74bac5959847ccae3c1` |
| `tests/unit/` | `3d146c8eef1d91b108e83d93e3535e271c8f09e0` |
| `tests/contract/` | `2edee13a6de3d73bf62dc852f8504eb62bc8984e` |
| `tests/integration/` | `aa79dbeb5864e0f8abcc8b42fd3fa8e6e8afafb6` |
| `tests/support/` | `5f691a9b1fba2483e8cb06a802a609034991ed6c` |
| `tests/live/` | `305d6affdbf4847e30c4236aed898c70a3a71ba6` |
| `tests/conftest.py` | `9ad8c0cbced8d5ef5048f9cc708a1739807aba43` |
| `docs/rebuild/adr/` (ADR 0001-0005) | `c1e6f151dc2fa17fd14d5eb706abbc1ec351c651` |
| `docs/rebuild/PLAN.md` | `1355a9f8665ef5344dab19a290458a92314521a6` |
| `docs/rebuild/m1-contracts.md` … `m6-api-cli-and-migration.md` | `902e105`, `5faabe9`, `37de9d4`, `7557ff6`, `b3061c9`, `dcaf4ca` |
| `LICENSE`, `pyproject.toml`, `uv.lock`, `THIRD_PARTY_DATA.md`, `.gitignore` | `7bbb71c`, `bf780d9`, `0de0044`, `4be1c5e`, `846a321` |

The first commit adapts the carried files as ADR 0006 records:

- The legacy RAG wrapper (`src/cve_kgrag/adapters/legacy/`), its unit test and
  `tests/support/legacy_rag.py` are not carried. Three `SearchService` tests run through
  the remaining semantic adapter with test doubles moved to `tests/support/vector_store.py`.
- The legacy fine-tuned model's registry entry and `LocalStoragePolicy.COMMITTED_ARTIFACT`
  are not carried.
- The semantic store directory is a required setting.
- The synthetic fixture's entry in `src/cve_kgrag/knowledge/sources.yaml` points at this
  repository.
- The dev group drops FastAPI and httpx2, the lock is regenerated, and the docs, ADR 0001,
  `.gitignore`, `THIRD_PARTY_DATA.md` and the licence year are updated. ADR 0006,
  `README.md` and this file are new.

## Left in CVE-KGRAG

The legacy RAG pipeline, the FastAPI `/api/v1` service, the Gradio UI, Neo4j and graph
construction, collectors, processors, mapper and training code, `data/`, `doc/`,
`scripts/`, `config.py`, `docker-compose.yml`, `requirements.txt`, the legacy fine-tuned
model (`models/fine_tuned_cve_production/`). Security fixes for that code are made there.

Three artefacts of the rebuild describe the legacy code and live with it in CVE-KGRAG's
`main` (merge commit `b64eef3`): the M0 baseline audit of the legacy repository
(`docs/rebuild/baseline.md`, which ADR 0001 cites), the legacy migration map
(`docs/rebuild/migration-map.md`) and the `/api/v1` characterization tests
(`tests/characterization/`). CVE-KGRAG holds edited versions of them, written for that
repository; the versions on the rebuild branch are in the archived history.

## Original commits

The code was developed in these 37 commits on CVE-KGRAG, 2026-10-13 to 2026-10-21.

| Commit | Date | Subject |
|---|---|---|
| `fae497e` | 2026-10-13 | test: M0 baseline, characterization tests and packaging ADR |
| `ab6a49a` | 2026-10-13 | feat: M1 canonical core, synthetic fixture and offline search |
| `035b321` | 2026-10-13 | feat: M2 typed retrieval and NVD normalization |
| `15ed474` | 2026-10-14 | fix: M2 review findings in filters, evidence scope, adapters and NVD parsing |
| `d33d25d` | 2026-10-14 | fix: M2 third review — legacy filtered search, request contract, NVD negate |
| `6f3fedd` | 2026-10-14 | fix: run the semantic channel only for queries with searchable terms |
| `1d154f5` | 2026-10-14 | feat: M3 reviewed topics, pinned FiGHT threat context and scoped topic context |
| `8347a04` | 2026-10-15 | fix: M3 review — FiGHT snapshot identity, contextual-alias exclusions, empty snapshots |
| `81705d3` | 2026-10-15 | fix: M3 review — bind FiGHT coverage to a reviewed snapshot catalog and the deployment pin |
| `a385c67` | 2026-10-15 | docs: record the 5G-AKA card scope and its CCS 2018 calibration reference |
| `dca9921` | 2026-10-15 | feat: M4 bounded investigation with deterministic policy and gated model planner |
| `424f8a2` | 2026-10-15 | fix: M4 review — bound anchor provenance, per-request caps, hard wall time, trajectory cross-checks |
| `fd65b3b` | 2026-10-16 | fix: M4 second review — planner identity at construction, decision-path audit, source capabilities |
| `f6aeb41` | 2026-10-16 | fix: M4 third review — record the typed model reply, bind replay to tool responses |
| `724a65a` | 2026-10-16 | fix: M4 fourth review — named CVE IDs, replay through the controller, planner identity, schema parity |
| `29dc915` | 2026-10-16 | fix: M4 fifth review — malformed CVE-ID tokens never name another ID; calendar-exact time patterns |
| `2350ca4` | 2026-10-17 | fix: M4 sixth review — near-ID spellings and invisible characters inside an ID fail closed |
| `23b29db` | 2026-10-17 | docs: mark M4 done; add the search-tool boundary to M5 acceptance |
| `349ed24` | 2026-10-17 | feat: low-signal query terms cve/cves leave every search text (M5 compatibility change) |
| `734be25` | 2026-10-18 | fix: a disguised low-signal word leaves the search text whole |
| `6e10e0a` | 2026-10-18 | feat: M5 batch 1 — affectedness contracts, Trustify port and disabled adapter, pinned trustify-mcp surface |
| `54a1e0e` | 2026-10-18 | feat: M5 batch 2 — evidence-set verification and the SDK-free knowledge toolbox |
| `4d246e2` | 2026-10-20 | feat: M5 batch 3 — read-only MCP server over stdio, mcp extra, M5 docs |
| `6c36132` | 2026-10-20 | fix: M5 whole-milestone review — request text, toolbox wiring, docs truth |
| `1fc23da` | 2026-10-20 | fix: M5 acceptance review — get_evidence anchor rules, server-owned affectedness text, live-call cap |
| `24f17eb` | 2026-10-20 | fix: no adapter text crosses the MCP boundary — typed backend failures, vouched match explanations (dev.16) |
| `746487c` | 2026-10-20 | docs: mark M5 done; record the model planner adapter follow-up |
| `8bf5c99` | 2026-10-21 | feat: M6 WP1 — typed settings boundary, secret handling, model planner discovery (dev.17) |
| `104c1e0` | 2026-10-21 | fix: M6 WP1 review — no adapter text in replies, guarded enumeration, server-built planner identity (dev.18) |
| `b221540` | 2026-10-21 | fix: M6 WP1 re-review — distinct endpoints never share a fingerprint, no replay-only reply reason |
| `6f22cee` | 2026-10-21 | docs: mark M6 WP1 done; state the planner request target exactly in ADR 0004 |
| `115af72` | 2026-10-21 | feat: OpenAI-compatible model planner adapter (DeepSeek) with opt-in live tests (dev.19) |
| `7ba3101` | 2026-10-21 | feat: M6 WP2 — semantic settings, unavailable semantic capability, CLI wiring (dev.20) |
| `fe082d8` | 2026-10-21 | fix: enforce the planner's share of the run; keep the semantic store out of mcp and verify |
| `8d0c470` | 2026-10-21 | fix: a planner reply landing after its share of the run is not read |
| `cf1f893` | 2026-10-21 | docs: mark the model planner adapter and M6 WP2 done |
| `53d75e3` | 2026-10-21 | docs: record the model planner live test run against DeepSeek |

## Names

The Python package `cve_kgrag`, the distribution and command `cve-kgrag`, the entry-point
group `cve_kgrag.adapters`, the MCP server name `cve-kgrag`, the `CVE_KGRAG_*` settings
and the fixture URI `urn:cve-kgrag:fixture:...` are unchanged from CVE-KGRAG. Evidence
IDs depend on the fixture URI, and recorded planner identities depend on the adapter's
module path.

## Licences

- Code: MIT, Copyright (c) 2025-2026 Yuning Jiang (`LICENSE`), the same licence and
  holder as CVE-KGRAG.
- MITRE FiGHT excerpt (`src/cve_kgrag/fixtures/fight/`): six techniques and five tactics
  cut byte for byte from `fight.yaml` at upstream commit
  `097cd5f73811dc34916ef84d5acc3fe7aba70450`, governed by the FiGHT Terms of Use
  (https://fight.mitre.org/resources/terms/), and for its ATT&CK-derived tactics and
  techniques also by the ATT&CK Terms of Use
  (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). `NOTICE.md`
  reproduces MITRE's notices verbatim, and the manifest pins its hash and the excerpt's.
  A commercial public release needs MITRE's or counsel's confirmation (see
  `THIRD_PARTY_DATA.md`).
- trustify-mcp tool list (`tests/contract/data/trustify_mcp_ac8955f/`): Apache-2.0,
  unmodified, at commit `ac8955f768a5bfef6f1c9a5c1d02ec5b5cf9bf5e`, with its licence
  beside it. It is test data only and not shipped in the wheel.
- Synthetic CVE fixture (`src/cve_kgrag/fixtures/synthetic/`): authored test data, MIT.
- 3GPP TS 33.501: clause citations only; terms not verified.
- No NVD, CVE Program, CISA KEV, CWE or CAPEC data is committed. Terms for every source
  are listed in `THIRD_PARTY_DATA.md`, and machine-readably in
  `src/cve_kgrag/knowledge/sources.yaml`.

## No compatibility guarantee

This repository's contracts are pre-release (`2.0.0-dev.20` at the split) and may change
between versions without a deprecation window. It does not provide, emulate or promise
compatibility with CVE-KGRAG's `/api/v1` API, its Gradio UI, its legacy Python modules,
its data files or its model artifacts. An evidence set recorded with CVE-KGRAG at the
split commit verifies here only while the contract version, the packaged fixture and the
planner identity are unchanged.
