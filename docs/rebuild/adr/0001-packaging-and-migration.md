# ADR 0001 — Packaging, optional adapters, and strangler migration

Status: accepted (M0). Applies to the whole v2 rebuild. §6 is superseded and the
Context, §1, §2, §5 and Consequences are amended by ADR 0006 (repository split); §2's
`dev`, `mcp`, `api` and `neo4j` rows are amended by ADR 0007 (HTTP surfaces).

## Context

The legacy code in CVE-KGRAG installs from one `requirements.txt` that pulls
Torch, transformers, Chroma, Neo4j, Gradio and the training stack, and its modules
do I/O and directory creation at import or construction time (findings 20 and 22
of the M0 baseline audit of the legacy repository, CVE-KGRAG's
`docs/rebuild/baseline.md`). It is imported as an implicit `src.*` namespace from the repository root with
`sys.path` edits. Nothing in it is packaged, and the audit found no verifiable
consumer of `/api/v1` outside that repository.

The v2 core must install and run offline with no heavy dependency, while
optional adapters (semantic, Neo4j, Trustify, API, MCP) remain available.

## Decisions

### 1. One distribution, `src/` layout

- `pyproject.toml` defines the `cve-kgrag` distribution; the import package is
  `src/cve_kgrag/`, the only directory packaged
  (`[tool.hatch.build.targets.wheel] packages = ["src/cve_kgrag"]`).
- Build backend: `hatchling`. Environment and lock: `uv` with a committed
  `uv.lock`. Minimum Python: 3.11.

### 2. Dependency profiles

| Profile | Mechanism | Contents | Introduced |
|---|---|---|---|
| core | `[project].dependencies` | `pydantic`; `PyYAML` from M3 (a `SafeLoader` subclass only, for reviewed topic cards and FiGHT snapshots, which protocol-context retrieval needs in a core-only install) | M1 / M3 |
| dev | `[dependency-groups].dev` | pytest, ruff, mypy, types-PyYAML, jsonschema (schema/model agreement tests), and the `mcp` extra from M5 and the `migration` extra from M6 WP9, so the default lane runs the MCP server's and the importer's tests; the HTTP test client (`httpx2`) the HTTP tests import | M0 |
| semantic | extra | Chroma / sentence-transformers adapter | M2 |
| trustify | extra | MCP client for the official Trustify MCP server | introduced with the verified Trustify adapter (ADR 0003); not in M5 |
| mcp | extra | official MCP SDK for the CVE-KGRAG server; Starlette and uvicorn, declared explicitly, for MCP over Streamable HTTP (ADR 0007) | M5; HTTP in M6 WP6 |
| api | extra | anyio, Starlette and uvicorn for the v2 REST API, without the MCP SDK (ADR 0007) | M6 WP7 |
| migration | extra | ijson, the legacy-data importer's streaming JSON parser (ADR 0008) | M6 WP9 |
| neo4j | — | none: no v2 Neo4j adapter exists (ADR 0007) | — |

An extra is added in the milestone that adds the adapter which needs it; no
empty extras are declared ahead of their code. The core must never depend on
Torch, CUDA wheels, transformers, Gradio, Neo4j or Chroma; a test asserts that
importing every `cve_kgrag` module leaves those packages out of `sys.modules`.

### 3. Optional adapters load only through entry points

The no-inline-imports rule and optional extras conflict: an adapter whose
dependency is not installed cannot be imported at module top level of the core
or the composition root. The single sanctioned mechanism:

- Each optional adapter lives in its own module under
  `cve_kgrag/adapters/<name>/` with ordinary top-level imports of its
  dependency.
- The distribution registers it under the entry-point group
  `cve_kgrag.adapters`, e.g.
  `semantic = "cve_kgrag.adapters.semantic.chroma_retriever:build_semantic_retriever"`.
  The adapter's dependencies are declared in the matching extra.
- The composition root calls `importlib.metadata.entry_points(group="cve_kgrag.adapters")`
  for the adapters enabled in typed settings, loads each enabled entry point, and
  passes the built adapter into the application services. A load failure
  (missing extra) becomes a typed "unavailable" capability, never a silent
  fallback to a different source.
- An optional interface (the MCP server runner) registers in the same group and
  loads through the same discovery module (ADR 0003 §11).
- That discovery call is the only dynamic-loading point in the codebase. No other
  function-level, conditional or `try: import` imports are allowed. Domain,
  ports and application modules never reference an adapter module.

Because entry points are declared for the whole distribution, a registered
entry point can exist while its extra is not installed; that is precisely the
case the typed "unavailable" capability covers. The discovery code itself lands
with the first optional adapter (M2, semantic); M1 has none.

### 4. Inward dependency direction

`interfaces → application → domain/ports ← adapters`. Domain and application
modules import only the standard library, `pydantic`, and other `cve_kgrag`
domain/ports modules. This is enforced by an import-boundary test as layers
appear.

### 5. Legacy behaviour is reached through its outputs

- New behavior is implemented in `cve_kgrag`. Legacy behaviour is reached through
  the data it produces (the read-only importer, M6 WP9, ADR 0008; the semantic
  channel reading the Chroma store format, ADR 0006), not through wrappers around
  legacy modules. Legacy parsing knowledge (NVD 1.1/2.0 field paths, CPE/KEV/CSAF
  handling) is reused when the canonical importer is written, with the defects
  recorded in the baseline fixed in the new code.
- The legacy modules stay in CVE-KGRAG, with their migration map and
  characterization tests (ADR 0006, `PROVENANCE.md`). No `_deprecated` markers, aliases or re-exports are
  added.

### 6. `/api/v1` is internal

Superseded by ADR 0006 §3: `/api/v1` stays in CVE-KGRAG, and this repository
provides no v1 facade, deprecation window or compatibility promise.

### 7. Contracts and schema snapshots

External request/response types are Pydantic v2 models in `cve_kgrag`; their
JSON Schemas are generated and committed under `schemas/v2/` with a manifest of
SHA-256 hashes. A contract test fails when the generated schema differs from the
committed snapshot. v2 is pre-release until M7: snapshots change with each
milestone, and every change is reviewed through the snapshot diff.

### 8. Runtime knowledge ships inside the package

The brief sketches `knowledge/topics/` at the repository root. Reviewed topic
cards (`cve_kgrag/knowledge/topics/*.yaml`), the source registry
(`cve_kgrag/knowledge/sources.yaml`) and the pinned fixtures
(`cve_kgrag/fixtures/`) live inside the package instead, so an installed wheel
carries everything the core reads at runtime and nothing depends on a source
checkout. Evaluation data that only tests read stays at the root (`eval/gold/`).

## Consequences

- A core-only environment (`pip install .`) runs the deterministic service and
  its offline tests; optional capabilities report themselves unavailable.
- Adding an optional adapter costs an entry point, an extra, and a capability
  status, which keeps every heavy dependency visible in `pyproject.toml`.
