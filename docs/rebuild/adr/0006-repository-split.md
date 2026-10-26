# ADR 0006 — Repository split

Status: accepted (M6 WP-S), implementing the owner's split decision of 2026-10-21.
Supersedes ADR 0001 §6; amends ADR 0001 Context, §1, §2, §5 and Consequences. §5 is
amended by ADR 0009 (store activation and serving).

## Context

The v2 rebuild was developed in CVE-KGRAG on a branch beside the legacy RAG pipeline,
`/api/v1`, the Gradio UI and the Neo4j tooling. It imports nothing from the legacy `src.*` namespace, and it never changed a legacy file:
over the legacy paths, the branch adds only the characterization tests and two
`.gitignore` groups (local `.env` files and build outputs). The owner decided to develop the telecom knowledge service in its
own repository and to keep the legacy system, and its security fixes, in CVE-KGRAG.

## Decision

1. **Scope.** This repository holds the `cve_kgrag` package, its tests, `schemas/v2`,
   `eval/gold` and the rebuild docs. They were imported from CVE-KGRAG at commit
   `53d75e3` without history, and this repository's first commit already contains the
   changes this ADR makes. The original commits are archived by the owner, not
   published; `PROVENANCE.md` lists the carried paths with their git object IDs at the
   split commit and the original commits by hash and subject.
2. **Names unchanged.** The package `cve_kgrag`, the distribution and command
   `cve-kgrag`, the entry-point group `cve_kgrag.adapters`, the MCP server name and the
   `CVE_KGRAG_*` settings keep their names. The URIs `urn:cve-kgrag:fixture:` and
   `urn:cve-kgrag:test` are identifiers hashed into evidence IDs and are never renamed.
3. **v1 is out of scope.** `/api/v1`, the Gradio UI and the legacy modules stay in
   CVE-KGRAG, and so do the `/api/v1` characterization tests (its
   `tests/characterization/`). This repository provides no v1 facade, no
   deprecation headers and no compatibility promise. ADR 0001 §6 is superseded.
4. **No legacy wrapper.** `LegacyRagRetriever` had no production wiring and has no
   legacy object to wrap here, so it is not carried. Legacy data enters only through
   the read-only importer (M6 WP9, ADR 0008). The backend failure codes
   `filters_unsupported` and `no_answer` stay in the published contract, as vocabulary
   for any `semantic` adapter registered through the entry point; the contract stays
   at `2.0.0-dev.20`.
5. **Data coupling.** The semantic channel reads a Chroma collection in the format
   CVE-KGRAG's `src/generators/rag_system.py` writes (collection `cve_documents`, entry
   IDs `<CVE ID>_chunk_N`, the CVE ID in `cve_id` metadata). This repository does not
   build that store. The operator names its directory
   (`CVE_KGRAG_SEMANTIC_PERSIST_DIRECTORY`, required when the channel is enabled); there
   is no default path. The collection and model names keep their defaults, because they
   describe the store format the adapter reads. A legacy collection may also hold
   `KEV-` chunks, whose `cve_id` metadata is not a CVE ID; the channel refuses such a
   hit as malformed, so a query that reaches one reports the semantic channel as failed
   and the response as `partial` (ADR 0009 §14).
6. **Provenance subjects.** The legacy fine-tuned model is not in this repository; its
   registry entry and `LocalStoragePolicy.COMMITTED_ARTIFACT` are not carried, and its
   provenance is recorded in CVE-KGRAG's `THIRD_PARTY_DATA.md`.

## Deviations from the brief

| Brief item | In this repository |
|---|---|
| M6 exit "v1 and v2 contract tests pass" | "v2 contract tests pass" (M6 WP7). The v1 characterization tests run in CVE-KGRAG (Decision 3). |
| B1 tested v1 compatibility with deprecation header and window; B2 v1 incompatibility list; §19 v1 compatibility tests | Not provided. Optional in CVE-KGRAG. |
| B3 legacy wildcard CORS and 0.0.0.0 bind; E2 hard-coded Neo4j passwords; E3 `requirements.txt` and docker-compose review | Out of scope here: that code lives in CVE-KGRAG, which fixed them (merge commit `b64eef3`): loopback binds without wildcard CORS, no default Neo4j password, docker-compose on loopback with required credentials, and a `requirements.txt` that installs on Python 3.11 with its remaining advisories recorded. |
| E5 provenance of the legacy model | Recorded in CVE-KGRAG's `THIRD_PARTY_DATA.md`. |
| D13 `search_cves` filtered seam | Dropped with the legacy wrapper. |
| §22 no deletion of legacy modules | Met: no legacy module is deleted; they stay in CVE-KGRAG. |

## Consequences

- One Python tree, one distribution; `pythonpath = ["."]` exists only so tests import
  `tests.support`.
- The default lane needs no FastAPI.
- A change to the Chroma store format in CVE-KGRAG must be checked against the semantic
  adapter here; the adapter was written against the format at the split commit.
- An operator who enables the semantic channel without naming a directory gets a usage
  error naming `CVE_KGRAG_SEMANTIC_PERSIST_DIRECTORY`.
