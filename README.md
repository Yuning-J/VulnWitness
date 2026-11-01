# telecom-cve-kgrag

A read-only evidence layer for CVEs and telecom threat context, with cited sources and
bounded investigations over synthetic fixtures or operator-imported NVD/KEV data.
Catalogue associations are not attack paths or evidence of exploitation. Product
matches and NVD version notes leave affectedness `unknown`.

## Install

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).
From a checkout (`uv` can install Python if needed):

```sh
uv sync --locked
source .venv/bin/activate
```

## Quick start

With `CVE_KGRAG_STORE_ROOT` unset, these use the packaged synthetic fixture:

```sh
cve-kgrag demo
cve-kgrag lookup CVE-9999-0001
cve-kgrag investigate 5G-AKA --scope mixed --format text
```

`investigate` exits 1 when needs remain unmet, including this pending-card example.

## Real data

Create a store root outside the repository, then fetch, import and activate:

```sh
mkdir -p ~/data/cve-kgrag/stores
export CVE_KGRAG_STORE_ROOT="$HOME/data/cve-kgrag/stores"
.venv/bin/python scripts/operator/refresh_store.py --feeds-dir ~/data/cve-kgrag/feeds/2026-10-31 --store nvd-2026-10-31 --activate
export CVE_KGRAG_HTTP_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
cve-kgrag api
```

The bundled demo requires no corpus download. For the full NVD corpus, we recommend a
machine with 16 GB RAM or more; the minimum has not been established. Initial setup
involves a substantial download and several GB of disk space.
Keep the server running for repeated queries. Restart after activation or rollback.
The [runbook](docs/runbook.md) covers local-feed reuse, sizing and recovery.

## Entry points

- CLI lookup: `cve-kgrag lookup CVE-9999-0001` — exact record and weakness paths.
- CLI search: `cve-kgrag search "authentication bypass"` — ranked word matches.
- CLI product: `cve-kgrag product --vendor democorp --version 2.0 --format text` — counted inventory pages.
- CLI investigate: `cve-kgrag investigate 5G-AKA --scope mixed --format text` — bounded evidence set.
- CLI capabilities: `cve-kgrag capabilities` — sources, coverage and available tools.
- REST: `curl -H "Authorization: Bearer $CVE_KGRAG_HTTP_TOKEN" http://127.0.0.1:8766/api/v2/capabilities`.
- MCP: `cve-kgrag mcp` (stdio), or `cve-kgrag mcp --http` (authenticated `/mcp` on port 8765).

## Limits

- Word matches and pending-review topic cards cannot establish sufficiency; normal
  runs with such matches end `needs_unmet`. Read matched terms and warnings.
- The GTP card covers the family; a GTP-U query can include GTP-C records.
- NVD may lack product/version data. A missing match or `no_hit` never establishes safety.
- No verified affectedness source is available. Weakness paths are derived catalogue associations.
- REST/MCP investigations are deterministic. Model planning is opt-in through the CLI;
  imported stores have no bound semantic collection.
- Results and context are bounded; an answer makes no completeness guarantee.

[Runbook](docs/runbook.md) · [Architecture](docs/architecture.md) ·
[Evaluation](docs/evaluation.md) · [Third-party data](THIRD_PARTY_DATA.md)

Pre-release contracts: [schema manifest](schemas/v2/manifest.json).
Code: [MIT](LICENSE); third-party data: [THIRD_PARTY_DATA.md](THIRD_PARTY_DATA.md).
