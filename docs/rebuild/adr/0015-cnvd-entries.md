# ADR 0015 — CNVD entries beside NVD records

Status: accepted (2026-11-08). Applies to the importer (ADR 0008), the corpus store and
its reader (ADR 0009), CVE lookup on every surface, session reports (ADR 0012) and the
local UI (ADR 0014).

## Context

Vulnerability analysis and prioritisation (VAP) work watches US and Chinese sources side
by side: NVD and the two Chinese national databases, CNVD (run by CNCERT) and CNNVD (run
by CNITSEC). VulnWitness serves NVD records with CISA KEV joined by CVE ID. The need is
one CVE with each source's statement shown side by side, each with its own provenance,
and a disagreement flagged by a stated rule.

Access, checked on 2026-11-08:

- CNNVD's OpenAPI needs an account with enterprise real-name verification, and its XML
  downloads need an account. No public mirror with known terms was found.
- CNVD's downloads need an account. CIRCL republishes CNVD, without a login, in two forms:
  - the Hugging Face dataset `CIRCL/Vulnerability-CNVD`: five fields, licensed CC BY 4.0
    as CIRCL declares;
  - Vulnerability-Lookup's `cnvd.ndjson` dump and its API: CNVD's own fields (products,
    submission and publication dates, reference link, solution), with no stated data
    licence.
- Neither CIRCL source says how its terms relate to CNVD's own, which were not found.

The pinned dataset revision `986160c9b1c910049f64a166ab4056de191f6de7` (2026-08-28),
counted over both of its files on 2026-11-08:

| Fact | Count |
|---|---|
| Rows (`train` 116,871, `test` 12,986) | 129,857 |
| Rows whose `cve_id` is exactly one well-formed CVE ID | 105,641 (81.4%) |
| Rows with an empty `cve_id` | 24,184 |
| Rows with other `cve_id` text (IDs on separate lines, an en dash, bare digits, Chinese words) | 32 |
| CVEs named by more than one CNVD ID | 119 |
| Repeated `id` values | 0 |

Every `id` is `CNVD-`, a year, `-` and 4 to 6 digits; `severity` is 高, 中 or 低; no title or
description is empty; `source` is always `cnvd`. The dataset card says entries without a
description or severity were left out.

## Decisions

### 1. Scope

CNVD entries attach to CVE records by CVE ID, as KEV does. The CVE ID stays the record
key: a CNVD entry is never a record of its own. CNVD text never merges into NVD's fields;
`descriptions`, `cvss`, `cwe_ids` and `affected` stay NVD's.

### 2. The default input

- **Registry and catalog.** The source registry names it `circl-cnvd`.
  `knowledge/cnvd_snapshots.yaml` lists the reviewed revision and the SHA-256 and row
  count of both of its files, `data/train-00000-of-00001.parquet` and
  `data/test-00000-of-00001.parquet`. Changing the pin is a reviewed change to that
  catalog.
- **Both files or none.** A manifest declares each file as its own `circl-cnvd` input.
  The declared CNVD files must be exactly one catalogued revision's file set, matched by
  SHA-256: an uncatalogued file and an incomplete set each fail the run with their own
  code. The `train`/`test` split is a machine-learning partition with no meaning here.
- **Recognised by content.** A CNVD input is a Parquet file whose columns are exactly
  `id`, `title`, `description`, `severity`, `cve_id` and `source`, all strings. Reading
  it needs `pyarrow`, which joins the `migration` extra and loads through the migration
  parsers entry point, as `ijson` does.
- **All or nothing on structure**, as for KEV (ADR 0008 §6). Any of the following makes
  the input invalid, each with its own failure code:
  - a missing, extra or mistyped column, or a null value;
  - an `id` outside the pattern above, or repeated within or across the files;
  - an empty title or description;
  - a severity other than 高, 中 or 低, or a `source` other than `cnvd`;
  - a file past the CNVD bounds in `MigrationLimits`.

  The pinned revision passes every check.
- **`cve_id` is classified, never repaired.** A value that is exactly one well-formed CVE
  ID (the whole value matches the CVE ID pattern) joins. An empty value is
  `cnvd_without_cve_id`; any other value is `cnvd_unrecognised_cve_id`.

### 3. Join outcomes

The join runs after ADR 0008 §5, on the final NVD records. The migration report counts
each CNVD row under exactly one outcome:

| Case | Outcome | Stored |
|---|---|---|
| A servable NVD record | `merged` | on the record |
| No NVD candidate | `cnvd_without_nvd_record` | as a pending entry |
| The NVD winner is rejected | `cnvd_for_rejected_nvd_record` | as a pending entry |
| The NVD CVE was excluded by ADR 0008 §5 | `cnvd_for_excluded_nvd_record` | as a pending entry |
| Empty `cve_id` | `cnvd_without_cve_id` | no |
| Other `cve_id` text | `cnvd_unrecognised_cve_id` | no |

Unlike KEV rows, entries with a well-formed CVE ID and no servable NVD record are kept.
A Chinese source listing a CVE that the NVD snapshot lacks is an early warning, not
noise. The store keeps these pending entries beside the records, each with its outcome.
Nothing carries over between stores: every import rebuilds from all its inputs, so an
entry joins on the first import whose NVD input holds a servable record for its CVE.

### 4. Record and store shape

- `CveRecord.cnvd`: a tuple of `CnvdEntry`, ordered by CNVD ID; empty when no consulted
  source lists one. A `CnvdEntry` holds `cnvd_id`, `title`, `description` (Chinese
  text, untrusted like every source description), `severity` (`high`, `medium` or `low`
  for 高, 中, 低) and `evidence_id`.
- **Anchor.** Each entry has its own anchor:
  - `source_name` `circl-cnvd`, and a new `SourceType` `circl_cnvd_parquet`;
  - `authoritative_record_id`: the CNVD ID;
  - `source_uri`: the file's Hugging Face `resolve` URL at the revision;
  - `source_version`: the revision;
  - `content_sha256`: the SHA-256 of the canonical JSON of the row's six columns;
  - `locator`: `id=<CNVD ID>`;
  - scope `implementation_vulnerability`, assertion `asserted`, trust `secondary`, no
    excerpt.
- **NVD status.** `CveRecord.nvd_status` keeps NVD 2.0's `vulnStatus` verbatim. It is
  null for 1.1 entries and the synthetic fixture.
- **Store format 2.** It holds both fields and the pending entries; the reader reads
  formats 1 and 2. A format-1 store has no CNVD entries and no NVD status, and the
  knowledge capabilities say CNVD was not imported. The contract version moves to the
  next development version.

### 5. The comparison rule

The comparison is computed when an entry is served, from stored fields, and is never
stored. Each served CNVD entry carries a `source_comparison` with two parts.

**`nvd_state`**, one of:

- `analysed`: `vulnStatus` is Analyzed or Modified;
- `awaiting_analysis`: Received, Awaiting Analysis or Undergoing Analysis;
- `deferred`: Deferred;
- `status_unknown`: no status, or a value not listed here (`nvd_status` keeps it
  verbatim);
- for pending entries: `not_in_nvd_snapshot`, `rejected_by_nvd` or `excluded_by_import`.

**`severity`**: `agree`, `disagree` or `not_comparable`, under the rule
`cnvd_severity_vs_nvd_primary_cvss3`.

- 高 matches HIGH or CRITICAL, 中 matches MEDIUM, and 低 matches LOW.
- The rule compares against the record's primary-scorer CVSS v3.1 metric, or else its
  primary v3.0 metric.
- No such metric, or one without a base severity or with NONE, gives `not_comparable`.
- CVSS v2, v4 and secondary (CNA) scores are not compared.

The response names the rule, says it is VulnWitness's comparison rather than a statement
by NVD or CNVD, and shows both raw values beside it. CNVD's grading criteria were not
found, so the mapping is this project's choice.

### 6. Surfaces

- Exact CVE lookup on the CLI, REST and MCP returns `cnvd`, each entry with its
  comparison. A CVE with no NVD record but pending CNVD entries returns those entries
  with their NVD state, not a bare not-found.
- Lookup by CNVD ID resolves to its CVE's record or its pending entry. The import keeps
  no CNVD entry without a CVE ID, and the not-found answer says so.
- Search, product queries, graph expansion and investigation planning are unchanged.
  Chinese text is not indexed, since no Chinese tokenizer is used, and CNVD fields add
  no relevance score. Records they return carry their CNVD entries.
- Session reports and the local UI show NVD and CNVD side by side, with the comparison
  and the attribution.

### 7. Attribution and terms

Wherever CNVD content is shown (CLI, REST, MCP, reports, UI), it carries:

> CNVD entries from CIRCL/Vulnerability-CNVD (Hugging Face, revision 986160c), licensed
> CC BY 4.0 as declared by CIRCL (https://creativecommons.org/licenses/by/4.0/);
> normalised by VulnWitness. How this licence relates to CNVD's own terms is unverified.

The MCP server instructions add that sentence when the served store holds CNVD entries.
The source registry gains two entries:

- `circl-cnvd`, the republisher:
  - terms: the CC BY 4.0 URL;
  - `allowed_with_conditions`: credit CIRCL and the dataset, link the licence and
    indicate changes;
  - `operator_supplied`, verified on 2026-11-08;
  - versioned by the revision pinned in the catalog.
- `cnvd`, the source of record: terms `null`, redistribution `unknown`, the way the
  `cve-program` entry stands beside `nvd`.

The repository commits no CNVD data. Tests build synthetic CNVD Parquet files at test
time in a temporary directory; no binary fixture is committed.

### 8. Fetching

The operator fetch behind `refresh_store.py` downloads both files of the catalogued
revision from `https://huggingface.co/datasets/CIRCL/Vulnerability-CNVD/resolve/<revision>/<path>`.
It checks each file against the catalog's SHA-256 and declares the files in the
manifest with their URL, revision and retrieval time. CNVD is fetched by default.

### 9. Later work

- **Raw `cnvd.ndjson`** from Vulnerability-Lookup, for richer fields and comparing
  publication dates. It is a research input that must be enabled explicitly. Continuous
  sync uses the API's `since` parameter: one baseline dump, then increments merged into a
  local operator mirror that each import reads as a whole input, with no periodic full
  download. It needs its own ADR, and becomes the default only after CIRCL or CNVD
  confirm its terms in writing.
- **CNNVD** waits until data access exists. Parsing will follow the official
  《CNNVD 漏洞兼容性描述规范》. The copy in `y4ney/collect-cnnvd-vuln` (`doc/pdf`) is a
  parsing reference only: it is not committed here and grants no right to obtain or use
  CNNVD data. CNNVD will follow this ADR's pattern: entries joined by CVE ID, their own
  anchors, the join outcomes, and a comparison rule for CNNVD's four grades.
- **Chinese full-text search.**
- **Moving the telecom features into `vulnwitness-telecom`**, under its own ADR.

## Consequences

- `pyarrow` joins the `migration` extra.
- Store format 2, a contract version change and new schema snapshots.
- The default CNVD data is a snapshot from 2026-08-28. Ongoing monitoring needs the
  research input in §9.
