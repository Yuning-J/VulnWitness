# ADR 0010: Investigation sessions

Status: accepted

Contract: `2.0.0-dev.49`

Structured claims extend this ADR because they govern the same findings artifact and
checker trust boundary; a separate decision would split that contract across documents.

## Purpose and boundary

An investigation is one existing controller run, with at most two rounds and its own
budgets and trajectory. A session chains independent calls over one served dataset.
Recording does not change an investigation, its planner, admission, or budgets.

CLI, agent integrations and an interactive analyst interface share the session directory
format. REST recording, report generation, the UI and an Agent Skill are outside this
implementation. REST recording belongs to the UI work; there is no session-writing MCP
tool.

## Facts and authored interpretation

The recorder records requests, outcomes and the response bytes it actually returns. It
never creates or edits findings, claims, selections or questions. Users, agents and a
workflow may author `findings.yaml` separately. A workflow may write deterministic kinds
only and must write them as `unconfirmed`. To confirm one, a user or agent takes authorship
of that finding. Status remains authored and never changes the check result. No triage or
report command is introduced by the claim contract. Findings cite saved calls instead of
copying model-rendered versions of responses into the record.

A response can itself contain source text or an investigation's existing model judgement.
Recording preserves that interface response verbatim; the recorder supplies no judgement.
MCP tools remain read-only over deployment knowledge. The only optional writes are to the
operator-selected session directory.

## Directory format 1

The committed schemas under `schemas/v2` describe each JSON or YAML artifact:

| Path | Schema | Contents |
| --- | --- | --- |
| `session.json` | `session_record.schema.json` | Format 1, name, creation time, optional goal/scope, dataset identity, contract version, call limit |
| `calls/NNNN.json` | `session_call.schema.json` | Sequence, interface, command/tool, normalized validated request, dataset, outcome, response filename and contract name, start/finish times |
| `responses/NNNN.json` | `session_response.schema.json` | Exact response document, with no session envelope |
| `findings.yaml` | `session_findings.schema.json` | Authored findings, selections and open questions |

Numbers start at `0001`. The session name is the directory's final name. Creation and call
timestamps come from an injected clock. Call requests include contract defaults. An MCP
request that fails validation has a null validated request; its invalid raw arguments are
not persisted. Tool failures have their exact typed failure JSON, with the code also stored
as the call outcome. Successful calls use outcome `ok`, including empty or partial answers;
this means execution succeeded, not that a claim or affectedness was confirmed.

`response_schema` chooses the command's precise response contract within the shared
response schema. The checker validates that contract, including required serialized
fields, and checks that it is the response contract for the named command. CLI affectedness
keeps its JSON list, with a normalized request containing all requested checks. Verification
records the validated input filename and the returned verification report.

Findings have an ID, author (`user`, `agent`, `workflow`), declared kind,
confirmed/unconfirmed status and citations `{call: 1, evidence_id: 'ev:...'}`. Deterministic
kinds require a typed `claim` with the same `kind`; `model_judgement` and `analyst_note`
require free-text `statement` and have no claim. Deterministic statements may be omitted
or null: parsing supplies the canonical rendering from the claim. An explicit statement
must equal that rendering exactly, otherwise the findings file is invalid. Consumers must
parse findings with this contract before presenting them. This retains human-readable
statements while preventing independently authored prose from contradicting checked fields.
Canonical sentences quote claim values as ASCII-escaped JSON; version and catalogue wording
repeats their limits. JSON Schema expresses kind and author constraints; the model enforces
canonical text equality because JSON Schema cannot compute a statement from claim values. More interpretation belongs in a separate narrative finding.

### Structured claim fields

Each claim has `kind` and the recorded integer `call`. No claim recomputes search,
version comparison, catalogue inference or controller sufficiency: it checks fields the
recorded interface actually returned. Claim calls need not have an evidence anchor;
citation resolution remains a separate layer, and empty citations grant no source support.

| Kind | Exact assertion |
| --- | --- |
| `product_field_match` | `cve_id`, `vendor`, `product`: that product page item has basis `product_field` and one matched pair containing both names |
| `description_mention` | `cve_id`, `phrase`: that product page item's basis is `description_mention` with that exact `matched_phrase` |
| `version_note` | `cve_id`, `version`, `mention`, `outcome`, `applicability`: page version, item's NVD note mention and outcome, and applicability exactly `unknown` |
| `catalogue_association` | `cve_id`, `cwe_id`, `capec_id`, optional `technique_id`, required nullable `terminal_reason`, optional `inherited_from` and `inherited_from_cwe`, and `hops`: one lookup association path matches every field, including hop sources, versions and identities |
| `need_status` | `need_kind`, nullable `subject`, `outcome`: the investigation's coverage need with that exact kind and subject has that outcome |
| `record_fact` | `cve_id` and typed `fact`: a returned record's publication timestamp, complete ordered CWE list, complete KEV entry, or selected CVSS metric severity |

A record fact's nested `fact.field` discriminates `published` (timestamp `value`), `cwe_ids`
(nonempty list `value`), `kev` (KEV object `value`), and `cvss.base_severity` (severity `value`
plus metric `version`, `scorer` and nullable `scorer_type`). Records can come from product,
search/lookup or included investigation candidates. CVSS selects exactly one metric;
missing, null or ambiguous selected metrics are unverifiable. Null publication/KEV and
empty CWEs mean absent source fields, never a verified negative. Values compare as their
canonical JSON serialization, including exact strings and ordered lists. Product identities
and phrases must use returned spellings; the checker performs no additional normalization.
Catalogue hops and inheritance prevent an indirect path from verifying a direct-link claim.
An empty but present association-path list contradicts a claimed path. A missing subject,
response family or required field is unverifiable. A present field with a different value is
contradicted, identifying the first differing field and its expected and recorded values.

`selections.cve_ids` holds selected CVE IDs. Each `selections.product_queries` entry holds
vendor, product, version, the page-call sequence numbers, next cursor and a completion
flag. These selections are authored bookkeeping, not server conclusions. `open_questions`
is a list of strings. The checker requires a valid `findings.yaml`; the operator can supply
empty findings, selections and questions.

## Dataset identity and citations

Every call repeats the session's composite dataset identity: served corpus kind and search
version, store name, manifest digest, corpus content digest, and FiGHT/MITRE snapshot
digests when served. These identities come from the verified corpus and loaded snapshots,
not from a fresh read of `ACTIVE` after loading. The synthetic fixture uses a null store
name, its existing canonical manifest identity, and the pinned records-file digest for
content. Corpus stores use their actual directory name and already verified digests.
There are no additional response, session or findings integrity hashes.

A citation resolves only when its particular call exists, succeeded, has the same composite
dataset identity as `session.json`, and contains the complete cited evidence anchor in its
saved response. A bare reference to an evidence ID is insufficient. Anchors are indexed by
call, never merged across calls by bare ID. Changing any part of the served identity on a
later invocation refuses the call with `session_dataset_mismatch`, CLI exit 2, and appends
nothing. Even equal corpus bytes in a different physical store belong to different sessions.

Recorded data commands load the complete data plane, including for commands that otherwise
need only the corpus or topic registry. This supplies one stable composite identity for
calls chained across commands. It also means a configured snapshot failure prevents a
recorded command from running. Ordinary unrecorded command loading stays as documented in
ADR 0009. `session check` loads no corpus or deployment snapshots.

## Entry points and limits

`--session DIR` is available on exactly these CLI data commands:

- `lookup`, `search`, `product`, `investigate`, `topic`;
- `evidence`, `affectedness`, `capabilities`, `resolve`, `verify`.

`verify` is included because it returns a verdict against served knowledge. `demo`, `eval`,
`schema`, `store`, `migrate` and `mitre build` are administrative, fixture demonstrations or
artifact-building commands and have no session option. `session check` itself does not
append calls. `api` has no recording option in this implementation.

Recorded CLI calls require JSON output; `--session --format text` is a usage error (exit 2)
on lookup, search, product and investigate. Saved response bytes include the CLI's
terminating newline. Text summaries are available on unrecorded commands.

Product `--all` and `--output FILE --export jsonl|csv` use the same traversal as ordinary
product calls. Each page is its own call with its validated cursor-bearing request and
individual JSON response, rather than the combined stdout array or exported rows.
Exports are not session artifacts. The session call limit is checked before each page:
a refusal mid-traversal exits 2 and leaves completed page calls, with no partial call.
Neither limit failures nor recording failures publish the combined array or export;
`--max-pages` also preserves completed page calls. Output options are validated before
loading the corpus or creating a session.

`vulnwitness mcp --session DIR` and `vulnwitness mcp --http --session DIR` record all dispatched
tool calls, including unknown tools, invalid arguments, loading refusals and tool failures.
Recorded MCP failures use typed tool errors with both JSON text and structured content;
unknown recorded tools produce `invalid_arguments`. Invalid JSON-RPC frames that cannot be
dispatched as tool calls remain protocol errors. Stdio recording loads the data plane
before protocol startup to establish identity; the toolbox is published after negotiation.
No MCP operation writes user-authored findings. The shared failure contract includes
`session_call_limit`, `session_dataset_mismatch` and `session_recording_failed`. The REST
status registry remains exhaustive (429, 409 and 500 respectively), but no REST recording
entry point emits them in this implementation.

The first admitted call creates metadata and private call/response directories. The default
session limit is 100; `--session-call-limit 1..100` sets a lower limit at creation. The
metadata limit is immutable; a later explicit limit must equal it. `--session-goal` and
`--session-scope` set optional creation metadata and likewise cannot change it. These flags
require `--session`. Once the limit is reached, `session_call_limit` refuses a new call
before its operation executes, CLI exit 2 or an MCP tool failure, and appends nothing.
Recorded failures count toward the limit. Investigation budgets remain independent.

## Writes and failures

The recorder is a separately injected unit behind a recording port; domain file models
have no filesystem effects.
An exclusive nonblocking per-directory file lock serializes appends across processes and
threads. A busy lock or any recording failure produces `session_recording_failed`; the
CLI exits 2 or MCP returns that typed failure. No successful answer is released unrecorded.
Path and invocation validation can refuse before there is a recordable call.

Created directories are 0700 and files 0600, including temporary files and the lock. Writes
use a new temporary file, sync, atomic rename and directory sync. The response is committed
before its call metadata. The two files are not a multi-file transaction: an interrupted
commit can leave an orphan response, which the checker reports and subsequent appends
refuse. A sync failure can leave a complete pair on disk but still withholds the answer.
The recorder never repairs, deletes or silently skips existing calls.

Recording refuses a symlink at the session directory, linked call/response directories,
linked or nonregular input files, and any session path inside the configured store root. Existing
regular-file and store-root identity helpers enforce those boundaries.

## Checking and trust

`vulnwitness session check DIR` emits a typed JSON check report;
`--format text` emits a readable report. Exit 0 requires record consistency, citation
resolution and verification of every deterministic claim; exit 1 means a violation,
contradiction or unverifiable claim. There is no aggregate `passed` field.

Consistency checks cover format and contract parsing, contiguous sequences, unique call
numbers, response pairing, response contracts, normalized request contracts, failure
outcomes, call limits, composite dataset equality and authored findings validation.
Resolution checks apply the per-call citation rules above. Missing or invalid findings
are violations, and findings IDs must be unique.

The report separates `record` (`consistent`, `calls_checked`, located `violations`),
`citations` (`resolved`, `citations_checked`, located `violations`), and `claims` (`verified`,
per-finding `checks`). Each claim check identifies `finding_id`, `call`, `status`
(`verified`, `contradicted`, `unverifiable`), nullable `field`, `expected`, `recorded`, and
`message`. Failed, missing, invalid or dataset-mismatched calls cannot verify claims.
The checker retains validated responses in memory and reads no deployment data.
`not_checked` contains `count` and `finding_ids` for model and analyst findings, regardless
of their authored status. Empty layers have zero checks and no violations; a malformed
findings file is a record violation and supplies no claim or narrative checks.

Both JSON and text repeat `support_limitation`: free narrative is not checked and field
agreement does not establish source support or real-world truth. Selection pagination,
selection reasoning and confirmed/unconfirmed statuses remain authored declarations.

Everything read back from a session directory is untrusted input, including server-looking
JSON, filenames, source excerpts, statements and questions. Reads are bounded, only regular
files are accepted, duplicate JSON keys are refused, and YAML uses the repository's safe
strict declaration loader, with no aliases, merge keys or duplicate keys. The checker does
not execute session text, contact sources, or treat a passed check as proof of origin. An
operator able to rewrite the whole record can forge consistent identities and responses;
this format supplies dataset binding and reference resolution, not authenticity.
