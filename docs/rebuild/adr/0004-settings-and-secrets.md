# ADR 0004 — Settings and secrets

Status: accepted (M6, work package 1). Applies to `settings.py`, the model planner
discovery in `adapter_discovery.py`, `application/planner_setup.py`, the
`model_planner` capability in `domain/planning.py` and `domain/investigation.py`,
`list_accepted_planner_capabilities` in `composition.py`,
`application/evidence_set_verification.py` and the CLI.

## Context

The brief (§15) asks for one typed settings boundary, no default production password,
and "missing credentials disable the corresponding adapter with a typed capability
status". §10 asks for an optional OpenAI-compatible planner behind `ModelPort`,
disabled by default, that keeps credentials out of logs; §20 asks that errors never
leak credentials or local paths.

Before this package, no v2 code read the environment. The model planner existed only as
`ModelPort` and test fakes; the `model_planner` capability was `available` or
`not_configured`. The planner adapter itself is the next task. This package fixes how
that adapter is configured, discovered and reported, so the adapter task adds an adapter
and nothing else.

## Decisions

### 1. Settings are environment variables, read once, with nothing else read

`load_settings(environment)` (`settings.py`) is the only code that reads configuration.
The CLI calls it once, with `os.environ`; tests pass a mapping.

| Variable | Setting | Default |
|---|---|---|
| `CVE_KGRAG_PLANNER_ENABLED` | turns the model planner on (`true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off`, any case) | off |
| `CVE_KGRAG_PLANNER_BASE_URL` | the OpenAI-compatible endpoint | none; required when enabled |
| `CVE_KGRAG_PLANNER_MODEL_NAME` | the model the planner names (`ModelPlannerIdentity.model_name`'s pattern) | none; required when enabled |
| `CVE_KGRAG_PLANNER_API_KEY` | the key that authenticates it: 1 to 1024 printable ASCII characters without whitespace, since it travels in a header | none |
| `CVE_KGRAG_PLANNER_REASONING_EFFORT` | sent as the request's `reasoning_effort` (`^[a-z]{1,16}$`); DeepSeek reasons by default and `none` turns it off (ADR 0005) | not sent |

- An empty variable counts as unset, so `KEY=` in a sourced file leaves the key missing.
- The planner's other variables are read only when it is enabled.
- Variables the table does not name are ignored, including other `CVE_KGRAG_*` names, so
  a test opt-in variable never aborts a command.
- No configuration file and no `.env` file is read; an operator who keeps settings in an
  untracked `.env` sources it in the shell (`set -a; . ./.env; set +a`). `.env` and
  `.env.*` are ignored by git.
- No command-line flag sets a planner setting: a key on the command line is left in shell
  history and process listings.
- There is no `provider` setting: the one protocol is OpenAI-compatible, the entry point
  chooses the adapter and `base_url` chooses the vendor.
- Settings are not a published contract: their models are `BaseModel`s, not
  `ContractModel`s, and no schema is exported for them.

The semantic channel is a second section, read the same way (M6 WP2):

| Variable | Setting | Default when enabled |
|---|---|---|
| `CVE_KGRAG_SEMANTIC_ENABLED` | turns the semantic channel on | off |
| `CVE_KGRAG_SEMANTIC_COLLECTION_NAME` | the Chroma collection (Chroma's name rule) | `cve_documents` |
| `CVE_KGRAG_SEMANTIC_PERSIST_DIRECTORY` | the directory holding it, relative to the working directory unless absolute; no control character | required when enabled |
| `CVE_KGRAG_SEMANTIC_MODEL_NAME` | the sentence-transformers model (`^[A-Za-z0-9._/-]{1,256}$`) | `sentence-transformers/all-MiniLM-L6-v2` |

The collection and model defaults are what CVE-KGRAG's pipeline builds; the directory has
no default (ADR 0006). Only an operator's own run opens the
semantic store: `search`, `topic` and `investigate` load the adapter when run with
`--semantic`, and otherwise load no adapter; `lookup` and `demo` never do. Every command
still validates the semantic settings at startup, so an invalid one is a usage error. `mcp`
and `verify` never load it, whatever the settings, and log one line saying so: Chroma has
no read-only client (opening an existing store may write its journal or migrations), and
both surfaces promise not to change local state, so their `semantic_channel` is
`not_configured` and a set sealed with `--semantic` while the channel was enabled does
not verify. The adapter opens
only a directory that already holds a Chroma database, so a mistyped directory is
reported unusable rather than created, and loads its model from disk only
(`local_files_only`), so it never reaches the model hub.
`semantic_channel` is `available` once its adapter loads, `not_configured` when it is not
enabled, and `unavailable` with `SemanticUnavailableDetail.ADAPTER_UNUSABLE` when it is
enabled but its adapter is not installed, installed twice, or fails to load or build. A
search of an unusable channel reports it unavailable (`ADAPTER_UNUSABLE`), as one of an
unconfigured channel reports `NOT_CONFIGURED`; the validator applies the same rules to
both states and requires each search's reason to match the capability.
Discovery logs a load failure by type alone, and a failed search too: a Chroma or model
error may name a local path.

### 2. The endpoint is one a key may be sent to

`check_endpoint_url` accepts an ASCII URL, `https`, or `http` only to `localhost` or a
loopback IP address, with a host, a port from 1 to 65535 if any, and no user information, query or
fragment. It rejects whitespace, control characters, `\` and `%` anywhere, each of which
could make two URL parsers disagree on the host, and `?` and `#`, which start a query or a
fragment even when it is empty. It removes exactly one trailing `/`, and the adapter sends
each request to `base_url + "/" + route` (`ModelPortFactory`): `/v1` and `/v1/` therefore
reach the same routes, while `/v1//` becomes `/v1/`, whose routes (`/v1//route`) a server
may treat as another path than `/v1`. The URL comes from
the operator's environment, never from a caller.

### 3. No error, log or answer carries a setting's value

- The key is a `SecretStr`: masked in `repr`, `str` and JSON dumps.
- Both settings models set `hide_input_in_errors`. `SettingsError` is built from
  `ValidationError.errors(include_input=False)`, as `VARIABLE: message` lines, and is
  raised outside the `except` block, so it has no `__context__` holding the error that
  held the values. The validators' own messages quote nothing.
- An invalid setting is a usage error (exit 2) for every command; the message names the
  variables.

### 4. A missing key or an unusable adapter leaves the planner unavailable

`discover_planner_setup(settings)` (`adapter_discovery.py`) returns a `PlannerSetup`
(`application/planner_setup.py`): `ModelPlanning(identity, model_port)` or
`DeterministicPlanning(unavailable_detail)`.

| Settings and adapter | Planner | `model_planner` capability |
|---|---|---|
| not enabled | deterministic | `not_configured` |
| enabled, no key | deterministic | `unavailable`, `MISSING_API_KEY` |
| enabled; the registry cannot be listed, or the adapter is not installed, installed twice, belongs to no distribution, or fails to load or build | deterministic | `unavailable`, `ADAPTER_UNUSABLE` |
| enabled, one usable adapter | the model | `available`, `format_planner_version(identity)` |

- A missing key is not looked up any further: no entry point is listed.
- The two sentences are `ModelPlannerUnavailableDetail`. Every unusable-adapter case
  shares one sentence; the log line names the case.
- The entry point is `model_planner` in `cve_kgrag.adapters`. Its factory is
  `ModelPortFactory`:
  `factory(*, base_url, model_name, api_key: SecretStr, reasoning_effort) -> ModelPort`.
  - Building the adapter does no network or file I/O.
  - Only `propose_plan` talks to the endpoint, within its timeout.
  - Requests stay under the configured base URL: each targets exactly
    `base_url + "/" + route` (§2). They follow no redirect and ignore proxy settings from
    the environment.
  - The key stays a `SecretStr` until the request header is built.
- Listing the registry, reading the entry point, loading and building run inside guards.
  Anything they raise is logged by its type name only, never with its message or
  traceback, since an adapter's or the registry's error may quote its request or a local
  path; a `KeyboardInterrupt` is raised again afresh, with no adapter text. The semantic
  and MCP discovery paths list the registry under the same guard.

### 5. The server builds the planner's identity, and an adapter writes no text

`ModelPort` has one method, `propose_plan`; the port says nothing about itself. The
server builds the identity every trajectory records (`describe_installed_planner`):

| Field | From |
|---|---|
| `model_name` | `CVE_KGRAG_PLANNER_MODEL_NAME` |
| `adapter` | the entry point's object reference (`module:attribute`) |
| `adapter_version` | the version of the distribution that installed the entry point |
| `endpoint_sha256` | `fingerprint_endpoint(base_url)`: SHA-256 of the configured URL (one trailing `/` already removed) with its scheme and host in lower case, its port written out (the scheme's default when none is given) and its path exactly as written |
| `reasoning_effort` | `CVE_KGRAG_PLANNER_REASONING_EFFORT`, or null |

- So the same model name behind another endpoint, another adapter, another adapter
  version or another reasoning effort is another planner. The fingerprint binds the endpoint without naming its
  host; a guessable host can still be confirmed by hashing it.
- The `model_planner` capability's version is `format_planner_version(identity)`: the
  model name, then the SHA-256 of the whole identity. The validator requires the
  capability to equal the one the trajectory's planner gives, so binding the capability
  binds the identity.
- `ModelReply.detail` is a `ModelReplyFailureDetail`, one of the server's sentences
  (unreachable, timed out, credentials rejected, rate limited, endpoint error, malformed
  response, adapter failed). An adapter picks the reason; it cannot write the text, so no
  endpoint or adapter text reaches a trajectory. Every sentence describes a reply a
  planner gave; none is reserved for replay, so a live adapter cannot claim a state only
  replay knows.
- `plan_text` is untrusted model output: its schema description, the investigate tool's
  description and the server instructions say so.
- The port is wrapped in `GuardedModelPort`:
  - anything `propose_plan` raises, a `BaseException` included (it runs on a call-runner
    worker thread, where no interrupt arrives), is recorded as the fixed failed reply
    `FAILED_ADAPTER_REPLY` and logged by type;
  - every answer is validated afresh inside the same guard (`check_model_reply`), its
    fields read as attributes and never serialized, so a reply built without validation
    (`model_construct`), a reply with missing fields, or a reply whose field reads run
    adapter code that raises with the key is refused the same way;
  - the round falls back to the policy, and the adapter's text reaches neither the
    trajectory nor a log.

### 6. The contract states the unavailable planner and the planner's identity (`2.0.0-dev.19`)

- `model_planner` may be `available`, `not_configured` or `unavailable`.
- An unavailable one carries one of the `ModelPlannerUnavailableDetail` sentences; the
  published schema and the validator both confine the detail to them.
- The validator requires `available` with the trajectory's planner version for a model
  planner, and `not_configured` or `unavailable` for the deterministic policy.
- `ModelPlannerIdentity` carries `adapter`, `adapter_version` and `endpoint_sha256`
  beside `model_name`; `ModelReply.detail` is a `ModelReplyFailureDetail`.
- The planner is per service, not per deployment: `InvestigationDeployment` still
  describes every subject but `model_planner`. `InvestigationService` takes the
  `PlannerSetup`, and `describe_service_capabilities(deployment, planner_setup)` adds its
  capability.

### 7. Verification binds the configuration and takes health from the record

`verify_evidence_set(evidence_set, deployment, accepted_planner_capabilities)` validates
against the deployment's capabilities followed by the set's own `model_planner`
capability when that is accepted, otherwise the first accepted one, so the validator
reports the difference.

`list_accepted_planner_capabilities(settings)` (`composition.py`) reads the settings and
the installed adapter's metadata, without loading the adapter or reading the key:

- `not_configured` always, since the MCP tools plan with the deterministic policy;
- with the planner enabled, `unavailable` with each sentence, and `available` with the
  identity of the installed adapter under these settings, when one is installed.

Whether the configured planner could plan is the health of the service that sealed the
set, which the set records. Its model, adapter and endpoint are configuration, which the
verifier's settings and installation fix. Replay rebuilds the planner from the record:
the recorded replies for a model (`RecordedModelPort`), or the recorded reason for the
deterministic policy (`find_planner_unavailable_detail`). A replayed run that asks for a
round the record holds no reply for is answered `ADAPTER_FAILED`, since the recorded port
gives no valid reply there; the round then differs from the recorded one and replay names
`trajectory.rounds`. The replayed set is compared, never published.

`cve-kgrag investigate` plans with the discovered planner. `cve-kgrag verify` accepts
the capabilities the settings and the installed adapter allow. `cve-kgrag mcp` keeps the
deterministic planner.

## Consequences

- With no environment set, every command behaves as before, except that `model_planner`
  can now report `unavailable` and the contract version is `2.0.0-dev.19`.
- A set verifies under the settings and installation that sealed it. A model-planned set
  does not verify under settings naming another model, endpoint or reasoning effort, with
  another adapter or adapter version installed, or with no planner configured.
- A set sealed while the configured planner could not plan verifies under any settings
  that enable a planner, whatever the verifier's key and adapter.
- The core package registers one `model_planner` entry point, the OpenAI-compatible
  adapter (ADR 0005), so an enabled planner with a key plans through it.
- Subprocess tests start the server without `CVE_KGRAG_*` variables, so a developer's
  exported settings cannot change them.
- Not done here:
  - The published schema does not tie the trajectory's planner kind to the
    `model_planner` state; the validator does. That gap predates this package.
  - No rule governs the environment a child process inherits; nothing in `src` starts
    one. The Trustify stdio-client task owns that rule.
