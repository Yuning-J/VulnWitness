# ADR 0005 — The model planner adapter

Status: accepted (M6, the model planner adapter task). Applies to
`adapters/planner/` (`openai_compatible.py`, `http_transport.py`, `chat_completion.py`),
the `model_planner` entry point in `pyproject.toml`, `PlanningInput.required_tools`,
`PLANNER_SHARE_OF_WALL_TIME` and `tests/live/`.

## Context

ADR 0004 fixed how a model planner is configured, discovered, guarded and identified, and
left the adapter to this task. The brief (§10) asks for an optional OpenAI-compatible
planner behind `ModelPort`: disabled by default, emitting only a schema-validated
`QueryPlan` over an allowlisted vocabulary, shown untrusted text only as quoted data,
under the same budgets and gate, never writing facts, never required, and keeping
credentials out of logs. §19 asks that live tests use explicit markers and an
environment opt-in; §20 asks for no SSRF, strict timeouts and redacted secrets.

DeepSeek's API, read on 2026-10-21 (api-docs.deepseek.com):

- base URL `https://api.deepseek.com`, route `/chat/completions`;
- models `deepseek-flash` and `deepseek-v4-pro`;
- thinking mode is on by default; `reasoning_effort: none` (or `thinking.type: disabled`)
  turns it off;
- `response_format: {type: json_object}` needs the word "json" in a prompt and "may
  occasionally return empty content";
- errors 400, 401, 402 (insufficient balance), 422, 429, 500, 503.

## Decisions

### 1. The adapter ships in core, on the standard library

`build_model_port` (`adapters/planner/openai_compatible.py`) is registered as the
`model_planner` entry point beside `semantic` and `mcp_server`. It needs no extra:
requests go through `http.client`, which reads no proxy setting from the environment and
follows no redirect, so no handler needs switching off. `urllib.request` was rejected for
those defaults and because its timeout is per socket operation.

### 2. One request per round, its reads ended at the deadline

`post_json` (`http_transport.py`) sends one POST to `base_url + "/chat/completions"`:

- TLS with `ssl.create_default_context()` (certificate and host name checks) for https;
  plain http only where the settings allow it, a loopback host;
- connecting (name resolution, TCP, the TLS handshake) and sending run under the socket
  timeout, the whole timeout for each address tried;
- once the request is sent, a watchdog shuts the socket down at the deadline, and any
  answer the deadline cut off is `TIMED_OUT`. `http.client` reads a status line, a header
  block, interim `100 Continue` answers and chunk trailers in many reads, so a per-read
  timeout would let an endpoint that sends a fragment now and then (DeepSeek's keep-alive
  blank lines, or a hostile one) hold the call indefinitely;
- the port is always given explicitly (the scheme's default when none is written), so
  `http.client` never reads a port out of an IPv6 host;
- a body is read only for a 200, and never past 1 MiB; any other status comes back
  unread, so an error body cannot fill memory, and a 3xx is a status, never followed;
- it never raises and never logs; a timeout is `TIMED_OUT`, any other socket, protocol or
  value error `UNREACHABLE`.

A planner call gets at most a third of the run's wall-time budget
(`PLANNER_SHARE_OF_WALL_TIME`; 10 s of the default 30 s), a core rule every adapter gets.
The adapter is told that limit as its timeout, and the controller enforces it: a call
still running when its share ends is abandoned, and a reply that lands at or after the end
of its share is not read; with the run in time, either is recorded as the failed reply
`PLANNER_CAP_REPLY` (`TIMED_OUT`), so the round falls back to the policy
(`model_unavailable`) and retrieves with the time left. Replay answers that round from the
record, so it takes the same path without timing. Only a call still running at the run's
deadline is `model_timed_out`. An investigation with a model planner may therefore leave
up to three abandoned calls behind: each round's planner call at the end of its share,
and one call at the run's deadline. Only `cve-kgrag investigate` plans with a model, one
process per investigation, and `cve-kgrag eval planner`, whose runs go one after another
on one call runner and start only once every call an earlier run abandoned has returned,
so its process holds no more than one investigation's. The MCP tools plan with the
policy, so ADR 0003 §8's bound on their abandoned calls stands.

### 3. The request

- Headers: `Authorization: Bearer <key>` (built per request from the `SecretStr`),
  `Content-Type` and `Accept: application/json`, `User-Agent: cve-kgrag-planner`.
- Body: `model`, `messages` (the fixed system instructions, then the round's
  `PlanningInput` as JSON), `response_format: {type: json_object}`, `stream: false`, and
  `reasoning_effort` only when configured. No `temperature` or `max_tokens`: replay uses
  recorded replies, so sampling buys nothing to fix, and the reply is bounded by the read
  cap, `MAX_PLAN_TEXT_CHARS` and the deadline.
- The instructions (`PLANNER_INSTRUCTIONS`) give the `QueryPlan` shape with an example and
  the gate's rules: only `allowed_tools`, every tool in `required_tools`, every ID in
  `cve_ids` in one lookup, search words only from `allowed_terms`, the tool costs within
  `remaining_tool_calls`, nothing from `issued_calls` repeated. The shape lists
  `{"tool": "fight_direct_search"}`, with the rule that it takes no arguments, searches
  MITRE FiGHT with the question's own words and is offered only when no topic resolved;
  the planning input offers it only when, in addition, the scope is not
  `implementation_only` and the interpretation lets the words go to FiGHT
  (`fight_terms`). `quoted_query` is the caller's text and never instructs the model.
- `PlanningInput.required_tools` is new: the tools of the policy's round-1 plan, so a
  round-1 model plan that includes them consults every baseline source the gate requires;
  empty in round 2. A planner was otherwise left to guess the baseline.
- `allowed_tools` and `tool_costs` leave out a tool that on its own would consult more
  sources than the run may, and `required_tools` names only offered tools, so the model is
  never asked for a tool it is not offered. Two offered tools can still exceed the budget
  together, and the gate then falls back. When the policy's own round-1 plan is over the
  source budget, no plan passes the gate, since a round-1 plan must consult the policy's
  sources: the model is not called, and the round records `model_not_consulted` with the
  policy plan's rejections (`is_model_consultable`). Over the tool-call budget alone the
  model is consulted, since fewer calls may reach the same sources.

### 4. The answer

| Endpoint answer | `ModelReply` |
|---|---|
| 200, the first choice's message content, non-blank, at most `MAX_PLAN_TEXT_CHARS`, not holding the key as written or JSON-escaped | `ok`, that content as plan text |
| 200 otherwise (not JSON, no choices, null, blank or overlong content, content holding the key, a body over 1 MiB) | `error`, `MALFORMED_RESPONSE` |
| 401, 403 | `error`, `CREDENTIALS_REJECTED` |
| 429 | `unavailable`, `RATE_LIMITED` |
| 408, 504, 524, or the deadline | `unavailable`, `TIMED_OUT` |
| 502, 503 | `unavailable`, `ENDPOINT_ERROR` |
| any other status (3xx, 400, 402, 422, 500, …) | `error`, `ENDPOINT_ERROR` |
| no connection or no HTTP | `unavailable`, `UNREACHABLE` |

- The completion is parsed by boundary models (`chat_completion.py`) that read only
  `choices[0].message.content`; `reasoning_content` and every other field are ignored.
- Content that holds the configured key is refused, so a key an endpoint echoes is never
  recorded: a round records the reply it got even when the gate rejects the plan. The
  check reads the content as written and every JSON string literal in it decoded on its
  own (`\uXXXX`, `\/`), wherever it stands: a repeated key a JSON reader drops, a value
  beside a number Python's reader refuses, or prose around the plan. A key split across
  literals or otherwise encoded is not recognised.
- A failed status is logged as its number alone (`model endpoint answered HTTP 401`).
- The adapter itself never raises; `GuardedModelPort` (ADR 0004 §5) still wraps it.

### 5. Live tests are opt-in

`tests/live/` is outside `testpaths`, and its tests carry the `live` marker. They are
skipped unless `CVE_KGRAG_LIVE_TESTS=1`; once opted in, missing planner settings fail.
They check that the configured endpoint answers a round with a plan, that the sealed set
holds no key, and, for `reasoning_effort` `none`, that the answer carries no reasoning.
They print nothing of a reply, assert on secrets only through `assert_secret_absent`,
and are never run with `--showlocals`. `tests/live` is linted with the offline lane.

## Consequences

- An enabled planner with a key plans through this adapter. For DeepSeek:
  `CVE_KGRAG_PLANNER_BASE_URL=https://api.deepseek.com`,
  `CVE_KGRAG_PLANNER_MODEL_NAME=deepseek-flash`, `CVE_KGRAG_PLANNER_REASONING_EFFORT=none`.
- A server that rejects `response_format: json_object` answers 400, which is
  `ENDPOINT_ERROR` every round; the policy plans.
- The adapter's identity version is the cve-kgrag distribution's version, so a change to
  the instructions or the request body changes what a planner does without changing
  `adapter_version` until the package version moves; during development every build is
  `2.0.0.dev0`.
- Offline tests use a recording transport and loopback servers on 127.0.0.1, never an
  outside network; https is not exercised offline.
- The model is not consulted in round 1 when the policy's own plan is over the source
  budget, which no round-1 plan can meet (`model_not_consulted`), nor in round 2 without a
  policy refinement for an open need. Otherwise it is consulted, whether or not some
  plan could pass the gate.
