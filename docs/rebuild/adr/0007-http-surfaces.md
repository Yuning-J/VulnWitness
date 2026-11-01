# ADR 0007 — HTTP surfaces

Status: accepted (M6 WP3′). Applies to the HTTP guard and settings (M6 WP6), MCP over
Streamable HTTP (WP6) and the v2 REST API (WP7). Amends ADR 0001 §2 and ADR 0003 §10
and §12.
WP6 implements the guard, the settings and MCP over HTTP, and WP7 the REST API
(`m6-api-cli-and-migration.md`, WP6 and WP7).

## Context

Without HTTP the server answers over stdio (ADR 0003). M6 adds two HTTP surfaces: MCP over
Streamable HTTP and a v2 REST API. Both reach the same `KnowledgeToolbox`, whose
`ToolLimits` and sanitized `ToolFailure` already bound what a remote caller can do,
and both run on a developer machine where other local processes and any browser page
can reach a loopback port.

## Decisions

1. **One ASGI stack.** Starlette and uvicorn, declared explicitly in the extras that
   need them. Routes pass the raw JSON body to the toolbox, so `ToolLimits` and the
   sanitized `ToolFailure` apply unchanged; a framework that validates bodies itself
   would duplicate the `schemas/v2` contracts and answer with its own error detail,
   which echoes input. FastAPI is in no dependency group. The dev group declares the HTTP
   test client (`httpx2`) the HTTP tests import.
2. **Two processes, two extras.** REST (`vulnwitness api`) and MCP over HTTP
   (`vulnwitness mcp --http`) run as separate processes. They share the guard, the host,
   the token and the limits, and each has its own port variable. The `mcp` extra owns
   MCP over HTTP, so a user who wants it installs nothing REST needs; `api` is a new
   extra. There is no `neo4j` extra: no v2 Neo4j adapter exists, and ADR 0001 declares
   no empty extra.
3. **Loopback only.** The host setting accepts loopback addresses only, and a server
   asked for any other host refuses to start. DNS-rebinding settings for other hosts are
   a later decision.
4. **Bearer token on both servers**, even on loopback, from settings only. A server
   without a token refuses to start. `/health` is open; `/ready` and every other route
   require the token, so readiness tells an unauthenticated caller nothing.
5. **Deterministic planner, no semantic channel.** Both HTTP surfaces plan with the
   deterministic policy and serve no semantic channel, and their capabilities report
   both as not served. The toolbox's concurrency accounting assumes deterministic
   planning (`KnowledgeToolbox`), and Chroma has no read-only client, so opening its
   store could write during a read. This matches stdio `mcp`.
6. **Stateless MCP sessions.** MCP over HTTP runs with `stateless_http=True` and
   `json_response=True`: every tool is one read-only call, a request deadline cannot cut
   a stream, and the server holds no session state.
7. **A separate envelope for HTTP rejections.** Authentication, Host, Origin and size
   rejections happen before any tool runs, so they answer with their own `HttpRejection`
   contract, not a `ToolFailure`. The HTTP request deadline is set longer than the
   toolbox's per-call time limit, so a tool call that runs out of time normally answers
   first with the `ToolFailure` `timed_out`: over REST as 504 (decision 8), over MCP as
   the tool's error result. Only when the request deadline itself expires, while the
   toolbox's own limit still bounds the tool body on its thread, does the answer become
   504 with `HttpRejection`, on either surface.
8. **`ToolFailureCode` to HTTP status, for the REST API.** MCP over HTTP answers a tool
   failure as stdio does: HTTP 200 with a JSON-RPC result whose `isError` is true and
   whose one text block holds the `ToolFailure` (ADR 0003 §7), because the call itself
   succeeded at the protocol level. The REST API (WP7) answers it with a status:

   | Code | Status |
   |---|---|
   | `invalid_arguments` | 422 |
   | `arguments_too_large` | 413 |
   | `unknown_evidence_id` | 404 |
   | `server_busy` | 503 |
   | `timed_out` | 504 |
   | `response_too_large`, `integrity_check_failed`, `internal_error` | 500 |

   The REST body is the bare `ToolFailure` with its fixed sentence, so the mapping needs
   no new envelope and no contract change. A WP7 test iterates every `ToolFailureCode`
   member.
9. **REST endpoints, verification included.** `POST /api/v2/search`,
   `POST /api/v2/investigate`, `GET /api/v2/evidence/{evidence_id}`,
   `GET /api/v2/capabilities` and `POST /api/v2/verify`, plus `/health` and `/ready`.
   Verification over HTTP settles ADR 0003 §10: its route has a 4 MiB body cap (the
   `MAX_EVIDENCE_SET_BYTES` the CLI's `verify` reads), runs one request at a time and has a deadline of
   the investigation wall time plus a margin. It answers 200 with the verdict for every
   verdict; 413, 503 and 504 stay for the bounds, because a verification answer is not a
   request failure. MCP keeps its eight tools.
10. **Ports from settings only.** The defaults are 8765 for MCP over HTTP and 8766 for
    the API. Host and ports come from the settings boundary (ADR 0004) and nowhere else:
    no `--host` or `--port` flag.
11. **Body caps counted on the wire, before parsing.** The toolbox's 64 KiB argument cap
    applies only after the transport has decoded the JSON and the toolbox has serialized
    the arguments again, so it cannot stop a server from buffering and parsing a huge
    body. Every HTTP route, REST and MCP alike, therefore reads its body through the
    guard, which counts the bytes as they arrive and enforces a fixed cap before any JSON
    parsing and before the MCP SDK sees the request:

    | Route | Body cap |
    |---|---|
    | `POST /api/v2/verify` | 4 MiB (decision 9) |
    | every other route, MCP's endpoint included | 256 KiB |

    A `Content-Length` over the cap is refused before the body is read; a body without one
    (chunked) is refused as soon as the count passes the cap. Both answer 413 with
    `HttpRejection`. Whitespace, escapes and the MCP JSON-RPC envelope count against the
    cap, which is why it is four times the toolbox's argument cap; the toolbox still
    applies its own cap to the decoded arguments. The caps are constants, not settings.

## Consequences

- WP6 adds `HttpSettings`, the guard, `mcp --http` and the `HttpRejection` contract
  (`2.0.0-dev.23`); WP7 adds the `api` extra, `vulnwitness api`, its routes and the
  `route_busy` rejection for the verification route's one-at-a-time bound
  (`2.0.0-dev.24`).
- Nothing listens on a network address other than loopback, and nothing answers an
  unauthenticated caller beyond `/health`.
- The REST surface covers less than the CLI (for example, topic context has no route).
  That is deliberate: every route is one toolbox call or verification.
- A model planner or the semantic channel over HTTP needs a new decision: the toolbox's
  concurrency accounting and the no-writes-on-read rule would both have to change.


## Local UI scope

[ADR 0014](0014-local-ui.md#http-surface-amendments-to-adr-0007) specifies the
local UI's public static shells, per-launch fragment token, port option and early
HTTP startup during loading, with the browser-specific reasons for these exceptions.
The API and MCP HTTP decisions above retain their existing behavior.
