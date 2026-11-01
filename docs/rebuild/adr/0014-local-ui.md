# ADR 0014 — Local browser workspace

Status: accepted.

## Decision

`vulnwitness ui --workspace ROOT --port 8767` serves packaged HTML, CSS and vanilla
JavaScript with a narrow ASGI adapter. It needs the `api` extra, binds only to
127.0.0.1, and needs no frontend server or build. The default workspace is
`~/.vulnwitness/workspace`.

The adapter injects the same complete toolbox and workspace deployment as MCP.
Product input uses bounded triage; CVE and topic input start manual investigations
and record ordinary knowledge calls with their session IDs. The browser persists
normalized form values and a random submission nonce in session storage. Their
SHA-256 request key binds retries to that submission. A separate New submission
action discards the nonce. The backend remains the authority for idempotency,
locking, caps, failure messages, selection order and uncertainty.

Detail panels serialize `build_session_report`'s existing content model; they do
not reconstruct CVE match, affectedness, path or check meanings. The HTML report's
freshness uses the workspace's format-specific status. Report reads accept an
investigation ID only and read its fixed `report.html` artifact through workspace
path validation. They accept neither filenames nor path parameters.

Each recorded investigation contributes implementation candidates, separate FiGHT
protocol threat context with sources, answer and step warnings, status and needs
to the shared report model. HTML, Markdown and UI detail views render those same
sections. Candidate links point to recorded lookup cards when available.

## HTTP surface amendments to ADR 0007

The existing guard, exact raw-path routing, Host/Origin allowlist, bearer header,
body cap, deadline, no-store and nosniff rules apply. No CORS permission is served.
These deliberate differences support a browser in one local process:

- The token is random per launch, printed only in the initial URL fragment. The
  page moves it into tab session storage and removes the fragment. Data requests
  carry it in Authorization, including every mutation; no cookies authorize calls.
- Fixed packaged page shells and assets are public behind Host/Origin validation.
  They contain no investigation or dataset content. Every data operation requires
  the bearer. A top-level browser navigation cannot set Authorization, so the
  read-only report navigation POST carries the same random token in its bounded
  form body instead. Host/Origin validation and constant-time token comparison
  still apply before any workspace access; neither cookies nor query-string
  tokens authorize reads. The separate API report read requires the bearer header.
- UI pages use `Referrer-Policy: same-origin` so browser form POSTs to the report
  route retain the page's real Origin. Cross-origin navigation sends no referrer;
  external links retain `rel="noreferrer noopener"`. The guard refuses null and
  foreign Origins. The report itself uses `no-referrer` and carries both a CSP
  header and a saved-file CSP meta tag; its inline stylesheet needs no server.
- The port is a CLI option; the host is fixed. There is no HTTP-token prerequisite
  in settings for this surface.
- Pages and the authenticated list answer while a daemon thread loads the same
  data plane as workspace MCP. The shared publication signal and bounded
  `wait_for_data` contract serve readiness. Operations return `data_loading`
  immediately, without creating records or reserving keys. Loading failure stops
  the server with exit 1. HTTP acceptance therefore means the UI is available;
  readiness means the dataset is available. Existing API/MCP HTTP startup is unchanged.

The API exposes only list, start, triage, snapshot, report content model, lookup,
topic investigation, saved call, check, HTML render, fixed report read and readiness.
Existing request contracts and typed failures/status registry apply. UI-only
compositions are not committed schema exports; no contract version changes.

## Browser trust boundary

All recorded text uses DOM `textContent`, including exact saved JSON. Scripts and
styles are packaged, with no external resources or inline scripts. The page CSP
limits scripts/styles/connections and form submissions to self, denies base URLs,
frames and embedding. The ID-addressed report navigation serves only the fixed
HTML file directly, with its renderer's own CSP denying scripts and permitting its
self-contained inline stylesheet. The same report policy is also sent as a header.
The browser can save that HTML as an exported report.

No chat, model routing, agents, task workers, finding editing, remote access or
additional investigation engine are part of this interface.
