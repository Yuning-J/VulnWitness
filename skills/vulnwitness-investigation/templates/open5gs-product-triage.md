# Open5GS product triage

Use workspace mode. Establish the requested component and version; leave unknown
values unspecified. The packaged demo may have no Open5GS records. JSON blocks
are tool-call envelopes: send the named tool its arguments. Replace the illustrative
`session_id` everywhere with the ID returned by creation, and use a fresh request
key for an intentional new run. Never copy example call numbers without inspecting
the snapshot.

1. Run bounded triage. Add a version only if the user supplied it. `select` can
   contain returned CVEs for an intentional selection; automatic selection is an
   order, not a risk ranking. The workflow records capabilities, pages and lookups.

   ```json
   {"tool": "triage_product", "arguments": {"product": "open5gs", "max_pages": 20, "lookups": 5, "goal": "Review Open5GS implementation records; deployed version unknown", "request_key": "open5gs-triage-1"}}
   ```

2. Inspect the saved summary, dataset, calls, remaining steps and outcome.

   ```json
   {"tool": "get_investigation", "arguments": {"session_id": "inv_aaaaaaaaaaaaaaaaaaaa"}}
   ```

   For `stopped_at_cap`, disclose partial inventory or deep-dive scope and the cap.
   For `no_match`, report this bounded empty query; do not invent a candidate or
   infer safety. For `failed`, retain earlier evidence and disclose the failure.
   On a lost response, retry creation with the same `request_key` and arguments;
   this returns the existing record without rerunning. `request_key_conflict`
   requires recovering the original request or intentionally choosing a new key.
   For `investigation_busy`, wait and retry at most once within budget. For
   `workspace_full`, ask the operator to prune or choose another workspace.
   `investigation_interrupted` requires a new triage and key; there is no resume.

3. Read each relevant call using the actual sequence from the snapshot. Call 1
   is the capabilities call in a fresh successful triage; inspect the product
   and lookup call references too. `response_json` contains exact saved JSON.

   ```json
   {"tool": "read_call", "arguments": {"session_id": "inv_aaaaaaaaaaaaaaaaaaaa", "call": 1}}
   ```

   Optional deeper lookup: substitute an ID actually returned by this inventory.
   The synthetic ID below demonstrates request shape only. Skip if no candidate.

   ```json
   {"tool": "lookup_cve", "arguments": {"session_id": "inv_aaaaaaaaaaaaaaaaaaaa", "cve_id": "CVE-9999-0001"}}
   ```

   Every follow-up knowledge call needs `session_id` to reach the report. Refresh
   the snapshot to find its call number, then read it. Preserve product-field
   versus description-mention basis, version uncertainty and catalogue inheritance.
   Catalogue associations are not attack paths; affectedness remains `unknown`.

4. Add findings using exact fields and call/anchor pairs from saved evidence.
   The [demo request](../examples/add_findings.request.example.json) shows a
   product claim generated from packaged data; its IDs are not Open5GS evidence.
   This anchorless analyst note records a limitation, without claiming source proof:

   ```json
   {"tool": "add_findings", "arguments": {"session_id": "inv_aaaaaaaaaaaaaaaaaaaa", "findings": [{"id": "open5gs-scope-note", "kind": "analyst_note", "status": "unconfirmed", "statement": "Deployment applicability remains unknown; review the recorded scope and component relevance before use.", "citations": []}]}}
   ```

   Use client IDs; identical content under the same ID is a retry no-op. For a
   revision send a new ID with `supersedes` pointing to the earlier effective
   finding. For example, after the note above:

   ```json
   {"tool": "add_findings", "arguments": {"session_id": "inv_aaaaaaaaaaaaaaaaaaaa", "findings": [{"id": "open5gs-scope-revision", "supersedes": "open5gs-scope-note", "kind": "analyst_note", "status": "unconfirmed", "statement": "Component relevance and deployed applicability need independent review; the recorded query covers only the served corpus.", "citations": []}]}}
   ```

   `written: true` is not passed: inspect batch and whole-record checks.

5. Check, then render and present the returned local path or resource URI with
   evidence, limits and unresolved questions. A passing check compares record,
   citations and structured claims; it is not a verified answer. Narrative is
   not checked. Re-render after later calls or findings make a report stale.

   ```json
   {"tool": "check_investigation", "arguments": {"session_id": "inv_aaaaaaaaaaaaaaaaaaaa"}}
   ```

   ```json
   {"tool": "render_report", "arguments": {"session_id": "inv_aaaaaaaaaaaaaaaaaaaa", "format": "html"}}
   ```

## Appendix: manual chaining

Use `start_investigation` with a goal and `request_key` instead of triage, then
`get_knowledge_capabilities`, `query_product_vulnerabilities` and `lookup_cve`, all
with `session_id`. For paging, pass the exact `next_cursor` as `cursor` with the
same product/vendor/version/limit until null or your cap. Record progress and
candidate reasoning, read saved calls, add findings, check and render as above.
Without `session_id`, calls are exploration only and do not reach the report.
Shell users can run `vulnwitness triage … --session DIR` → `vulnwitness report DIR`.
