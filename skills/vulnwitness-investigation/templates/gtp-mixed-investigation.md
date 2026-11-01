# GTP mixed investigation

Use workspace mode. Establish the protocol/component and choose the requested
scope; this example uses mixed implementation/protocol context. JSON blocks are
tool-call envelopes. Replace the illustrative `session_id` with the returned ID,
use actual call numbers, and choose a fresh request key for an intentional new run.

1. Create a manual investigation. Keep the `request_key` and exact arguments for
   retries; the same request returns its existing record without rerunning.

   ```json
   {"tool": "start_investigation", "arguments": {"goal": "Review GTP-U implementation candidates and protocol context", "scope": "mixed", "request_key": "gtp-mixed-1"}}
   ```

2. Record capabilities and resolve terminology. Inspect dataset limits, topic
   review state and scope. The packaged GTP card is `pending_review` and covers
   the family; GTP-U queries can return GTP-C candidates.

   ```json
   {"tool": "get_knowledge_capabilities", "arguments": {"session_id": "inv_aaaaaaaaaaaaaaaaaaaa"}}
   ```

   ```json
   {"tool": "resolve_telecom_concept", "arguments": {"session_id": "inv_aaaaaaaaaaaaaaaaaaaa", "query": "GTP-U"}}
   ```

3. Run the bounded investigation **with `session_id`**. Six GTP search templates
   cost six backend calls; the eight-call ceiling also covers protocol context.

   ```json
   {"tool": "investigate_telecom_topic", "arguments": {"session_id": "inv_aaaaaaaaaaaaaaaaaaaa", "query": "GTP-U", "scope": "mixed", "budget": {"max_tool_calls": 8, "max_rounds": 2}}}
   ```

4. Inspect the actual call list and saved answer. With exactly the successful
   sequence above, the topic investigation is call 3; failures can change that.

   ```json
   {"tool": "get_investigation", "arguments": {"session_id": "inv_aaaaaaaaaaaaaaaaaaaa"}}
   ```

   ```json
   {"tool": "read_call", "arguments": {"session_id": "inv_aaaaaaaaaaaaaaaaaaaa", "call": 3}}
   ```

   Inspect component relevance per CVE. Keep implementation candidates and FiGHT
   context separate. Catalogue associations are not attack paths; neither these
   nor FiGHT establish a protocol-design flaw or deployed affectedness. Applicability
   stays `unknown`. Preserve controller status, stop reason, warnings, budget usage
   and every need outcome. A pending-card run with matches normally remains
   `partial` / `needs_unmet`; source or budget failures can take precedence.

5. Add one `need_status` finding per returned coverage need. Copy `need_kind`,
   `subject` and `outcome` from the actual answer. This example matches the packaged
   demo's implementation need for the sequence above; do not assume it for a
   different dataset. Empty citations supply no resolved source evidence: the
   structured claim compares the controller's saved fields, not a source anchor.

   ```json
   {"tool": "add_findings", "arguments": {"session_id": "inv_aaaaaaaaaaaaaaaaaaaa", "findings": [{"id": "gtp-implementation-need", "kind": "need_status", "status": "unconfirmed", "claim": {"kind": "need_status", "call": 3, "need_kind": "implementation_cves", "subject": null, "outcome": "not_found"}, "citations": []}, {"id": "gtp-protocol-need", "kind": "need_status", "status": "unconfirmed", "claim": {"kind": "need_status", "call": 3, "need_kind": "protocol_context", "subject": null, "outcome": "matches_unassessed"}, "citations": []}]}}
   ```

   Put interpretations in separate analyst notes. Use client IDs, identical
   IDs/content for retries, and a new ID with `supersedes` for a revision.
   `written: true` is not passed; inspect both check reports.

6. Check and render. Deliver the returned path or resource URI with the pending
   review, family scope, unmet needs, source limits and failures. A passing check
   covers record consistency, citations and structured claims only; narrative is
   not checked and the answer is not verified.

   ```json
   {"tool": "check_investigation", "arguments": {"session_id": "inv_aaaaaaaaaaaaaaaaaaaa"}}
   ```

   ```json
   {"tool": "render_report", "arguments": {"session_id": "inv_aaaaaaaaaaaaaaaaaaaa", "format": "md"}}
   ```

   On `investigation_busy`, retry later at most once within budget. On
   `request_key_conflict`, recover the original arguments or intentionally start
   with another key. On `workspace_full`, ask the operator to prune or choose a
   workspace. For `investigation_interrupted`, start a new triage with a new key
   rather than appending to the interrupted product workflow.

## Appendix: manual follow-up chaining

Optional `search_fight`, `lookup_cve` and `get_evidence` calls must carry the same
`session_id`; inspect saved calls and cite their actual anchors. Separate calls
cannot repair the earlier controller verdict. Calls without the ID are exploration
only; record anything needed for the report. For file-based recording, launch
`vulnwitness mcp --session DIR`, write [findings.yaml](findings.yaml), check with
`vulnwitness session check DIR` and render with `vulnwitness report DIR`.
