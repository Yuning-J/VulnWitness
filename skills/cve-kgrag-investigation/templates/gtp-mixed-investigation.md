# GTP mixed investigation

1. Confirm the target: GTP family or GTP-U component, product/vendor if any, versions
   if known, and mixed implementation/protocol scope. Start recording and check
   capabilities using the Skill's session contract section before querying.
2. Resolve the terminology. Inspect the returned card review state and scope.

   ```json
   {"tool": "resolve_telecom_concept", "arguments": {"query": "GTP-U"}}
   ```

   The bundled GTP card is pending review. It covers the GTP family; a GTP-U query
   can return GTP-C records. An alias does not assess every candidate's relevance.
3. Run the bounded investigation. The six GTP templates consume six backend calls;
   allow room for protocol context within the eight-call ceiling.

   ```json
   {"tool": "investigate_telecom_topic", "arguments": {"query": "GTP-U", "scope": "mixed", "budget": {"max_tool_calls": 8, "max_rounds": 2}}}
   ```

4. Read implementation candidates separately from FiGHT protocol context. Inspect
   each CVE's component rather than labelling all family matches GTP-U findings.
   A normal pending-card run with matches is partial with unmet needs; preserve
   the actual outcome when budget or source failures take precedence. Report every
   need's outcome, including missing implementation evidence and unassessed matches.
5. If a separate protocol-context view helps, search FiGHT explicitly. This call
   does not repair or change the prior investigation's needs or stopping decision.

   ```json
   {"tool": "search_fight", "arguments": {"query": "GTP-U", "limit": 5}}
   ```

6. Select a returned CVE only if there is one; explain the component relevance and
   uncertainty. Look it up using the `lookup_cve` pattern in the product template.
   Read anchors with `get_evidence` when needed. Keep catalogue associations apart
   from FiGHT context; neither demonstrates an exploit chain or protocol-design flaw.
7. Copy [the findings template](findings.yaml), fill it from actual recorded calls,
   and check it using the Skill's session contract section. Replace the product
   observation with the appropriate finding kind; omit unused product pagination.
   Report unmet needs, pending review, family scope, truncation, and any failures.
   Finish with Answer, Evidence, What is not established, and Next steps.
