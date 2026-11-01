# Open5GS product triage

1. Confirm Open5GS, the intended component and version, and implementation scope.
   If vendor or version is unknown, say so. Start recording and check capabilities
   using the Skill's session contract section before querying.
2. Query the product, without assuming a vendor identity. The packaged fixture can
   return no Open5GS records; use the separate synthetic example to practise paging.

   ```json
   {"tool": "query_product_vulnerabilities", "arguments": {"product": "open5gs", "limit": 2}}
   ```

3. Inspect matched vendor/product pairs and the basis on each item. If the user
   supplied a version, include it on the first request and every continuation.
   Follow the returned cursor unchanged; substitute the actual string below.
   Skip this call if the cursor is null.

   ```json
   {"tool": "query_product_vulnerabilities", "arguments": {"product": "open5gs", "limit": 2, "cursor": "<next_cursor from the previous page>"}}
   ```

   Record progress using the Skill's session contract section. Stop at the final
   page or agreed budget. State remaining pagination explicitly. No page traversal
   establishes corpus completeness.
4. Pick one returned CVE and explain which component or evidence made it useful.
   Substitute its actual ID; do not run this illustrative ID against a real corpus
   unless it was returned. If the product query was empty, report that and stop.

   ```json
   {"tool": "lookup_cve", "arguments": {"cve_id": "CVE-9999-0001"}}
   ```

5. Inspect the returned weakness associations, inheritance, missing links, snapshot
   identity and omitted count. Read the source anchors. Preserve the distinction
   between product fields, description mentions, and version notes. Do not call
   the catalogue associations attack paths or infer affectedness from a condition.
6. Copy [the findings template](findings.yaml), fill it from actual recorded calls,
   and check it using the Skill's session contract section.
   Finish with Answer, Evidence, What is not established, and Next steps. Cite only
   actual calls/anchors. Report the check outcome and its support limitation.
