# ADR 0012: Session reports

Status: accepted

## Decision

`vulnwitness report DIR` renders Markdown or a single self-contained HTML file from any
session, including manual CLI, MCP and workflow sessions. This is a separate ADR because
presentation and output-file policy are independent of ADR 0010's recording contract.
It introduces no session or service contract change.

The report contains only recorded content plus the existing session check results.
The checker exposes the same parsed metadata, calls, responses and findings that it checked;
the report does not reread those files, retrieve evidence, load a store or call a service.
Invalid files remain checker violations and are not rendered as valid findings or responses.
An unreadable session.json refuses rendering. Other layer failures remain visible in a
rendered report and cause exit 1. Status pills and check-layer marks come from the actual
checker verdicts; an aggregate consistency pill appears only when all checked layers pass.

A typed format-independent document in the domain holds the report sections. The application
builds those sections; separate interface renderers escape their text for HTML and Markdown.
The HTML template is package data with inline CSS, dark-mode and print styles, and no
JavaScript or external resources. Recorded URIs are displayed as text. Session timestamps
and stable record order make repeated rendering byte-identical. The title uses the triage
product and version, or the manual session goal/name.

The report orders overview, key facts and limits, CVE details, read inventory, execution
and checks, and a folded technical appendix. CVE cards use recorded lookups; the inventory
uses all recorded product pages. Full descriptions, original association hops, inheritance,
terminal reasons, source identities and the full check JSON remain available. The same CVSS
selection policy supplies severity in both cards and inventory, including the recorded scorer.
Version-condition outcomes use neutral styling and never establish affectedness.

Optional triage.json supplies workflow scope and selection context only. Counts come from
recorded responses, and the workflow artifact cannot change checker verdicts. Missing or
invalid workflow metadata does not prevent manual session reporting. Dark-mode styles and
print styles share variables; print explicitly selects the light palette and expands details.

## Trust and output

Record consistency, citation resolution and structured field agreement retain their distinct
meanings. A verified claim does not establish source support or real-world truth. Model and
analyst findings appear under “Not checked: narrative”, irrespective of authored status.
The report does not establish narrative support, completeness or deployment affectedness.

Output defaults to stdout. An explicit file is published atomically with mode 0600;
no-clobber publication refuses existing files unless --force was supplied. Writes inside the
session are limited to explicit DIR/report.* files, preserving the recorded artifacts.
Symlink outputs are refused. No current timestamp or report artifact is appended to the
session's call log.
