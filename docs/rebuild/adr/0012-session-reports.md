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
rendered report and cause exit 1; there is no aggregate passed badge.

A typed format-independent document in the domain holds the report sections. The application
builds those sections; separate interface renderers escape their text for HTML and Markdown.
The HTML template is package data with inline CSS, dark-mode and print styles, and no
JavaScript or external resources. Recorded URIs are displayed as text. Session timestamps
and stable record order make repeated rendering byte-identical. The metadata contract has
goal and scope but no separate question field, so the header says that question is not
separately recorded rather than inferring one from later calls.

CVE tables use only responses cited by findings. Weakness paths use recorded lookups and
retain the derived-catalogue association limitation. Optional triage.json is displayed only
as unchecked workflow scope metadata, separating inventory and deep-dive scope without
making the report depend on a workflow summary or using it as evidence.

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
