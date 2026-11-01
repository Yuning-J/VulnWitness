"""CLI arguments and presentation for the reusable triage workflow."""

import argparse
from pathlib import Path

from vulnwitness.application.triage_workflow import plan_triage_calls
from vulnwitness.domain.product_query import ProductQueryRequest
from vulnwitness.domain.session_record import SessionCheckReport
from vulnwitness.domain.triage import TriageLimits, TriageSummary


def add_triage_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--vendor")
    parser.add_argument("--product")
    parser.add_argument("--version")
    parser.add_argument("--session", type=Path, required=True, metavar="DIR")
    parser.add_argument("--session-call-limit", type=int, choices=range(1, 101), metavar="1..100")
    parser.add_argument("--session-goal")
    parser.add_argument("--session-scope")
    parser.add_argument("--max-pages", type=int, default=20)
    parser.add_argument("--lookups", type=int, default=5)
    parser.add_argument("--time-limit", type=float, default=120)
    parser.add_argument("--limit", type=int, default=10, help="product page size (1..20)")
    parser.add_argument("--select", action="append", default=[], metavar="CVE-ID")
    parser.add_argument("--format", choices=("text", "json"), default="text")


def build_triage_plan(arguments: argparse.Namespace) -> tuple[ProductQueryRequest, TriageLimits]:
    request = ProductQueryRequest(
        vendor=arguments.vendor,
        product=arguments.product,
        version=arguments.version,
        limit=arguments.limit,
    )
    limits = TriageLimits(
        max_pages=arguments.max_pages,
        lookups=arguments.lookups,
        time_limit=arguments.time_limit,
        call_limit=arguments.session_call_limit or 100,
    )
    plan_triage_calls(request, tuple(arguments.select), limits)
    return request, limits


def render_triage_summary(summary: TriageSummary, check: SessionCheckReport) -> str:
    inventory = summary.inventory
    deep_dive = summary.deep_dive
    lines = [
        f"Triage outcome: {summary.stop_reason}",
        f"Inventory: {inventory.pages_read} pages read; {inventory.items_seen} items seen; "
        f"total_available={inventory.total_available}; traversal "
        f"{'finished' if inventory.complete else 'unfinished'}.",
        f"Deep dive: {deep_dive.lookups_completed} looked up: "
        f"{', '.join(deep_dive.looked_up_ids) or '(none)'}.",
        f"Selection: {deep_dive.selection_mode} (N={len(deep_dive.selected_ids)}).",
        f"Order: {deep_dive.selection_rule}.",
        f"Caps hit: {', '.join(summary.caps_hit) or '(none)'}.",
    ]
    if summary.failure_code is not None:
        lines.append(f"Recorded failure: {summary.failure_code.value}.")
    if summary.stop_reason == "time_limit":
        lines.append("Time limit reached; stopped early after the last admitted call.")
    if summary.stop_reason == "invalid_selection":
        lines.append("Refused selection: every --select ID must be in the inventoried pages.")
    lines.append(f"Remaining planned steps: {'; '.join(summary.remaining_steps) or '(none)'}.")
    lines.append("Artifacts: findings.yaml (workflow, unconfirmed) and triage.json.")
    layers_pass = check.record.consistent and check.citations.resolved and check.claims.verified
    lines.append(
        f"Session check: {'passed' if layers_pass else 'failed'}; "
        f"{check.record.calls_checked} calls; {len(check.claims.checks)} claims."
    )
    lines.append(check.support_limitation)
    return "\n".join(lines)
