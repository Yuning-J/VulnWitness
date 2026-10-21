"""Command-line interface over the offline search, topic-context and investigation
services, the verification of an evidence set handed back, and the MCP server over stdio.

Exit codes: 0 when the result status is ok (for ``verify``, when the verdict is
``verified``; for ``mcp``, when the client closes stdin), 1 for any other status or verdict,
for schema drift and for ``mcp`` without a usable server runner, 2 for invalid usage,
including invalid settings and a ``verify`` file that cannot be read or is larger than
``MAX_EVIDENCE_SET_FILE_BYTES``.
"""

import argparse
import json
import logging
import os
import re
import sys
from collections.abc import Mapping, Sequence
from enum import StrEnum
from pathlib import Path

from pydantic import ValidationError

from cve_kgrag.adapter_discovery import (
    InterfaceUnavailable,
    McpServerRunner,
    discover_mcp_server_runner,
    discover_planner_setup,
)
from cve_kgrag.adapters.fixture.synthetic_fixture import default_fixture_dir, load_fixture_bundle
from cve_kgrag.application.evidence_set_verification import verify_evidence_set
from cve_kgrag.application.investigation_deployment import InvestigationDeployment
from cve_kgrag.application.search import SearchService
from cve_kgrag.application.trajectory_replay import ReplayDifference, ReplayTimedOut
from cve_kgrag.composition import (
    build_investigation_deployment,
    build_investigation_service,
    build_knowledge_toolbox,
    build_search_service,
    build_topic_context_service,
    list_accepted_planner_capabilities,
)
from cve_kgrag.domain.cve import CVE_ID_PATTERN
from cve_kgrag.domain.investigation import (
    InvestigationRequest,
    KnowledgeEvidenceSet,
    SourceCapability,
)
from cve_kgrag.domain.search import (
    MAX_FILTER_VALUES,
    MAX_RESULTS_PER_CALL,
    SearchFilters,
    SearchRequest,
    SearchResponse,
)
from cve_kgrag.domain.taxonomy import ResultStatus
from cve_kgrag.domain.topic_context import QueryScope, TopicContextRequest, TopicContextResponse
from cve_kgrag.domain.validation import EvidenceValidationError
from cve_kgrag.schema_snapshots import find_schema_drift, write_contract_schemas
from cve_kgrag.settings import SemanticSettings, ServiceSettings, SettingsError, load_settings

DEMO_QUERIES = (
    "CVE-9999-0003",
    "5G-AKA resynchronization crash",
    "demo_gateway injection",
    "CVE-9999-4242",
    "5gaka",
)
DEFAULT_SCHEMA_DIR = Path("schemas/v2")
SEMANTIC_HELP = (
    "also run the semantic channel, which CVE_KGRAG_SEMANTIC_ENABLED enables; only with "
    "this flag is its adapter loaded"
)
# Logged when `mcp` or `verify` runs with the semantic channel enabled: neither serves it,
# since its store cannot be opened read-only (ADR 0004 §1).
SEMANTIC_NOT_SERVED = "the semantic channel is not served by cve-kgrag %s"
# Product-context options of `investigate` and the filter field each one fills.
PRODUCT_OPTIONS = (("--vendor", "vendors"), ("--product", "products"), ("--purl", "purls"))
# `verify` reads at most this many bytes of the file it is handed, and refuses a larger one.
MAX_EVIDENCE_SET_FILE_BYTES = 4 * 1024 * 1024
OVERSIZED_EVIDENCE_SET_MESSAGE = (
    f"the evidence set file is larger than {MAX_EVIDENCE_SET_FILE_BYTES // (1024 * 1024)} MiB"
)
# `verify` reports at most this many violations.
MAX_REPORTED_VIOLATIONS = 100


class VerificationVerdict(StrEnum):
    """What `verify` found: the set parsed (``malformed`` when not); passed the validator and
    the decision-path audit, and its replay passed the checks the controller runs at seal
    (``invalid`` when not); and replayed to the recorded set (``replay_differs`` or
    ``replay_timed_out`` when not)."""

    VERIFIED = "verified"
    MALFORMED = "malformed"
    INVALID = "invalid"
    REPLAY_DIFFERS = "replay_differs"
    REPLAY_TIMED_OUT = "replay_timed_out"


def parse_cve_id(text: str) -> str:
    cve_id = text.strip().upper()
    if not re.fullmatch(CVE_ID_PATTERN, cve_id):
        raise argparse.ArgumentTypeError(f"not a CVE ID: {text!r}")
    return cve_id


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cve-kgrag", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("demo", help="run sample queries against the bundled synthetic fixture")

    search_parser = commands.add_parser("search", help="search the fixture; prints JSON")
    search_parser.add_argument("query")
    search_parser.add_argument("--semantic", action="store_true", help=SEMANTIC_HELP)
    search_parser.add_argument(
        "--limit",
        type=int,
        default=10,
        choices=range(1, MAX_RESULTS_PER_CALL + 1),
        metavar=f"1..{MAX_RESULTS_PER_CALL}",
    )

    topic_parser = commands.add_parser(
        "topic", help="resolve a protocol topic and gather scoped context; prints JSON"
    )
    topic_parser.add_argument("query")
    topic_parser.add_argument("--scope", required=True, choices=list(QueryScope))
    topic_parser.add_argument("--semantic", action="store_true", help=SEMANTIC_HELP)
    topic_parser.add_argument(
        "--limit",
        type=int,
        default=10,
        choices=range(1, MAX_RESULTS_PER_CALL + 1),
        metavar=f"1..{MAX_RESULTS_PER_CALL}",
    )

    investigate_parser = commands.add_parser(
        "investigate",
        help=(
            "run a bounded, evidence-grounded investigation with the planner the settings "
            "configure; prints JSON"
        ),
    )
    investigate_parser.add_argument("query")
    investigate_parser.add_argument("--scope", required=True, choices=list(QueryScope))
    investigate_parser.add_argument("--semantic", action="store_true", help=SEMANTIC_HELP)
    for product_option, product_field in PRODUCT_OPTIONS:
        investigate_parser.add_argument(
            product_option,
            action="append",
            default=[],
            dest=product_field,
            help=f"product context; repeat for up to {MAX_FILTER_VALUES} values",
        )

    lookup_parser = commands.add_parser("lookup", help="exact CVE-ID lookup; prints JSON")
    lookup_parser.add_argument("cve_id", type=parse_cve_id)

    verify_parser = commands.add_parser(
        "verify",
        help=(
            "validate, audit and replay a knowledge evidence set read from FILE against the "
            "packaged fixture and the planners the settings configure; prints JSON"
        ),
    )
    verify_parser.add_argument("evidence_set_path", metavar="FILE", type=Path)

    commands.add_parser(
        "mcp",
        help=(
            "serve the knowledge tools over MCP on stdio, over the packaged fixture and the "
            "deterministic planner; needs the 'mcp' extra"
        ),
    )

    schema_parser = commands.add_parser("schema", help="export or check v2 JSON Schema snapshots")
    schema_parser.add_argument("action", choices=("export", "check"))
    schema_parser.add_argument("--dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    return parser


def build_investigation_request(
    parser: argparse.ArgumentParser, arguments: argparse.Namespace
) -> InvestigationRequest:
    """The request, or a usage error (exit 2) naming what the contract rejected."""
    try:
        return InvestigationRequest(
            query=arguments.query,
            scope=QueryScope(arguments.scope),
            filters=SearchFilters(
                vendors=arguments.vendors, products=arguments.products, purls=arguments.purls
            ),
            semantic=arguments.semantic,
        )
    except ValidationError as error:
        parser.error("; ".join(list_validation_problems(error)))


def list_validation_problems(error: ValidationError) -> list[str]:
    """Each problem the contract found, as ``location: message`` (only the message for the
    document as a whole), without the rejected input."""
    problems: list[str] = []
    for problem in error.errors():
        location = ".".join(str(part) for part in problem["loc"])
        if location:
            problems.append(f"{location}: {problem['msg']}")
        else:
            problems.append(problem["msg"])
    return problems


def print_response(response: SearchResponse | TopicContextResponse | KnowledgeEvidenceSet) -> int:
    print(response.model_dump_json(indent=2))
    return 0 if response.status is ResultStatus.OK else 1


def summarize(response: SearchResponse) -> dict[str, object]:
    top_candidates: list[dict[str, object]] = []
    for candidate in response.candidates[:3]:
        channels: list[str] = []
        for channel_hit in candidate.channel_hits:
            channels.append(channel_hit.channel.value)
        top_candidates.append(
            {
                "rank": candidate.rank,
                "cve_id": candidate.record.cve_id,
                "relevance_score": candidate.relevance_score,
                "channels": channels,
                "scope": candidate.scope_assessment.scope.value,
            }
        )
    channels_executed: list[str] = []
    for channel in response.channels_executed:
        channels_executed.append(channel.value)
    warnings: list[str] = []
    for warning in response.warnings:
        warnings.append(f"{warning.code.value}:{warning.subject}")
    return {
        "query": response.query,
        "status": response.status.value,
        "channels_executed": channels_executed,
        "top_candidates": top_candidates,
        "warnings": warnings,
        "result_sha256": response.result_sha256,
    }


def run_demo(service: SearchService) -> int:
    for query in DEMO_QUERIES:
        response = service.search(SearchRequest(query=query, limit=5))
        print(json.dumps(summarize(response), indent=2))
    return 0


def read_evidence_set_file(parser: argparse.ArgumentParser, evidence_set_path: Path) -> bytes:
    """The file's bytes, or a usage error (exit 2) when it cannot be read or holds more than
    ``MAX_EVIDENCE_SET_FILE_BYTES``; never more than one byte past the cap is read."""
    try:
        with evidence_set_path.open("rb") as evidence_set_file:
            evidence_set_bytes = evidence_set_file.read(MAX_EVIDENCE_SET_FILE_BYTES + 1)
    except OSError as error:
        parser.error(f"cannot read {evidence_set_path}: {error.strerror}")
    if len(evidence_set_bytes) > MAX_EVIDENCE_SET_FILE_BYTES:
        parser.error(OVERSIZED_EVIDENCE_SET_MESSAGE)
    return evidence_set_bytes


def print_verification(
    verdict: VerificationVerdict,
    violations: Sequence[str],
    differences: Sequence[ReplayDifference],
) -> int:
    """Print the verdict, at most ``MAX_REPORTED_VIOLATIONS`` violations and every replay
    difference as JSON; 0 only for ``verified``."""
    reported_differences: list[dict[str, object]] = []
    for difference in differences:
        reported_differences.append({"step_index": difference.step_index, "part": difference.part})
    verification_report = {
        "verdict": verdict.value,
        "violations": list(violations[:MAX_REPORTED_VIOLATIONS]),
        "differences": reported_differences,
    }
    print(json.dumps(verification_report, indent=2))
    return 0 if verdict is VerificationVerdict.VERIFIED else 1


def run_verify(
    evidence_set_bytes: bytes,
    deployment: InvestigationDeployment,
    accepted_planner_capabilities: Sequence[SourceCapability],
) -> int:
    """Parse the set, then verify it against ``deployment`` and the
    ``accepted_planner_capabilities`` (``verify_evidence_set``)."""
    try:
        evidence_set = KnowledgeEvidenceSet.model_validate_json(evidence_set_bytes)
    except ValidationError as error:
        return print_verification(
            VerificationVerdict.MALFORMED, list_validation_problems(error), ()
        )
    try:
        replay_outcome = verify_evidence_set(
            evidence_set, deployment, accepted_planner_capabilities
        )
    except EvidenceValidationError as error:
        return print_verification(VerificationVerdict.INVALID, error.violations, ())
    if isinstance(replay_outcome, ReplayTimedOut):
        return print_verification(VerificationVerdict.REPLAY_TIMED_OUT, (), ())
    if replay_outcome.differences:
        return print_verification(
            VerificationVerdict.REPLAY_DIFFERS, (), replay_outcome.differences
        )
    return print_verification(VerificationVerdict.VERIFIED, (), ())


def run_mcp_server(runner: McpServerRunner | InterfaceUnavailable) -> int:
    """Serve the packaged fixture's knowledge tools with ``runner`` until the client closes
    stdin; 1 when there is no usable runner, with one line on stderr naming why: the
    missing ``mcp`` extra, or the reason the runner is unusable. Writes nothing to stdout,
    which carries the protocol. The tools are read-only, so they serve no semantic channel:
    its store cannot be opened read-only."""
    if isinstance(runner, InterfaceUnavailable):
        print(f"cve-kgrag mcp cannot start: {runner.detail}", file=sys.stderr)
        return 1
    runner(build_knowledge_toolbox(load_fixture_bundle(default_fixture_dir())))
    return 0


def choose_semantic_settings(
    settings: ServiceSettings, arguments: argparse.Namespace
) -> SemanticSettings | None:
    """The semantic settings a ``search``, ``topic`` or ``investigate`` command loads: the
    configured ones only when it was run with ``--semantic``, so no other run opens the
    semantic store."""
    if arguments.semantic:
        return settings.semantic
    return None


def run_schema_command(action: str, schema_dir: Path) -> int:
    if action == "export":
        write_contract_schemas(schema_dir)
        print(f"wrote schemas to {schema_dir}")
        return 0
    drift = find_schema_drift(schema_dir)
    for problem in drift:
        print(problem, file=sys.stderr)
    return 1 if drift else 0


def main(argv: Sequence[str] | None = None, environment: Mapping[str, str] | None = None) -> int:
    """Run the command ``argv`` names, with the settings ``environment`` holds (the process
    environment by default; ``cve_kgrag.settings``). Invalid settings are a usage error."""
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        settings = load_settings(os.environ if environment is None else environment)
    except SettingsError as error:
        parser.error(str(error))
    if arguments.command == "schema":
        return run_schema_command(arguments.action, arguments.dir)
    if arguments.command == "mcp":
        logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
        if settings.semantic is not None:
            logging.getLogger(__name__).warning(SEMANTIC_NOT_SERVED, "mcp")
        return run_mcp_server(discover_mcp_server_runner())

    bundle = load_fixture_bundle(default_fixture_dir())
    if arguments.command == "verify":
        evidence_set_bytes = read_evidence_set_file(parser, arguments.evidence_set_path)
        if settings.semantic is not None:
            logging.getLogger(__name__).warning(SEMANTIC_NOT_SERVED, "verify")
        return run_verify(
            evidence_set_bytes,
            build_investigation_deployment(bundle),
            list_accepted_planner_capabilities(settings.model_planner),
        )
    if arguments.command == "investigate":
        investigation_request = build_investigation_request(parser, arguments)
        investigation_service = build_investigation_service(
            bundle,
            semantic_settings=choose_semantic_settings(settings, arguments),
            planner_setup=discover_planner_setup(settings.model_planner),
        )
        return print_response(investigation_service.investigate(investigation_request))
    if arguments.command == "topic":
        topic_request = TopicContextRequest(
            query=arguments.query,
            scope=QueryScope(arguments.scope),
            limit=arguments.limit,
            semantic=arguments.semantic,
        )
        topic_context_service = build_topic_context_service(
            bundle, semantic_settings=choose_semantic_settings(settings, arguments)
        )
        return print_response(topic_context_service.explore(topic_request))
    if arguments.command == "demo":
        return run_demo(build_search_service(bundle))
    if arguments.command == "lookup":
        lookup_request = SearchRequest(query=arguments.cve_id, limit=1)
        return print_response(build_search_service(bundle).search(lookup_request))
    service = build_search_service(bundle, choose_semantic_settings(settings, arguments))
    return print_response(
        service.search(
            SearchRequest(query=arguments.query, limit=arguments.limit, semantic=arguments.semantic)
        )
    )


if __name__ == "__main__":
    sys.exit(main())
