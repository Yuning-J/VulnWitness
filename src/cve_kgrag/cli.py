"""Command-line interface over the offline search, topic-context and investigation
services, the knowledge lookups (capabilities, topic resolution, affectedness, evidence),
the verification of an evidence set handed back, the MCP server over stdio or, with
``--http``, over Streamable HTTP, the v2 REST API, both HTTP servers on a loopback
address, the local planner evaluation (``eval planner``), the legacy-data importer
(``migrate legacy``) and the corpus store operations (``store``).

The serving commands serve the served corpus: the store ``CVE_KGRAG_STORE_ROOT``'s
``ACTIVE`` names, or the packaged synthetic fixture when no root is configured
(ADR 0009 §9, §10). Loading a configured store is announced on stderr, and once more when
its data is loaded, so stdout carries only a command's JSON or the MCP protocol.

Exit codes: 0 when the answer is a full one: result status ok, the verdict ``verified``,
a query that resolves to a topic, an evidence ID the catalogue serves, every
affectedness answer established, capabilities always, a product query with matches,
an ``eval planner`` run that wrote
its results, a ``migrate legacy`` run that imported, found its import done or completed
a dry run, a ``store`` operation that succeeded (for ``status``, a readable ``ACTIVE``
whose active store is ok), and for ``mcp`` the client closing stdin or, for
``mcp --http`` and ``api``, an interrupt (SIGINT; on SIGTERM the process ends by that signal).
1 for any other status, verdict or answer, for schema drift, for ``mcp`` or ``api``
without a usable server runner, for an HTTP server on a port it cannot bind, for model
runs whose enabled planner cannot plan, for evaluation results that cannot be written,
for an evaluation stopped before its report, for a failed import, for ``migrate legacy``
without the ``migration`` extra and for a failed ``store`` operation, named by its
reason code. 2 for invalid usage: an argument a contract rejects, a filter the served
dataset cannot execute (a ``--purl`` over records that name no package URL), invalid
settings, a ``store`` command without a store root or with a name that is no store name,
an HTTP server without a token, a configured store root or FiGHT snapshot that cannot be
served (one line naming the reason), model runs without an enabled planner, an
evaluation ``--out`` inside the package or the store root, an input manifest that is not
valid, a ``verify`` file that cannot be read or is larger than ``MAX_EVIDENCE_SET_BYTES``,
and a gold file that cannot be read or is no investigation gold file.
"""

import argparse
import json
import logging
import os
import re
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any, NoReturn, TypeVar
from xml.etree.ElementTree import ParseError

from pydantic import SecretStr, ValidationError

from cve_kgrag.adapter_discovery import (
    ApiServerRunner,
    InterfaceUnavailable,
    McpHttpServerRunner,
    McpServerRunner,
    discover_api_server_runner,
    discover_mcp_http_server_runner,
    discover_mcp_server_runner,
    discover_migration_parsers,
    discover_planner_setup,
)
from cve_kgrag.adapters.fight.operator_snapshot import FightSnapshotUnavailable
from cve_kgrag.adapters.migration.inputs_manifest import InputsManifestError, load_inputs_manifest
from cve_kgrag.adapters.migration.legacy_migration import (
    MigrationDependencies,
    MigrationRequest,
    run_migration,
)
from cve_kgrag.adapters.migration.migration_limits import MigrationLimits
from cve_kgrag.adapters.migration.parser_types import MigrationParsers
from cve_kgrag.adapters.mitre.catalogue_parser import (
    build_mapping_snapshot,
    serialize_mapping_snapshot,
)
from cve_kgrag.adapters.mitre.mapping_file import (
    MitreSnapshotUnavailable,
    load_weakness_mapping,
    write_mapping_file,
)
from cve_kgrag.adapters.regular_files import NotARegularFileError, open_regular_file
from cve_kgrag.adapters.store.store_activation import StoreActivation, describe_identity
from cve_kgrag.adapters.store.store_root import lies_in_store_root
from cve_kgrag.application.affectedness import check_affectedness
from cve_kgrag.application.evidence_set_verification import (
    MAX_EVIDENCE_SET_BYTES,
    check_evidence_set,
)
from cve_kgrag.application.investigate import describe_service_capabilities
from cve_kgrag.application.investigation_deployment import InvestigationDeployment
from cve_kgrag.application.knowledge_lookup import find_served_evidence, lookup_cve
from cve_kgrag.application.planner_setup import ModelPlanning
from cve_kgrag.application.search import SearchService
from cve_kgrag.application.serving_data_plane import ServingDataPlane
from cve_kgrag.composition import (
    assemble_topic_context_service,
    build_investigation_deployment,
    build_investigation_service,
    build_knowledge_toolbox,
    build_nvd_normalizer,
    build_product_query_service,
    build_search_service,
    build_serving_data_plane,
    build_store_activation,
    build_topic_registry,
    build_trustify_port,
    derive_gold_sets,
    list_accepted_planner_capabilities,
    load_fight_source,
    load_packaged_fixture,
    load_packaged_source_registry,
    load_served_corpus,
    utc_now,
)
from cve_kgrag.distribution import read_installed_version
from cve_kgrag.domain.affectedness import AffectednessRequest, ApplicabilityStatus
from cve_kgrag.domain.contract_model import ContractModel, list_validation_problems
from cve_kgrag.domain.corpus_store_manifest import name_corpus_store_version
from cve_kgrag.domain.cve import CVE_ID_PATTERN
from cve_kgrag.domain.evidence_set_verification_report import (
    VerificationReport,
    VerificationVerdict,
)
from cve_kgrag.domain.hashing import sha256_hex
from cve_kgrag.domain.investigation import InvestigationRequest, KnowledgeEvidenceSet
from cve_kgrag.domain.migration_inputs import MAX_MANIFEST_BYTES
from cve_kgrag.domain.migration_report import MigrationOutcome
from cve_kgrag.domain.product_query import ProductQueryRequest
from cve_kgrag.domain.product_query_cursor import InvalidProductCursor
from cve_kgrag.domain.search import (
    MAX_FILTER_VALUES,
    MAX_RESULTS_PER_CALL,
    SearchRequest,
    SearchResponse,
    UnsupportedFilter,
)
from cve_kgrag.domain.served_dataset import ServedDataset, ServedDatasetKind
from cve_kgrag.domain.store_status import (
    STORE_OPERATION_FAILURE_MESSAGES,
    ActiveStoreCondition,
    StoreOperationFailed,
    StoreStatus,
    StoreUnavailable,
    is_store_name,
)
from cve_kgrag.domain.taxonomy import ResultStatus
from cve_kgrag.domain.threat_context import KnownFightSnapshot
from cve_kgrag.domain.tool_contracts import (
    ConceptResolution,
    ConceptResolutionRequest,
    CveLookupRequest,
    EvidenceLookupRequest,
    KnowledgeCapabilities,
    ToolFailureCode,
)
from cve_kgrag.domain.topic_context import QueryScope, TopicContextRequest, TopicContextResponse
from cve_kgrag.domain.validation import EvidenceValidationError
from cve_kgrag.domain.weakness_mapping import WeaknessMapping
from cve_kgrag.evaluation.case_runner import (
    EvaluationStopped,
    ModelRuns,
    build_fixture_data_planes,
    describe_fixture_dataset,
)
from cve_kgrag.evaluation.gold_cases import (
    MAX_GOLD_FILE_BYTES,
    FightChoice,
    GoldCase,
    GoldFileError,
    read_gold_cases,
)
from cve_kgrag.evaluation.gold_formats import (
    GoldFormat,
    classify_gold_document,
    read_gold_document,
)
from cve_kgrag.evaluation.gold_sets import (
    MAX_GOLD_SETS_FILE_BYTES,
    RecordedSets,
    read_recorded_sets,
)
from cve_kgrag.evaluation.labelled_cases import GoldFile, read_gold_file
from cve_kgrag.evaluation.planner_report import DatasetIdentity, FightProfile, format_report
from cve_kgrag.evaluation.planner_runner import (
    MAX_MODEL_RUNS,
    REPORT_FILE_NAME,
    LabelledCases,
    read_source_revision,
    run_planner_evaluation,
)
from cve_kgrag.evaluation.result_directory import ResultDirectory
from cve_kgrag.interfaces.investigation_summary import render_investigation_summary
from cve_kgrag.interfaces.knowledge_toolbox import (
    UNSUPPORTED_FILTER_ERROR,
    KnowledgeToolbox,
    describe_knowledge_capabilities,
)
from cve_kgrag.interfaces.knowledge_tools import ToolLimits, build_tool_failure
from cve_kgrag.interfaces.product_query_summary import render_product_query_summary
from cve_kgrag.ports.served_corpus import ServedCorpus
from cve_kgrag.ports.sources import FightSource
from cve_kgrag.schema_snapshots import find_schema_drift, write_contract_schemas
from cve_kgrag.settings import (
    HTTP_VARIABLES,
    PLANNER_ENABLED_VARIABLE,
    SERVED_DATA_VARIABLES,
    FightSnapshotSettings,
    HttpSettings,
    MitreSnapshotSettings,
    ModelPlannerSettings,
    SemanticSettings,
    ServiceSettings,
    SettingsError,
    find_section_variable,
    load_settings,
)

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
# Logged when `mcp`, `api` or `verify` runs with the semantic channel enabled: none serves
# it, since its Chroma collection cannot be opened read-only (ADR 0004 §1).
SEMANTIC_NOT_SERVED = "the semantic channel is not served by cve-kgrag %s"
# Filter options, each repeatable, with the `SearchFilters` field it fills and how its text
# is read. The product ones are also `investigate`'s product context.
PRODUCT_OPTIONS = (
    ("--vendor", "vendors", str),
    ("--product", "products", str),
    ("--purl", "purls", str),
)
RECORD_FILTER_OPTIONS = (
    ("--cwe", "cwe_ids", str.upper),
    ("--severity", "severities", str.upper),
    ("--year", "published_years", int),
    ("--origin", "origins", str),
)
# `investigate`'s budget options and the `InvestigationBudget` field each one sets; an
# option left out keeps the budget's default.
BUDGET_OPTIONS = (
    ("--max-rounds", "max_rounds"),
    ("--max-tool-calls", "max_tool_calls"),
    ("--max-sources", "max_sources"),
    ("--max-results-per-call", "max_results_per_call"),
    ("--max-wall-time-seconds", "max_wall_time_seconds"),
    ("--max-context-bytes", "max_context_bytes"),
)
OVERSIZED_EVIDENCE_SET_MESSAGE = (
    f"the evidence set file is larger than {MAX_EVIDENCE_SET_BYTES // (1024 * 1024)} MiB"
)
HTTP_TOKEN_VARIABLE = find_section_variable(HTTP_VARIABLES, "token")
# The installed package directory, whose git checkout (if any) names the evaluated source.
PACKAGE_DIR = Path(__file__).resolve().parent
MODEL_RUNS_WITHOUT_A_PLANNER = (
    f"invalid settings: --model-runs needs the model planner enabled ({PLANNER_ENABLED_VARIABLE})"
)
OUT_INSIDE_THE_PACKAGE = "--out must not lie inside the installed cve_kgrag package"
# A result directory inside a store makes the reader refuse that store.
OUT_INSIDE_THE_STORE_ROOT = "--out must not lie inside the store root"
STORE_ROOT_VARIABLE = find_section_variable(SERVED_DATA_VARIABLES, "store_root")
FIGHT_SNAPSHOT_PATH_VARIABLE = find_section_variable(SERVED_DATA_VARIABLES, "fight_snapshot_path")
STORE_ROOT_REQUIRED = f"invalid settings: {STORE_ROOT_VARIABLE}: required by store"
SETS_WITHOUT_LABELLED_CASES = "--sets is for a gold file of labelled cases (M7b)"
LABELLED_CASES_WITHOUT_SETS = (
    "a gold file of labelled cases needs --sets, the sets file derived from it"
)
EVAL_NEEDS_A_STORE_ROOT = (
    f"invalid settings: {STORE_ROOT_VARIABLE}: required by eval planner for labelled "
    "cases, which run on the active store"
)
EVAL_NEEDS_A_FIGHT_SNAPSHOT = (
    "invalid settings: eval planner runs labelled cases on the operator FiGHT snapshot, "
    f"which {FIGHT_SNAPSHOT_PATH_VARIABLE} configures"
)
GOLD_SETS_NEED_LABELLED_CASES = "eval gold-sets reads a gold file of labelled cases (M7b)"
GOLD_SETS_NEED_A_STORE_ROOT = (
    f"invalid settings: {STORE_ROOT_VARIABLE}: required by eval gold-sets, which reads the "
    "active store"
)
GOLD_SETS_NEED_A_FIGHT_SNAPSHOT = (
    "invalid settings: eval gold-sets reads the operator FiGHT snapshot, which "
    f"{FIGHT_SNAPSHOT_PATH_VARIABLE} configures"
)
# Written once per run of the commands fixed to the fixture, whatever the settings: their
# gold cases and demo queries name fixture CVEs (ADR 0009 §10).
DEMO_FIXTURE_NOTICE = "cve-kgrag demo uses the packaged synthetic fixture, not the store root"
EVAL_FIXTURE_NOTICE = (
    "cve-kgrag eval planner runs investigation trajectories on the packaged synthetic "
    "fixture, not the store root, and the FiGHT source each gold case names, not a "
    "configured snapshot"
)
# Written to stderr, never stdout, around loading a configured store: stdout carries a
# command's JSON or the MCP protocol. A real NVD store takes minutes to load.
STORE_LOADING_NOTICE = (
    "cve-kgrag {command}: loading store {store_name}; a full NVD store takes minutes"
)
DATA_LOADED_NOTICE = "cve-kgrag {command}: {cve_search_version} data loaded after {seconds:.0f} s"
UNKNOWN_EVIDENCE_MESSAGE = "no evidence anchor is served under {evidence_id}"
UNSERVED_EVIDENCE_MESSAGE = (
    "the anchor catalogued under {evidence_id} fails the anchor rules, so it is not served"
)

ContractT = TypeVar("ContractT", bound=ContractModel)


def parse_cve_id(text: str) -> str:
    cve_id = text.strip().upper()
    if not re.fullmatch(CVE_ID_PATTERN, cve_id):
        raise argparse.ArgumentTypeError(f"not a CVE ID: {text!r}")
    return cve_id


def parse_store_name(text: str) -> str:
    if not is_store_name(text):
        raise argparse.ArgumentTypeError(
            "not a store name: one path component of letters, digits, '.', '_' and '-', "
            "starting with a letter or digit, at most 64 characters, and not ACTIVE"
        )
    return text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cve-kgrag", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    mitre_parser = commands.add_parser("mitre", help="build an offline catalogue mapping")
    mitre_commands = mitre_parser.add_subparsers(dest="mitre_command", required=True)
    mitre_build_parser = mitre_commands.add_parser(
        "build", help="derive catalogue links and marked CWE hierarchy inferences"
    )
    for source_name in ("cwe", "capec", "attack"):
        mitre_build_parser.add_argument("--" + source_name, type=Path, required=True)
    mitre_build_parser.add_argument("--out", type=Path, required=True)
    mitre_build_parser.add_argument(
        "--cwe-id", action="append", default=[], help="select CWE IDs for an excerpt"
    )

    commands.add_parser("demo", help="run sample queries against the bundled synthetic fixture")

    search_parser = commands.add_parser("search", help="search the served CVE records; prints JSON")
    search_parser.add_argument("query")
    search_parser.add_argument("--semantic", action="store_true", help=SEMANTIC_HELP)
    add_result_limit_option(search_parser, "--limit")
    add_filter_options(search_parser, (*PRODUCT_OPTIONS, *RECORD_FILTER_OPTIONS))
    search_parser.add_argument(
        "--kev-only", action="store_true", help="only records listed as known exploited"
    )
    search_parser.add_argument(
        "--graph-expand",
        action="store_true",
        help="also add the records the relation graph links to the matches",
    )

    topic_parser = commands.add_parser(
        "topic", help="resolve a protocol topic and gather scoped context; prints JSON"
    )
    topic_parser.add_argument("query")
    topic_parser.add_argument("--scope", required=True, choices=list(QueryScope))
    topic_parser.add_argument("--semantic", action="store_true", help=SEMANTIC_HELP)
    add_result_limit_option(topic_parser, "--limit")
    add_result_limit_option(
        topic_parser,
        "--max-results-per-search",
        default=MAX_RESULTS_PER_CALL,
        help_text="results each CVE search and the FiGHT search may return",
    )

    investigate_parser = commands.add_parser(
        "investigate",
        help=(
            "run a bounded, evidence-grounded investigation with the planner the settings "
            "configure; prints JSON or a text summary"
        ),
    )
    investigate_parser.add_argument("query")
    investigate_parser.add_argument("--scope", required=True, choices=list(QueryScope))
    investigate_parser.add_argument("--format", choices=("json", "text"), default="json")
    investigate_parser.add_argument("--semantic", action="store_true", help=SEMANTIC_HELP)
    add_filter_options(investigate_parser, PRODUCT_OPTIONS)
    for budget_option, budget_field in BUDGET_OPTIONS:
        investigate_parser.add_argument(
            budget_option,
            type=int,
            dest=budget_field,
            help="investigation budget; defaults to the cap the contract allows",
        )

    lookup_parser = commands.add_parser("lookup", help="exact CVE-ID lookup; prints JSON")
    lookup_parser.add_argument("cve_id", type=parse_cve_id)

    product_parser = commands.add_parser(
        "product", help="CVEs for explicit vendor/product names, with optional version notes"
    )
    product_parser.add_argument("--vendor")
    product_parser.add_argument("--product")
    product_parser.add_argument("--version")
    product_parser.add_argument("--cursor", help="continuation from the preceding product page")
    product_parser.add_argument("--format", choices=("json", "text"), default="json")
    add_result_limit_option(product_parser, "--limit")

    capabilities_parser = commands.add_parser(
        "capabilities",
        help="the sources `investigate` would use and what each serves; prints JSON",
    )
    capabilities_parser.add_argument("--semantic", action="store_true", help=SEMANTIC_HELP)

    resolve_parser = commands.add_parser(
        "resolve", help="resolve a query to the reviewed protocol topics; prints JSON"
    )
    resolve_parser.add_argument("query")

    affectedness_parser = commands.add_parser(
        "affectedness",
        help="whether a package version is affected by each CVE; prints a JSON list",
    )
    affectedness_parser.add_argument("cve_ids", metavar="CVE_ID", nargs="+", type=parse_cve_id)
    affectedness_parser.add_argument(
        "--purl", required=True, help="the package and version, as a versioned package URL"
    )

    evidence_parser = commands.add_parser(
        "evidence", help="the evidence anchor served under an evidence ID; prints JSON"
    )
    evidence_parser.add_argument("evidence_id")

    verify_parser = commands.add_parser(
        "verify",
        help=(
            "validate, audit and replay a knowledge evidence set read from FILE against the "
            "served CVE records and the planners the settings configure; prints JSON"
        ),
    )
    verify_parser.add_argument("evidence_set_path", metavar="FILE", type=Path)

    mcp_parser = commands.add_parser(
        "mcp",
        help=(
            "serve the knowledge tools over MCP on stdio, over the served CVE records and the "
            "deterministic planner; needs the 'mcp' extra"
        ),
    )
    mcp_parser.add_argument(
        "--http",
        action="store_true",
        help=(
            "serve over Streamable HTTP instead, on the loopback host and port the "
            "CVE_KGRAG_HTTP_HOST and CVE_KGRAG_MCP_HTTP_PORT settings name, every route but "
            "/health behind the CVE_KGRAG_HTTP_TOKEN bearer token; runs until interrupted"
        ),
    )

    commands.add_parser(
        "api",
        help=(
            "serve the v2 REST API on the loopback host and port the CVE_KGRAG_HTTP_HOST and "
            "CVE_KGRAG_API_PORT settings name, every route but /health behind the "
            "CVE_KGRAG_HTTP_TOKEN bearer token, over the served CVE records and the "
            "deterministic planner; runs until interrupted; needs the 'api' extra"
        ),
    )

    eval_parser = commands.add_parser(
        "eval", help="local evaluation tools for reviewers and operators, served by no API"
    )
    eval_commands = eval_parser.add_subparsers(dest="eval_command", required=True)
    planner_eval_parser = eval_commands.add_parser(
        "planner",
        help=(
            "run each gold investigation case with the deterministic policy and, with "
            "--model-runs, the model planner the settings enable; writes every evidence set "
            "and a report of counts, codes and hashes to a new directory and prints the report"
        ),
    )
    planner_eval_parser.add_argument(
        "--gold",
        required=True,
        type=Path,
        help="an investigation gold file, such as eval/gold/m4_trajectories.yaml",
    )
    planner_eval_parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help=(
            "the directory, such as eval-results, to create a new owner-only planner-* "
            "result directory in; its evidence sets hold the queries and the model's plan "
            "text, so never commit them"
        ),
    )
    planner_eval_parser.add_argument(
        "--sets",
        type=Path,
        metavar="SETS_FILE",
        help=(
            "the sets file eval gold-sets wrote for a gold file of labelled cases, such as "
            "eval/gold/m7b_sets.json; required with one, refused otherwise"
        ),
    )
    planner_eval_parser.add_argument(
        "--model-runs",
        type=int,
        default=0,
        choices=range(MAX_MODEL_RUNS + 1),
        metavar=f"0..{MAX_MODEL_RUNS}",
        help=(
            "runs per case with the model planner, which calls its endpoint; 0, the "
            "default, runs the deterministic baseline alone and calls no endpoint"
        ),
    )

    gold_sets_parser = eval_commands.add_parser(
        "gold-sets",
        help=(
            "derive each M7b gold case's sets from its rules over the active store and the "
            "operator FiGHT snapshot, and print them as JSON; with --check, compare them "
            "with a recorded sets file instead"
        ),
    )
    gold_sets_parser.add_argument(
        "--gold",
        required=True,
        type=Path,
        help="an M7b gold file, such as eval/gold/m7b_cases.yaml",
    )
    gold_sets_parser.add_argument(
        "--check",
        type=Path,
        metavar="SETS_FILE",
        help="a recorded sets file, such as eval/gold/m7b_sets.json, to compare with",
    )

    migrate_parser = commands.add_parser(
        "migrate", help="import legacy data into a new corpus store (ADR 0008)"
    )
    migrate_commands = migrate_parser.add_subparsers(dest="migrate_command", required=True)
    legacy_parser = migrate_commands.add_parser(
        "legacy",
        help=(
            "import the raw NVD feeds and the CISA KEV catalog an input manifest declares "
            "into a new, verified corpus store; prints the migration report as JSON; needs "
            "the 'migration' extra"
        ),
    )
    legacy_parser.add_argument(
        "--inputs",
        required=True,
        type=Path,
        help="the input manifest: each input's source, path and retrieval time",
    )
    legacy_parser.add_argument(
        "--target",
        required=True,
        type=Path,
        help="the store directory to create; an existing one is never overwritten",
    )
    legacy_parser.add_argument(
        "--legacy-root",
        type=Path,
        help=(
            "a legacy data tree to walk read-only, reporting the derived files and the "
            "files never deserialized that it holds; the target must lie outside it"
        ),
    )
    legacy_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="read and check everything a real run would, then write no store",
    )

    store_parser = commands.add_parser(
        "store",
        help=(
            "validate, activate and roll back the corpus stores under CVE_KGRAG_STORE_ROOT, "
            "and report them (ADR 0009)"
        ),
    )
    store_commands = store_parser.add_subparsers(dest="store_command", required=True)
    validate_parser = store_commands.add_parser(
        "validate",
        help="verify the store with this name under the root, changing nothing; prints its "
        "identity as JSON",
    )
    validate_parser.add_argument("name", type=parse_store_name)
    activate_parser = store_commands.add_parser(
        "activate",
        help=(
            "verify the store with this name and record it active, keeping the store active "
            "before it as the one to roll back to; prints the store status as JSON; servers "
            "serve it once restarted"
        ),
    )
    activate_parser.add_argument("name", type=parse_store_name)
    store_commands.add_parser(
        "rollback",
        help=(
            "make the store active before the current one active again, verified again; "
            "prints the store status as JSON; servers serve it once restarted"
        ),
    )
    store_commands.add_parser(
        "status",
        help=(
            "the active and previous stores, each checked and verified; prints the store "
            "status as JSON, and exits 1 unless the active store is ok"
        ),
    )

    schema_parser = commands.add_parser("schema", help="export or check v2 JSON Schema snapshots")
    schema_parser.add_argument("action", choices=("export", "check"))
    schema_parser.add_argument("--dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    return parser


def add_result_limit_option(
    parser: argparse.ArgumentParser,
    option: str,
    default: int = 10,
    help_text: str | None = None,
) -> None:
    parser.add_argument(
        option,
        type=int,
        default=default,
        choices=range(1, MAX_RESULTS_PER_CALL + 1),
        metavar=f"1..{MAX_RESULTS_PER_CALL}",
        help=help_text,
    )


def add_filter_options(
    parser: argparse.ArgumentParser, filter_options: Sequence[tuple[str, str, Any]]
) -> None:
    for filter_option, filter_field, read_value in filter_options:
        parser.add_argument(
            filter_option,
            action="append",
            default=[],
            dest=filter_field,
            type=read_value,
            help=f"repeat for up to {MAX_FILTER_VALUES} values; any of them matches",
        )


def collect_filters(
    arguments: argparse.Namespace, filter_options: Sequence[tuple[str, str, Any]]
) -> dict[str, object]:
    """The ``SearchFilters`` fields the given filter options were set for."""
    filters: dict[str, object] = {}
    for _, filter_field, _ in filter_options:
        values = getattr(arguments, filter_field)
        if values:
            filters[filter_field] = values
    return filters


def collect_budget(arguments: argparse.Namespace) -> dict[str, int]:
    """The ``InvestigationBudget`` fields the budget options were set for."""
    budget: dict[str, int] = {}
    for _, budget_field in BUDGET_OPTIONS:
        value = getattr(arguments, budget_field)
        if value is not None:
            budget[budget_field] = value
    return budget


def build_contract(
    parser: argparse.ArgumentParser, contract_type: type[ContractT], **fields: object
) -> ContractT:
    """The contract built from the command's arguments, or a usage error (exit 2) naming
    each problem the contract found, without the rejected input."""
    try:
        return contract_type.model_validate(fields)
    except ValidationError as error:
        parser.error("; ".join(list_validation_problems(error)))


def build_search_request(
    parser: argparse.ArgumentParser, arguments: argparse.Namespace
) -> SearchRequest:
    filters = collect_filters(arguments, (*PRODUCT_OPTIONS, *RECORD_FILTER_OPTIONS))
    if arguments.kev_only:
        filters["kev_only"] = True
    return build_contract(
        parser,
        SearchRequest,
        query=arguments.query,
        limit=arguments.limit,
        filters=filters,
        graph_expand=arguments.graph_expand,
        semantic=arguments.semantic,
    )


def build_investigation_request(
    parser: argparse.ArgumentParser, arguments: argparse.Namespace
) -> InvestigationRequest:
    return build_contract(
        parser,
        InvestigationRequest,
        query=arguments.query,
        scope=arguments.scope,
        filters=collect_filters(arguments, PRODUCT_OPTIONS),
        semantic=arguments.semantic,
        budget=collect_budget(arguments),
    )


def print_response(response: SearchResponse | TopicContextResponse | KnowledgeEvidenceSet) -> int:
    print(response.model_dump_json(indent=2))
    return 0 if response.status is ResultStatus.OK else 1


def print_investigation(evidence_set: KnowledgeEvidenceSet, output_format: str) -> int:
    if output_format == "text":
        print(render_investigation_summary(evidence_set))
        return 0 if evidence_set.status is ResultStatus.OK else 1
    return print_response(evidence_set)


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


def read_input_file(parser: argparse.ArgumentParser, input_path: Path, max_bytes: int) -> bytes:
    """At most ``max_bytes`` + 1 bytes of the file, so a caller can tell it is over the cap
    without reading it all, or a usage error (exit 2) when it cannot be read."""
    try:
        with input_path.open("rb") as input_file:
            return input_file.read(max_bytes + 1)
    except OSError as error:
        parser.error(f"cannot read {input_path}: {error.strerror}")


def read_inputs_manifest_file(parser: argparse.ArgumentParser, manifest_path: Path) -> bytes:
    """At most ``MAX_MANIFEST_BYTES`` + 1 bytes of the input manifest, opened like every
    file the importer reads: refused unless it is a regular file, never following a
    symbolic link and never waiting on a FIFO (``open_regular_file``). A manifest that
    cannot be read so is a usage error (exit 2)."""
    try:
        with open_regular_file(manifest_path) as manifest_stream:
            return manifest_stream.read(MAX_MANIFEST_BYTES + 1)
    except NotARegularFileError:
        parser.error(f"cannot read {manifest_path}: not a regular file")
    except OSError as error:
        parser.error(f"cannot read {manifest_path}: {error.strerror}")


def read_evidence_set_file(parser: argparse.ArgumentParser, evidence_set_path: Path) -> bytes:
    """The file's bytes, or a usage error (exit 2) when it cannot be read or holds more than
    ``MAX_EVIDENCE_SET_BYTES``."""
    evidence_set_bytes = read_input_file(parser, evidence_set_path, MAX_EVIDENCE_SET_BYTES)
    if len(evidence_set_bytes) > MAX_EVIDENCE_SET_BYTES:
        parser.error(OVERSIZED_EVIDENCE_SET_MESSAGE)
    return evidence_set_bytes


def print_verification(report: VerificationReport) -> int:
    """Print the report as JSON, its keys in the order the contract declares them; 0 only
    for ``verified``."""
    print(json.dumps(report.model_dump(mode="json"), indent=2))
    return 0 if report.verdict is VerificationVerdict.VERIFIED else 1


def print_capabilities(capabilities: KnowledgeCapabilities) -> int:
    print(capabilities.model_dump_json(indent=2))
    return 0


def print_resolution(resolution: ConceptResolution) -> int:
    """Print the resolution; 0 only when the query resolves to at least one topic."""
    print(resolution.model_dump_json(indent=2))
    return 0 if resolution.resolution.matches else 1


def run_affectedness(parser: argparse.ArgumentParser, arguments: argparse.Namespace) -> int:
    """Check each CVE against ``--purl`` and print the answers as a JSON list; 0 only when
    every answer establishes applicability, which no answer does while no verified
    affectedness source exists (ADR 0003)."""
    if len(arguments.cve_ids) > MAX_FILTER_VALUES:
        parser.error(f"at most {MAX_FILTER_VALUES} CVE IDs per affectedness command")
    affectedness_requests: list[AffectednessRequest] = []
    for cve_id in arguments.cve_ids:
        affectedness_requests.append(
            build_contract(parser, AffectednessRequest, cve_id=cve_id, purl=arguments.purl)
        )
    trustify_port = build_trustify_port()
    timeout_seconds = ToolLimits().affectedness_timeout_seconds
    answers: list[dict[str, object]] = []
    all_established = True
    for affectedness_request in affectedness_requests:
        affectedness_check = check_affectedness(
            trustify_port, affectedness_request, timeout_seconds
        )
        answers.append(affectedness_check.model_dump(mode="json"))
        if affectedness_check.applicability is ApplicabilityStatus.UNKNOWN:
            all_established = False
    print(json.dumps(answers, indent=2, ensure_ascii=False))
    return 0 if all_established else 1


def run_evidence_lookup(evidence_id: str, deployment: InvestigationDeployment) -> int:
    """Print the anchor ``deployment`` serves under ``evidence_id``; 1, with one line on
    stderr, when its catalogue holds none or the one it holds fails the anchor rules."""
    try:
        evidence_lookup = find_served_evidence(deployment, evidence_id)
    except EvidenceValidationError:
        print(UNSERVED_EVIDENCE_MESSAGE.format(evidence_id=evidence_id), file=sys.stderr)
        return 1
    if evidence_lookup is None:
        print(UNKNOWN_EVIDENCE_MESSAGE.format(evidence_id=evidence_id), file=sys.stderr)
        return 1
    print(evidence_lookup.model_dump_json(indent=2))
    return 0


def run_product_query(
    request: ProductQueryRequest, store_root: Path | None, output_format: str
) -> int:
    """Read the configured corpus through the product service and print its page."""
    started_at = time.monotonic()
    served_corpus = load_served_corpus_or_exit("product", store_root)
    service = build_product_query_service(served_corpus)
    announce_data_loaded(
        "product",
        store_root,
        served_corpus.describe_served_dataset(),
        time.monotonic() - started_at,
    )
    try:
        vulnerabilities = service.query(request)
    except InvalidProductCursor:
        print(
            build_tool_failure(ToolFailureCode.INVALID_CURSOR).model_dump_json(),
            file=sys.stderr,
        )
        return 2
    if output_format == "text":
        print(render_product_query_summary(vulnerabilities))
    else:
        print(vulnerabilities.model_dump_json(indent=2))
    return 0 if vulnerabilities.items else 1


def announce_store_loading(command: str, store_name: str) -> None:
    """One line on stderr naming the store ``command`` is about to load."""
    print(STORE_LOADING_NOTICE.format(command=command, store_name=store_name), file=sys.stderr)


def load_served_corpus_or_exit(command: str, store_root: Path | None) -> ServedCorpus:
    """The served corpus (``load_served_corpus``), a configured store announced on stderr
    once its checks passed and it starts loading. A configured store root that cannot be
    served ends the run with exit 2 and one line naming the reason, never a path."""
    try:
        return load_served_corpus(store_root, partial(announce_store_loading, command))
    except StoreUnavailable as error:
        print(
            f"cve-kgrag {command} cannot start: store unavailable: {error.reason.value}",
            file=sys.stderr,
        )
        raise SystemExit(2) from None


def announce_data_loaded(
    command: str,
    store_root: Path | None,
    served_dataset: ServedDataset,
    loading_seconds: float,
) -> None:
    """One line on stderr naming the configured store's dataset and how long loading it
    and building its indexes took; nothing for the packaged fixture."""
    if store_root is None:
        return
    print(
        DATA_LOADED_NOTICE.format(
            command=command,
            cve_search_version=served_dataset.cve_search_version,
            seconds=loading_seconds,
        ),
        file=sys.stderr,
    )


def load_search_service_or_exit(
    command: str,
    store_root: Path | None,
    semantic_settings: SemanticSettings | None = None,
    monotonic_clock: Callable[[], float] = time.monotonic,
    mitre_snapshot: MitreSnapshotSettings | None = None,
) -> SearchService:
    """The search service over the served corpus (``load_served_corpus_or_exit``), saying
    on stderr when a configured store's data is loaded."""
    started_at = monotonic_clock()
    served_corpus = load_served_corpus_or_exit(command, store_root)
    weakness_mapping = load_weakness_mapping_or_exit(command, mitre_snapshot)
    search_service = build_search_service(
        served_corpus, semantic_settings, weakness_mapping=weakness_mapping
    )
    announce_data_loaded(
        command,
        store_root,
        served_corpus.describe_served_dataset(),
        monotonic_clock() - started_at,
    )
    return search_service


def refuse_unsupported_filter(
    parser: argparse.ArgumentParser, error: UnsupportedFilter
) -> NoReturn:
    """A usage error (exit 2) naming the filter the served dataset cannot execute, never
    its values."""
    parser.error(f"filters.{error.filter_name}: {UNSUPPORTED_FILTER_ERROR}: {error}")


def load_fight_source_or_exit(
    command: str, fight_snapshot: FightSnapshotSettings | None
) -> tuple[FightSource, KnownFightSnapshot | None]:
    """The FiGHT source the settings configure (``load_fight_source``). A configured
    snapshot that cannot be served ends the run with exit 2 and one line naming the
    reason, never a path, file content or exception text."""
    try:
        return load_fight_source(fight_snapshot)
    except FightSnapshotUnavailable as error:
        print(
            f"cve-kgrag {command} cannot start: FiGHT snapshot unavailable: {error.failure.value}",
            file=sys.stderr,
        )
        raise SystemExit(2) from None


def load_weakness_mapping_or_exit(
    command: str, settings: MitreSnapshotSettings | None
) -> WeaknessMapping:
    """Refuse serving a configured snapshot whose file or digest cannot be verified."""
    try:
        return load_weakness_mapping(settings)
    except MitreSnapshotUnavailable as error:
        print(f"cve-kgrag {command} cannot serve MITRE snapshot: {error}", file=sys.stderr)
        raise SystemExit(2) from None


def load_data_plane_or_exit(
    command: str,
    settings: ServiceSettings,
    semantic_settings: SemanticSettings | None = None,
    monotonic_clock: Callable[[], float] = time.monotonic,
) -> ServingDataPlane:
    """The data plane a command that uses FiGHT serves from: the served corpus, then the
    FiGHT source, so a broken store is reported before a broken snapshot (ADR 0009 §9).
    A configured store is announced on stderr while it loads and once its data is loaded."""
    started_at = monotonic_clock()
    served_corpus = load_served_corpus_or_exit(command, settings.store_root)
    fight_source, pinned_fight_snapshot = load_fight_source_or_exit(
        command, settings.fight_snapshot
    )
    weakness_mapping = load_weakness_mapping_or_exit(command, settings.mitre_snapshot)
    data_plane = build_serving_data_plane(
        served_corpus,
        weakness_mapping=weakness_mapping,
        fight_source=fight_source,
        pinned_fight_snapshot=pinned_fight_snapshot,
        semantic_settings=semantic_settings,
    )
    announce_data_loaded(
        command,
        settings.store_root,
        data_plane.served_dataset,
        monotonic_clock() - started_at,
    )
    return data_plane


def run_mcp_server(
    runner: McpServerRunner | InterfaceUnavailable, settings: ServiceSettings
) -> int:
    """Serve the served corpus's knowledge tools with ``runner`` until the client closes
    stdin; 1 when there is no usable runner, with one line on stderr naming why: the
    missing ``mcp`` extra, or the reason the runner is unusable. The runner is checked
    before the corpus is loaded, so a core install exits before it touches any data.
    Writes nothing to stdout, which carries the protocol. The tools are read-only, so they
    serve no semantic channel: its Chroma collection cannot be opened read-only."""
    if isinstance(runner, InterfaceUnavailable):
        print(f"cve-kgrag mcp cannot start: {runner.detail}", file=sys.stderr)
        return 1
    dataset_kind = (
        ServedDatasetKind.SYNTHETIC_FIXTURE
        if settings.store_root is None
        else ServedDatasetKind.CORPUS_STORE
    )
    return runner(partial(load_mcp_toolbox, settings), dataset_kind=dataset_kind)


def load_mcp_toolbox(settings: ServiceSettings) -> KnowledgeToolbox:
    """Build the complete stdio toolbox on the runner's background thread."""
    return build_knowledge_toolbox(load_data_plane_or_exit("mcp", settings))


def require_http_token(
    parser: argparse.ArgumentParser, http_settings: HttpSettings, command: str
) -> SecretStr:
    """The configured token, or a usage error (exit 2) naming its variable and the
    ``command`` that needs it."""
    if http_settings.token is None:
        parser.error(f"invalid settings: {HTTP_TOKEN_VARIABLE}: required by {command}")
    return http_settings.token


def run_mcp_http_server(
    runner: McpHttpServerRunner | InterfaceUnavailable,
    settings: ServiceSettings,
    *,
    host: str,
    port: int,
    token: SecretStr,
) -> int:
    """Serve the served corpus's knowledge tools over Streamable HTTP with ``runner`` on
    ``host`` and ``port`` behind ``token`` until interrupted; 1 when there is no usable
    runner, with one line on stderr naming why, or when the server could not start, which
    the server has logged. The corpus and the FiGHT source are loaded before a port is
    bound."""
    if isinstance(runner, InterfaceUnavailable):
        print(f"cve-kgrag mcp --http cannot start: {runner.detail}", file=sys.stderr)
        return 1
    toolbox = build_knowledge_toolbox(load_data_plane_or_exit("mcp --http", settings))
    has_served = runner(toolbox, host=host, port=port, token=token)
    return 0 if has_served else 1


def run_api_server(
    runner: ApiServerRunner | InterfaceUnavailable,
    settings: ServiceSettings,
    *,
    host: str,
    port: int,
    token: SecretStr,
) -> int:
    """Serve the served corpus's REST API with ``runner`` on ``host`` and ``port`` behind
    ``token`` until interrupted. Its verification route checks a set as ``verify`` does,
    against the planners the settings configure. 1 when there is no usable runner, with
    one line on stderr naming why, or when the server could not start, which the server
    has logged. The corpus and the FiGHT source are loaded before a port is bound."""
    if isinstance(runner, InterfaceUnavailable):
        print(f"cve-kgrag api cannot start: {runner.detail}", file=sys.stderr)
        return 1
    # The toolbox's deployment and the verification route's share one read-only data
    # plane, and keep their call runners and admission apart (ADR 0009 §12).
    data_plane = load_data_plane_or_exit("api", settings)
    has_served = runner(
        build_knowledge_toolbox(data_plane),
        build_evidence_set_check(data_plane, settings.model_planner),
        host=host,
        port=port,
        token=token,
    )
    return 0 if has_served else 1


def build_evidence_set_check(
    data_plane: ServingDataPlane, planner_settings: ModelPlannerSettings | None
) -> Callable[[bytes], VerificationReport]:
    """``check_evidence_set`` against a deployment of ``data_plane`` and the planners
    ``planner_settings`` configure: how ``verify`` and the API's verification route check
    a set."""
    return partial(
        check_evidence_set,
        deployment=build_investigation_deployment(data_plane),
        accepted_planner_capabilities=list_accepted_planner_capabilities(planner_settings),
    )


def start_service_logging(settings: ServiceSettings, command: str) -> None:
    """Log warnings to stderr, the stream that carries no protocol, and say once that
    ``command`` serves no semantic channel when the settings enable one."""
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    if settings.semantic is not None:
        logging.getLogger(__name__).warning(SEMANTIC_NOT_SERVED, command)


def choose_semantic_settings(
    settings: ServiceSettings, arguments: argparse.Namespace
) -> SemanticSettings | None:
    """The semantic settings a ``search``, ``topic``, ``investigate`` or ``capabilities``
    command loads: the configured ones only when it was run with ``--semantic``, so no
    other run opens the semantic store."""
    if arguments.semantic:
        return settings.semantic
    return None


@dataclass(frozen=True)
class EvaluationInputs:
    """What one planner evaluation runs: its cases, the data plane of each FiGHT choice,
    the dataset they name, and the labelled cases and sets an M7b evaluation scores."""

    cases: tuple[GoldCase, ...]
    data_planes: Mapping[FightChoice, ServingDataPlane]
    dataset: DatasetIdentity
    labelled_cases: LabelledCases | None


def read_classified_gold(
    parser: argparse.ArgumentParser, gold_path: Path
) -> tuple[bytes, object, GoldFormat]:
    """The gold file's bytes, parsed once by the strict loader, and its format. A file
    over the cap, one the strict loader refuses or one of neither format is a usage
    error, reported without quoting it."""
    gold_bytes = read_input_file(parser, gold_path, MAX_GOLD_FILE_BYTES)
    try:
        gold_document = read_gold_document(gold_bytes)
        return gold_bytes, gold_document, classify_gold_document(gold_document)
    except GoldFileError as error:
        parser.error(f"invalid gold file: {error}")


def read_trajectory_inputs(
    parser: argparse.ArgumentParser, arguments: argparse.Namespace, gold_document: object
) -> EvaluationInputs:
    """M7a's cases over the packaged fixture, whatever the settings; ``--sets`` is a
    usage error, since trajectories carry no sets."""
    if arguments.sets is not None:
        parser.error(SETS_WITHOUT_LABELLED_CASES)
    print(EVAL_FIXTURE_NOTICE, file=sys.stderr)
    try:
        cases = read_gold_cases(gold_document)
    except GoldFileError as error:
        parser.error(f"invalid gold file: {error}")
    data_planes = build_fixture_data_planes(load_packaged_fixture())
    return EvaluationInputs(
        cases, data_planes, describe_fixture_dataset(data_planes), labelled_cases=None
    )


def find_stated_digest_mismatch(
    gold_file: GoldFile, recorded_sets: RecordedSets, fight_snapshot: FightSnapshotSettings
) -> str | None:
    """Which digest the gold file, the sets file and the configured snapshot state
    differently, or ``None`` when they agree."""
    if recorded_sets.gold_file_sha256 != gold_file.gold_file_sha256:
        return "the sets file was derived from another gold file"
    if recorded_sets.corpus_content_sha256 != gold_file.corpus_content_sha256:
        return "the sets file names another corpus than the gold file"
    if recorded_sets.fight_snapshot_sha256 != gold_file.fight_snapshot_sha256:
        return "the sets file names another FiGHT snapshot than the gold file"
    if (
        fight_snapshot.sha256 is not None
        and fight_snapshot.sha256 != gold_file.fight_snapshot_sha256
    ):
        return "the configured FiGHT snapshot is not the one the gold file was labelled against"
    return None


def find_loaded_digest_mismatch(gold_file: GoldFile, data_plane: ServingDataPlane) -> str | None:
    """Whether the loaded store and snapshot are the ones the gold file names."""
    corpus_version = name_corpus_store_version(gold_file.corpus_content_sha256)
    if data_plane.served_dataset.cve_search_version != corpus_version:
        return "the active store's corpus is not the one the gold file was labelled against"
    pinned_snapshot = data_plane.pinned_fight_snapshot
    if (
        pinned_snapshot is None
        or pinned_snapshot.snapshot_sha256 != gold_file.fight_snapshot_sha256
    ):
        return "the loaded FiGHT snapshot is not the one the gold file was labelled against"
    return None


def read_labelled_inputs(
    parser: argparse.ArgumentParser,
    arguments: argparse.Namespace,
    gold_bytes: bytes,
    gold_document: object,
    settings: ServiceSettings,
) -> EvaluationInputs | int:
    """M7b's cases over the active store and the operator snapshot, after the checks of
    the M7b design: the files' stated digests first, then the store and snapshot loaded
    once each, then the loaded digests. Missing settings and an unservable source are
    usage errors (exit 2); a sets file that is not one, or a digest that disagrees, is
    the exit code 1, with one line in the server's words."""
    if arguments.sets is None:
        parser.error(LABELLED_CASES_WITHOUT_SETS)
    if settings.store_root is None:
        parser.error(EVAL_NEEDS_A_STORE_ROOT)
    if settings.fight_snapshot is None:
        parser.error(EVAL_NEEDS_A_FIGHT_SNAPSHOT)
    try:
        gold_file = read_gold_file(gold_document, sha256_hex(gold_bytes))
    except GoldFileError as error:
        parser.error(f"invalid gold file: {error}")
    sets_bytes = read_input_file(parser, arguments.sets, MAX_GOLD_SETS_FILE_BYTES)
    try:
        recorded_sets = read_recorded_sets(sets_bytes, gold_file)
    except GoldFileError as error:
        print(f"cve-kgrag eval planner: {error}", file=sys.stderr)
        return 1
    mismatch = find_stated_digest_mismatch(gold_file, recorded_sets, settings.fight_snapshot)
    if mismatch is not None:
        print(f"cve-kgrag eval planner: {mismatch}", file=sys.stderr)
        return 1
    data_plane = load_data_plane_or_exit("eval planner", settings)
    mismatch = find_loaded_digest_mismatch(gold_file, data_plane)
    if mismatch is not None:
        print(f"cve-kgrag eval planner: {mismatch}", file=sys.stderr)
        return 1
    cases: list[GoldCase] = []
    for case in gold_file.cases:
        cases.append(GoldCase(case_sha256=case.case_sha256, request=case.request, fight="operator"))
    dataset = DatasetIdentity(
        cve_search_version=data_plane.served_dataset.cve_search_version,
        fight_profile=FightProfile.OPERATOR_SNAPSHOT,
        fight_snapshot_sha256=gold_file.fight_snapshot_sha256,
        sets_sha256=sha256_hex(sets_bytes),
    )
    return EvaluationInputs(
        tuple(cases),
        {"operator": data_plane},
        dataset,
        LabelledCases(gold_file=gold_file, gold_sets=recorded_sets.cases),
    )


def discover_model_runs(
    parser: argparse.ArgumentParser,
    arguments: argparse.Namespace,
    planner_settings: ModelPlannerSettings | None,
) -> ModelRuns | int | None:
    """The model runs ``--model-runs`` asks for, with an enabled planner that can plan,
    so a run never reports a model evaluation it did not make; exit code 1 when the
    planner cannot plan."""
    if arguments.model_runs == 0:
        return None
    if planner_settings is None:
        parser.error(MODEL_RUNS_WITHOUT_A_PLANNER)
    planner_setup = discover_planner_setup(planner_settings)
    if not isinstance(planner_setup, ModelPlanning):
        print(
            f"cve-kgrag eval planner cannot make model runs: {planner_setup.unavailable_detail}",
            file=sys.stderr,
        )
        return 1
    return ModelRuns(planner_setup, arguments.model_runs)


def run_planner_evaluation_command(
    parser: argparse.ArgumentParser, arguments: argparse.Namespace, settings: ServiceSettings
) -> int:
    """Run the gold cases (``run_planner_evaluation``), print the report and name the
    result directory on stderr. The gold file's format decides the data: M7a's
    trajectories run over the packaged fixture, M7b's labelled cases over the active store
    and the operator snapshot, scored against ``--sets`` (``read_labelled_inputs``). An
    ``--out`` inside the package is a usage error: the files a run writes there would
    change the package the report names; so is one inside the store root, whose reader
    would then refuse the store holding it."""
    resolved_out = arguments.out.resolve()
    if resolved_out.is_relative_to(PACKAGE_DIR):
        parser.error(OUT_INSIDE_THE_PACKAGE)
    if settings.store_root is not None and lies_in_store_root(resolved_out, settings.store_root):
        parser.error(OUT_INSIDE_THE_STORE_ROOT)
    gold_bytes, gold_document, gold_format = read_classified_gold(parser, arguments.gold)
    model_runs = discover_model_runs(parser, arguments, settings.model_planner)
    if isinstance(model_runs, int):
        return model_runs
    inputs: EvaluationInputs | int
    if gold_format is GoldFormat.TRAJECTORIES:
        inputs = read_trajectory_inputs(parser, arguments, gold_document)
    else:
        inputs = read_labelled_inputs(parser, arguments, gold_bytes, gold_document, settings)
    if isinstance(inputs, int):
        return inputs
    try:
        result_directory = ResultDirectory.create(arguments.out)
        report = run_planner_evaluation(
            inputs.cases,
            gold_sha256=sha256_hex(gold_bytes),
            data_planes=inputs.data_planes,
            dataset=inputs.dataset,
            labelled_cases=inputs.labelled_cases,
            model_runs=model_runs,
            source_revision=read_source_revision(PACKAGE_DIR),
            package_dir=PACKAGE_DIR,
            result_directory=result_directory,
        )
    except OSError as error:
        print(f"cve-kgrag eval planner cannot write its results: {error.strerror}", file=sys.stderr)
        return 1
    except EvaluationStopped as error:
        print(f"cve-kgrag eval planner stopped without a report: {error}", file=sys.stderr)
        return 1
    sys.stdout.write(format_report(report).decode())
    print(
        f"wrote the evidence sets and {REPORT_FILE_NAME} to {result_directory.path}",
        file=sys.stderr,
    )
    return 0


def list_differing_cases(derived_bytes: bytes, recorded_bytes: bytes) -> list[str] | None:
    """The IDs of the gold file's cases whose sets the recorded file states otherwise, or
    ``None`` when the recorded file is not a sets file of the same corpus and snapshot.
    The recorded file is outside input, so only IDs the gold file validated are returned,
    never a key of the recorded file."""
    derived_sets = json.loads(derived_bytes)
    try:
        recorded_sets = json.loads(recorded_bytes)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(recorded_sets, dict) or not isinstance(recorded_sets.get("cases"), dict):
        return None
    for key in ("corpus_content_sha256", "fight_snapshot_sha256"):
        if derived_sets[key] != recorded_sets.get(key):
            return None
    differing_cases: list[str] = []
    for case_id, case_sets in derived_sets["cases"].items():
        if recorded_sets["cases"].get(case_id) != case_sets:
            differing_cases.append(case_id)
    return differing_cases


def run_gold_sets_command(
    parser: argparse.ArgumentParser, arguments: argparse.Namespace, settings: ServiceSettings
) -> int:
    """Derive the gold file's sets (``derive_gold_sets``) and print them, or, with
    ``--check``, compare them with the recorded sets file: exit 0 when the bytes are
    equal, 1 naming the cases that differ. Missing settings, a gold file this command does
    not read and a source that cannot be read end the run with exit 2; a gold file whose
    labels the sources do not support, with exit 1."""
    if settings.store_root is None:
        parser.error(GOLD_SETS_NEED_A_STORE_ROOT)
    if settings.fight_snapshot is None:
        parser.error(GOLD_SETS_NEED_A_FIGHT_SNAPSHOT)
    gold_bytes, gold_document, gold_format = read_classified_gold(parser, arguments.gold)
    if gold_format is not GoldFormat.LABELLED_CASES:
        parser.error(GOLD_SETS_NEED_LABELLED_CASES)
    try:
        gold_file = read_gold_file(gold_document, sha256_hex(gold_bytes))
    except GoldFileError as error:
        parser.error(f"invalid gold file: {error}")
    try:
        derived_bytes = derive_gold_sets(gold_file, settings.store_root, settings.fight_snapshot)
    except StoreUnavailable as error:
        print(
            f"cve-kgrag eval gold-sets cannot start: store unavailable: {error.reason.value}",
            file=sys.stderr,
        )
        return 2
    except FightSnapshotUnavailable as error:
        print(
            "cve-kgrag eval gold-sets cannot start: FiGHT snapshot unavailable: "
            f"{error.failure.value}",
            file=sys.stderr,
        )
        return 2
    except GoldFileError as error:
        print(f"cve-kgrag eval gold-sets: {error}", file=sys.stderr)
        return 1
    if arguments.check is None:
        sys.stdout.write(derived_bytes.decode())
        return 0
    recorded_bytes = read_input_file(parser, arguments.check, MAX_GOLD_SETS_FILE_BYTES)
    if recorded_bytes == derived_bytes:
        print("cve-kgrag eval gold-sets: the recorded sets match", file=sys.stderr)
        return 0
    differing_cases = list_differing_cases(derived_bytes, recorded_bytes)
    if differing_cases is None:
        print(
            "cve-kgrag eval gold-sets: the recorded file is not the sets of this gold file, "
            "corpus and FiGHT snapshot",
            file=sys.stderr,
        )
    elif differing_cases:
        print(
            f"cve-kgrag eval gold-sets: the recorded sets differ for {', '.join(differing_cases)}",
            file=sys.stderr,
        )
    else:
        print(
            "cve-kgrag eval gold-sets: the recorded file differs only in cases the gold file "
            "does not hold, or in layout",
            file=sys.stderr,
        )
    return 1


def run_legacy_migration_command(
    parser: argparse.ArgumentParser,
    arguments: argparse.Namespace,
    parsers: MigrationParsers | InterfaceUnavailable,
    store_root: Path | None,
) -> int:
    """Run the import the arguments ask for (``run_migration``) and print its report.
    0 when the run imported, found the import already done, or completed a dry run; 1
    when it failed, which the report says, or the ``migration`` extra is missing, which
    stderr says; an input manifest that is not valid is a usage error."""
    if isinstance(parsers, InterfaceUnavailable):
        print(f"cve-kgrag migrate legacy cannot start: {parsers.detail}", file=sys.stderr)
        return 1
    manifest_bytes = read_inputs_manifest_file(parser, arguments.inputs)
    try:
        manifest = load_inputs_manifest(manifest_bytes)
    except InputsManifestError as error:
        parser.error(f"invalid input manifest: {error}")
    source_registry = load_packaged_source_registry()
    report = run_migration(
        MigrationRequest(
            manifest=manifest,
            manifest_bytes=manifest_bytes,
            manifest_path=arguments.inputs,
            target=arguments.target,
            legacy_root=arguments.legacy_root,
            is_dry_run=arguments.dry_run,
            store_root=store_root,
        ),
        MigrationDependencies(
            parsers=parsers,
            normalizer=build_nvd_normalizer(source_registry),
            source_registry=source_registry,
            clock=utc_now,
            importer_version=read_installed_version(),
            limits=MigrationLimits(),
        ),
    )
    print(report.model_dump_json(indent=2))
    return 1 if report.outcome is MigrationOutcome.FAILED else 0


def print_store_status(store_status: StoreStatus) -> None:
    print(store_status.model_dump_json(indent=2))


def is_store_status_ok(store_status: StoreStatus) -> bool:
    """Whether the record is readable and the active store is ``ok``; a previous store
    that is not ``ok`` does not count against it. A status shows an active store exactly
    when the record is readable."""
    active_store = store_status.active_store
    return active_store is not None and active_store.condition is ActiveStoreCondition.OK


def run_store_command(arguments: argparse.Namespace, store_activation: StoreActivation) -> int:
    """Run the ``store`` operation the arguments name and print its result as JSON. 1 with
    one line on stderr naming the reason code when it fails, never a path; ``status``
    also exits 1, after printing, unless the active store is ``ok``."""
    store_command = arguments.store_command
    try:
        if store_command == "validate":
            verified_store = store_activation.validate(arguments.name)
            print(describe_identity(verified_store).model_dump_json(indent=2))
            return 0
        if store_command == "activate":
            print_store_status(store_activation.activate(arguments.name))
            return 0
        if store_command == "rollback":
            print_store_status(store_activation.roll_back())
            return 0
        # The parser offers one more store command: status.
        store_status = store_activation.describe_status()
        print_store_status(store_status)
        return 0 if is_store_status_ok(store_status) else 1
    except StoreOperationFailed as error:
        message = STORE_OPERATION_FAILURE_MESSAGES[error.failure]
        print(
            f"cve-kgrag store {store_command} failed: {error.failure.value}: {message}",
            file=sys.stderr,
        )
        return 1


def run_mitre_build_command(arguments: argparse.Namespace) -> int:
    """Build a mapping without opening any corpus store or contacting a service."""
    try:
        snapshot = build_mapping_snapshot(
            arguments.cwe.read_bytes(),
            arguments.capec.read_bytes(),
            arguments.attack.read_bytes(),
            tuple(arguments.cwe_id),
        )
        snapshot_bytes = serialize_mapping_snapshot(snapshot)
        write_mapping_file(arguments.out, snapshot_bytes)
    except (OSError, ValueError, KeyError, TypeError, ParseError) as error:
        print(f"cve-kgrag mitre build failed: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "sha256": sha256_hex(snapshot_bytes),
                "size_bytes": len(snapshot_bytes),
                "coverage": snapshot.coverage,
                "counts": snapshot.counts.model_dump(),
            },
            sort_keys=True,
        )
    )
    return 0


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
    environment by default; ``cve_kgrag.settings``). Invalid settings are a usage error.

    A command loads only what its row of ADR 0009 §10 names, so a configured store that
    is missing or broken fails only the commands that serve it: ``schema``, ``migrate``,
    ``store``, ``resolve`` and ``affectedness`` load no served corpus, and ``demo`` and
    ``eval planner`` always use the packaged fixture."""
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        settings = load_settings(os.environ if environment is None else environment)
    except SettingsError as error:
        parser.error(str(error))
    if arguments.command == "mitre":
        return run_mitre_build_command(arguments)
    if arguments.command == "schema":
        return run_schema_command(arguments.action, arguments.dir)
    if arguments.command == "mcp":
        http_token = (
            require_http_token(parser, settings.http, "mcp --http") if arguments.http else None
        )
        start_service_logging(settings, "mcp")
        if http_token is not None:
            return run_mcp_http_server(
                discover_mcp_http_server_runner(),
                settings,
                host=settings.http.host,
                port=settings.http.mcp_port,
                token=http_token,
            )
        return run_mcp_server(discover_mcp_server_runner(), settings)
    if arguments.command == "api":
        api_token = require_http_token(parser, settings.http, "api")
        start_service_logging(settings, "api")
        return run_api_server(
            discover_api_server_runner(),
            settings,
            host=settings.http.host,
            port=settings.http.api_port,
            token=api_token,
        )
    if arguments.command == "migrate":
        return run_legacy_migration_command(
            parser, arguments, discover_migration_parsers(), settings.store_root
        )
    if arguments.command == "store":
        if settings.store_root is None:
            parser.error(STORE_ROOT_REQUIRED)
        return run_store_command(arguments, build_store_activation(settings.store_root))
    if arguments.command == "eval" and arguments.eval_command == "gold-sets":
        return run_gold_sets_command(parser, arguments, settings)
    if arguments.command == "eval":
        return run_planner_evaluation_command(parser, arguments, settings)
    if arguments.command == "resolve":
        resolution_request = build_contract(parser, ConceptResolutionRequest, query=arguments.query)
        return print_resolution(
            ConceptResolution(resolution=build_topic_registry().resolve(resolution_request.query))
        )
    if arguments.command == "affectedness":
        return run_affectedness(parser, arguments)
    if arguments.command == "demo":
        print(DEMO_FIXTURE_NOTICE, file=sys.stderr)
        return run_demo(build_search_service(load_packaged_fixture()))

    if arguments.command == "lookup":
        lookup_request = build_contract(parser, CveLookupRequest, cve_id=arguments.cve_id)
        return print_response(
            lookup_cve(
                load_search_service_or_exit(
                    "lookup", settings.store_root, mitre_snapshot=settings.mitre_snapshot
                ),
                lookup_request.cve_id,
            )
        )
    if arguments.command == "product":
        product_request = build_contract(
            parser,
            ProductQueryRequest,
            vendor=arguments.vendor,
            product=arguments.product,
            version=arguments.version,
            limit=arguments.limit,
            cursor=arguments.cursor,
        )
        return run_product_query(product_request, settings.store_root, arguments.format)
    if arguments.command == "search":
        search_request = build_search_request(parser, arguments)
        service = load_search_service_or_exit(
            "search",
            settings.store_root,
            choose_semantic_settings(settings, arguments),
            mitre_snapshot=settings.mitre_snapshot,
        )
        try:
            return print_response(service.search(search_request))
        except UnsupportedFilter as error:
            refuse_unsupported_filter(parser, error)
    if arguments.command == "verify":
        evidence_set_bytes = read_evidence_set_file(parser, arguments.evidence_set_path)
        if settings.semantic is not None:
            logging.getLogger(__name__).warning(SEMANTIC_NOT_SERVED, "verify")
        check_set = build_evidence_set_check(
            load_data_plane_or_exit("verify", settings), settings.model_planner
        )
        return print_verification(check_set(evidence_set_bytes))
    if arguments.command == "investigate":
        investigation_request = build_investigation_request(parser, arguments)
        data_plane = load_data_plane_or_exit(
            "investigate", settings, choose_semantic_settings(settings, arguments)
        )
        investigation_service = build_investigation_service(
            data_plane, planner_setup=discover_planner_setup(settings.model_planner)
        )
        try:
            evidence_set = investigation_service.investigate(investigation_request)
            return print_investigation(evidence_set, arguments.format)
        except UnsupportedFilter as error:
            refuse_unsupported_filter(parser, error)
    if arguments.command == "topic":
        topic_request = build_contract(
            parser,
            TopicContextRequest,
            query=arguments.query,
            scope=arguments.scope,
            limit=arguments.limit,
            max_results_per_search=arguments.max_results_per_search,
            semantic=arguments.semantic,
        )
        topic_context_service = assemble_topic_context_service(
            load_data_plane_or_exit(
                "topic", settings, choose_semantic_settings(settings, arguments)
            )
        )
        return print_response(topic_context_service.explore(topic_request))
    if arguments.command == "capabilities":
        data_plane = load_data_plane_or_exit(
            "capabilities", settings, choose_semantic_settings(settings, arguments)
        )
        deployment = build_investigation_deployment(data_plane)
        source_capabilities = describe_service_capabilities(
            deployment, discover_planner_setup(settings.model_planner)
        )
        return print_capabilities(describe_knowledge_capabilities(deployment, source_capabilities))
    evidence_request = build_contract(
        parser, EvidenceLookupRequest, evidence_id=arguments.evidence_id
    )
    return run_evidence_lookup(
        evidence_request.evidence_id,
        build_investigation_deployment(load_data_plane_or_exit("evidence", settings)),
    )


if __name__ == "__main__":
    sys.exit(main())
