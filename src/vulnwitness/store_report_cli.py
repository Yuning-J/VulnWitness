"""``vulnwitness store coverage`` and ``vulnwitness store diff``: read-only reports over
named stores under the store root. Each store is checked and loaded as activation loads
it; nothing is written and nothing is activated."""

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

from vulnwitness.adapters.store.corpus_store import CorpusStore, load_corpus_store
from vulnwitness.adapters.store.store_check import check_store
from vulnwitness.adapters.store.store_root import StoreRootUnusableError, check_store_root
from vulnwitness.domain.store_coverage import diff_store_semantics, measure_store_coverage
from vulnwitness.domain.store_status import StoreCondition, StoreOperationFailure


class StoreReportFailed(Exception):
    def __init__(self, name: str, condition: StoreCondition | StoreOperationFailure) -> None:
        super().__init__(f"{name}: {condition.value}")
        self.name = name
        self.condition = condition


def load_named_store(store_root: Path, name: str) -> CorpusStore:
    """Load a checked store; raise ``StoreReportFailed`` for an unusable root or store."""
    try:
        check_store_root(store_root)
    except StoreRootUnusableError:
        raise StoreReportFailed(name, StoreOperationFailure.STORE_ROOT_UNUSABLE) from None
    store_check = check_store(store_root, name, None, load_corpus_store)
    if store_check.condition is not StoreCondition.OK or store_check.read_store is None:
        raise StoreReportFailed(name, store_check.condition)
    return store_check.read_store


def add_store_report_parsers(
    store_commands: "argparse._SubParsersAction[argparse.ArgumentParser]",
    parse_store_name: Callable[[str], str],
) -> None:
    coverage_parser = store_commands.add_parser(
        "coverage",
        help=(
            "count, by publication month, NVD statuses, CPE, CVSS, source-CVSS, CWE, "
            "exploit references, KEV, CNVD, source-affected products and versions, purls "
            "and SSVC (including exploitation poc/active); format-4-only counts are null "
            "for earlier stores; prints JSON"
        ),
    )
    coverage_parser.add_argument("name", type=parse_store_name)
    diff_parser = store_commands.add_parser(
        "diff",
        help=(
            "compare two named stores record by record by semantic digest, telling content "
            "changes from metadata-only refreshes; prints JSON"
        ),
    )
    diff_parser.add_argument("old", type=parse_store_name)
    diff_parser.add_argument("new", type=parse_store_name)


def run_store_report_command(arguments: argparse.Namespace, store_root: Path) -> int:
    """Print the report as JSON; 1 with the store's condition on stderr when a store does
    not load."""
    try:
        if arguments.store_command == "coverage":
            store = load_named_store(store_root, arguments.name)
            coverage = measure_store_coverage(
                store.store_name,
                store.corpus_content_sha256,
                store.records,
                store.manifest.store_format_version,
            )
            print(coverage.model_dump_json(indent=2))
            return 0
        old_store = load_named_store(store_root, arguments.old)
        new_store = load_named_store(store_root, arguments.new)
        diff = diff_store_semantics(
            old_store.store_name, old_store.records, new_store.store_name, new_store.records
        )
        print(diff.model_dump_json(indent=2))
        return 0
    except StoreReportFailed as error:
        print(
            f"vulnwitness store {arguments.store_command} failed: {error.name}: "
            f"{error.condition.value}",
            file=sys.stderr,
        )
        return 1
