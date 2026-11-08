"""Shared corpus wiring and lookup cases for CLI, REST and MCP CNVD tests."""

from pathlib import Path
from typing import Any

from tests.support.clocks import read_fixed_clock
from tests.support.cnvd_inputs import import_cnvd_lookup_corpus
from tests.support.corpus_stores import import_store
from tests.support.toolbox import build_compatibility_store_toolbox
from vulnwitness.adapters.store.corpus_store import load_corpus_store
from vulnwitness.composition import (
    build_knowledge_toolbox,
    build_serving_data_plane,
    load_packaged_source_registry,
)
from vulnwitness.interfaces.knowledge_toolbox import KnowledgeToolbox

# ID, expected CVE, expected per-entry grades and states, and whether the entry is pending.
CNVD_LOOKUP_CASES = [
    ("CVE-9999-0001", "CVE-9999-0001", ["agree", "disagree"], "analysed", False),
    ("CNVD-9999-00001", "CVE-9999-0001", ["agree", "disagree"], "analysed", False),
    ("CVE-9999-0002", "CVE-9999-0002", ["not_comparable"], "rejected_by_nvd", True),
    ("CVE-9999-0003", "CVE-9999-0003", ["not_comparable"], "excluded_by_import", True),
    ("CVE-9999-0004", "CVE-9999-0004", ["not_comparable"], "not_in_nvd_snapshot", True),
    ("CNVD-9999-00004", "CVE-9999-0004", ["not_comparable"], "not_in_nvd_snapshot", True),
]
CNVD_LOOKUP_CASE_IDS = [
    "cve-merged",
    "cnvd-merged",
    "rejected",
    "excluded",
    "pending-only",
    "cnvd-pending",
]
NVD_STATE_CASES = [
    ("Analyzed", "analysed"),
    ("Modified", "analysed"),
    ("Received", "awaiting_analysis"),
    ("Awaiting Analysis", "awaiting_analysis"),
    ("Undergoing Analysis", "awaiting_analysis"),
    ("Deferred", "deferred"),
    ("Future Status", "status_unknown"),
]


def build_cnvd_serving_toolbox(directory: Path, **corpus_options: Any) -> KnowledgeToolbox:
    return build_knowledge_toolbox(
        build_serving_data_plane(import_cnvd_lookup_corpus(directory, **corpus_options)),
        wall_clock=read_fixed_clock,
    )


def cnvd_attribution() -> str:
    attribution = load_packaged_source_registry().find_source("circl-cnvd").attribution
    assert attribution is not None
    return attribution


def assert_cnvd_lookup(
    lookup: dict[str, Any],
    cve_id: str,
    severities: list[str],
    nvd_state: str,
    is_pending: bool,
) -> None:
    """Assert the same public shape after each transport's validation and serialization."""
    assert lookup["status"] == "ok"
    assert lookup["cnvd_attribution"] == cnvd_attribution()
    if is_pending:
        assert lookup["candidates"] == []
        entries = lookup["pending_cnvd"]
        assert entries[0]["cve_id"] == cve_id
        assert lookup["warnings"] == []
    else:
        assert lookup["candidates"][0]["record"]["cve_id"] == cve_id
        entries = lookup["candidates"][0]["record"]["cnvd"]
        assert "pending_cnvd" not in lookup
    actual_severities = []
    evidence_ids = set()
    for anchor in lookup["evidence"]:
        evidence_ids.add(anchor["evidence_id"])
    for entry in entries:
        comparison = entry["source_comparison"]
        actual_severities.append(comparison["severity"])
        assert comparison["nvd_state"] == nvd_state
        assert comparison["rule"] == "cnvd_severity_vs_nvd_primary_cvss3"
        assert "VulnWitness's comparison" in comparison["statement"]
        assert entry["evidence_id"] in evidence_ids
    assert actual_severities == severities


def build_cnvd_capability_toolbox(directory: Path, store_kind: str) -> KnowledgeToolbox:
    """CNVD imports with/without retained content, format 1, or a format-2 NVD-only import."""
    if store_kind == "format-1":
        return build_compatibility_store_toolbox()
    if store_kind == "no-cnvd-input":
        store_root = directory / "stores"
        store_root.mkdir()
        corpus = load_corpus_store(import_store(store_root, "nvd-only"))
        return build_knowledge_toolbox(build_serving_data_plane(corpus))
    return build_cnvd_serving_toolbox(directory, retain_cnvd=store_kind != "unlinked-cnvd")
