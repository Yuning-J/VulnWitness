"""Structured constraints and canonical in-memory graph expansion."""

from cve_kgrag.adapters.graph.in_memory_graph import InMemoryRelationGraph
from cve_kgrag.adapters.structured.in_memory_filter import InMemoryStructuredIndex
from cve_kgrag.domain.search import GraphPath, SearchFilters
from cve_kgrag.domain.taxonomy import BackendStatus
from tests.support.builders import build_cve_record
from tests.support.collect import list_cve_ids

RECORDS = (
    build_cve_record(
        cve_id="CVE-9999-0101",
        cwe_ids=["CWE-89"],
        affected=[{"vendor": "democorp", "product": "gateway", "status": "affected"}],
        cvss=[
            {
                "version": "3.1",
                "vector_string": "CVSS:3.1/AV:N",
                "base_score": 9.8,
                "base_severity": "CRITICAL",
                "scorer": "test",
            }
        ],
        published="2026-01-01T00:00:00Z",
    ),
    build_cve_record(
        cve_id="CVE-9999-0102",
        cwe_ids=["CWE-89"],
        affected=[{"vendor": "othercorp", "product": "portal", "status": "affected"}],
    ),
    build_cve_record(
        cve_id="CVE-9999-0103",
        cwe_ids=["CWE-79"],
        affected=[
            {
                "vendor": "democorp",
                "product": "gateway",
                "purl": "pkg:pypi/democorp-gateway@2.1.0?arch=x86",
                "status": "affected",
            }
        ],
    ),
    build_cve_record(
        cve_id="CVE-9999-0104",
        cwe_ids=["CWE-416"],
        affected=[{"vendor": "democorp", "product": "gateway", "status": "unaffected"}],
    ),
)


def test_structured_filters_and_fields_while_values_within_a_field_are_or() -> None:
    outcome = InMemoryStructuredIndex(RECORDS).search(
        SearchFilters(vendors=("DemoCorp",), cwe_ids=("CWE-89",), severities=("CRITICAL",))
    )

    assert outcome.status is BackendStatus.OK
    assert list_cve_ids(outcome.matches) == ["CVE-9999-0101"]
    assert outcome.matches[0].matched_fields == (
        "affected.vendor",
        "cwe_ids",
        "cvss.base_severity",
    )


def test_graph_expands_only_to_non_seed_records_with_shared_asserted_relations() -> None:
    outcome = InMemoryRelationGraph(RECORDS).expand(["CVE-9999-0101"], 10, None)

    assert list_cve_ids(outcome.matches) == ["CVE-9999-0103", "CVE-9999-0102"]
    assert outcome.matches[0].score == 2.0
    assert outcome.matches[0].matched_fields == ("relation.product", "relation.vendor")


def test_graph_hit_records_the_seed_and_relation_it_was_reached_through() -> None:
    outcome = InMemoryRelationGraph(RECORDS).expand(["CVE-9999-0101"], 10, None)

    assert outcome.matches[1].graph_paths == (
        GraphPath(seed_cve_id="CVE-9999-0101", relation="cwe", value="CWE-89"),
    )


def test_graph_skips_neighbours_outside_the_allowed_ids() -> None:
    outcome = InMemoryRelationGraph(RECORDS).expand(
        ["CVE-9999-0101"], 10, frozenset({"CVE-9999-0102"})
    )

    assert list_cve_ids(outcome.matches) == ["CVE-9999-0102"]


def test_unaffected_product_is_neither_a_filter_match_nor_a_graph_relation() -> None:
    filtered = InMemoryStructuredIndex(RECORDS).search(SearchFilters(vendors=("democorp",)))
    expanded = InMemoryRelationGraph(RECORDS).expand(["CVE-9999-0101"], 10, None)

    assert "CVE-9999-0104" not in list_cve_ids(filtered.matches)
    assert "CVE-9999-0104" not in list_cve_ids(expanded.matches)


def test_purl_filter_matches_any_version_of_the_named_package() -> None:
    outcome = InMemoryStructuredIndex(RECORDS).search(
        SearchFilters(purls=("pkg:PyPI/democorp-gateway",))
    )

    assert list_cve_ids(outcome.matches) == ["CVE-9999-0103"]
    assert outcome.matches[0].matched_fields == ("affected.purl",)


def test_reason_for_a_multi_value_filter_is_the_alphabetically_first_value_met() -> None:
    record = build_cve_record(
        cve_id="CVE-9999-0105",
        affected=[
            {"vendor": "zetacorp", "product": "gateway", "status": "affected"},
            {"vendor": "alphacorp", "product": "gateway", "status": "affected"},
        ],
    )

    outcome = InMemoryStructuredIndex([record]).search(
        SearchFilters(vendors=("zetacorp", "alphacorp", "othercorp"))
    )

    assert outcome.matches[0].matched_terms == ("alphacorp",)


def test_graph_keeps_every_seed_path_and_scores_distinct_shared_relations() -> None:
    outcome = InMemoryRelationGraph(RECORDS).expand(["CVE-9999-0102", "CVE-9999-0103"], 10, None)

    neighbour = outcome.matches[0]
    assert list_cve_ids(outcome.matches) == ["CVE-9999-0101"]
    assert neighbour.score == 3.0
    assert neighbour.graph_paths == (
        GraphPath(seed_cve_id="CVE-9999-0102", relation="cwe", value="CWE-89"),
        GraphPath(seed_cve_id="CVE-9999-0103", relation="product", value="democorp/gateway"),
        GraphPath(seed_cve_id="CVE-9999-0103", relation="vendor", value="democorp"),
    )


def test_graph_relates_different_versions_of_one_package() -> None:
    older = build_cve_record(
        cve_id="CVE-9999-0106",
        affected=[
            {
                "vendor": "exampleorg",
                "product": "parser",
                "purl": "pkg:pypi/example-parser@1.0",
                "status": "affected",
            }
        ],
    )
    newer = build_cve_record(
        cve_id="CVE-9999-0107",
        affected=[
            {
                "vendor": "otherorg",
                "product": "parser-fork",
                "purl": "pkg:pypi/example-parser@2.0",
                "status": "affected",
            }
        ],
    )

    outcome = InMemoryRelationGraph([older, newer]).expand(["CVE-9999-0106"], 10, None)

    assert outcome.matches[0].graph_paths == (
        GraphPath(seed_cve_id="CVE-9999-0106", relation="purl", value="pkg:pypi/example-parser"),
    )
