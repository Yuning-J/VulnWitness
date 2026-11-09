"""Synthetic raw CNVD imports, immutable stores and served lookup contracts (ADR 0018)."""

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest

from tests.support.cnvd_inputs import (
    CnvdScenario,
    build_cnvd_scenario,
    build_raw_cnvd_record,
    build_raw_cnvd_scenario,
    write_format_2_cnvd_store,
    write_raw_cnvd_file,
)
from tests.support.legacy_inputs import (
    RETRIEVED_AT,
    build_cve_id,
    build_declaration,
    run_test_migration,
    write_inputs_manifest,
)
from vulnwitness.adapters.migration.migration_limits import MigrationLimits
from vulnwitness.adapters.store.corpus_store import (
    CorpusStoreIntegrityError,
    load_corpus_store,
    verify_corpus_store,
)
from vulnwitness.composition import build_search_service, load_packaged_source_registry
from vulnwitness.domain.hashing import canonical_json_bytes, sha256_hex
from vulnwitness.domain.migration_report import CnvdOutcome, MigrationFailureCode, MigrationOutcome
from vulnwitness.interfaces.lookup_summary import render_lookup_summary


def import_scenario(scenario: CnvdScenario):
    report = run_test_migration(
        scenario.manifest, scenario.target, dependencies=scenario.dependencies
    )
    assert report.outcome is MigrationOutcome.IMPORTED, report.failure
    return load_corpus_store(scenario.target), report


def test_increment_replaces_whole_record_in_retrieval_order_and_keeps_source_pin(
    tmp_path: Path,
) -> None:
    scenario = build_raw_cnvd_scenario(
        tmp_path,
        [build_raw_cnvd_record(1), build_raw_cnvd_record(9, cves=[])],
        increment_records=[build_raw_cnvd_record(1, title="SYNTHETIC: 更新标题", products=[])],
        reverse_manifest=True,
    )

    corpus, report = import_scenario(scenario)
    lookup = build_search_service(corpus).lookup(build_cve_id(1))

    assert corpus.manifest.store_format_version == 3
    entry = lookup.candidates[0].record.cnvd[0]
    assert entry.title == "SYNTHETIC: 更新标题"
    assert entry.products == ()
    assert len(lookup.candidates[0].record.cnvd) == 1
    assert report.cnvd_outcomes[CnvdOutcome.MERGED] == 1
    raw_inputs = []
    for store_input in corpus.manifest.inputs:
        if store_input.source.value == "vulnerability-lookup-cnvd":
            raw_inputs.append(store_input)
    assert raw_inputs[0].retrieved_at < raw_inputs[1].retrieved_at
    for anchor in lookup.evidence:
        if anchor.source_name == "vulnerability-lookup-cnvd":
            assert anchor.source_version == raw_inputs[1].source_version
            assert anchor.retrieved_at == raw_inputs[1].retrieved_at


def test_increment_replaces_old_cve_links_instead_of_accumulating_them(tmp_path: Path) -> None:
    scenario = build_raw_cnvd_scenario(
        tmp_path,
        [build_raw_cnvd_record(1)],
        increment_records=[build_raw_cnvd_record(1, cves={"cve": {"cveNumber": build_cve_id(4)}})],
    )

    corpus, report = import_scenario(scenario)

    assert corpus.records[0].cnvd == ()
    assert (
        corpus.cnvd_index.pending_by_cve_id[build_cve_id(4)][0].entry.cnvd_id == "CNVD-9999-00001"
    )
    assert report.cnvd_outcomes[CnvdOutcome.MERGED] == 0


@pytest.mark.parametrize(
    "retrieved_at", [RETRIEVED_AT, "2026-10-24T16:30:00+08:00"], ids=["same", "same-instant"]
)
def test_equal_raw_retrieval_instants_are_refused(tmp_path: Path, retrieved_at: str) -> None:
    scenario = build_raw_cnvd_scenario(
        tmp_path,
        [build_raw_cnvd_record(1)],
        increment_records=[build_raw_cnvd_record(2)],
        increment_retrieved_at=retrieved_at,
    )

    report = run_test_migration(scenario.manifest, scenario.target)

    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.CNVD_EQUAL_RETRIEVED_AT
    assert report.failure.manifest_index == 3
    assert not scenario.target.exists()


def test_both_cnvd_sources_are_refused_before_catalog_matching(tmp_path: Path) -> None:
    scenario = build_raw_cnvd_scenario(tmp_path, [build_raw_cnvd_record(1)])
    manifest = write_inputs_manifest(
        scenario.manifest.parent,
        [
            build_declaration("base.ndjson", source="vulnerability-lookup-cnvd"),
            build_declaration("train.parquet", source="circl-cnvd"),
        ],
    )

    report = run_test_migration(manifest, scenario.target)

    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.CNVD_MIXED_SOURCES
    assert report.failure.manifest_index == 1


@pytest.mark.parametrize(
    ("cves", "products", "expected_products"),
    [
        ({"cve": {"cveNumber": build_cve_id(1)}}, {"product": " unchanged "}, [" unchanged "]),
        ([{"cve": {"cveNumber": build_cve_id(1)}}], {"product": ["a", "b"]}, ["a", "b"]),
        (
            [{"cve": {"cveNumber": build_cve_id(1)}}],
            [{"product": "a"}, {"product": ["b", "c"]}],
            ["a", "b", "c"],
        ),
    ],
    ids=["objects", "list-cves-list-product", "lists-and-nested-products"],
)
def test_raw_fields_round_trip_and_serve_verbatim_with_research_attribution(
    tmp_path: Path, cves: Any, products: Any, expected_products: list[str]
) -> None:
    scenario = build_raw_cnvd_scenario(
        tmp_path,
        [
            build_raw_cnvd_record(
                1,
                cves=cves,
                products=products,
                formalWay=" <script>untrusted</script>\n建议 ",
                containers={"ignored": [1]},
                patchName=123,
                referenceLink=False,
            )
        ],
    )

    corpus, _ = import_scenario(scenario)
    search = build_search_service(corpus)
    lookup = search.lookup(build_cve_id(1))
    served = lookup.model_dump(mode="json")
    entry = served["candidates"][0]["record"]["cnvd"][0]

    assert entry["products"] == expected_products
    assert entry["submit_time"] == "2026-10-01"
    assert entry["open_time"] == "2026-10-02"
    assert entry["handling_advice"] == " <script>untrusted</script>\n建议 "
    assert entry["name_check"]["rule"] == "cnvd_title_vs_nvd_cpe_names"
    assert entry["name_check"]["cnvd_name"] == "SYNTHETIC:"
    assert served["cnvd_language"] == "zh"
    source = load_packaged_source_registry().find_source("vulnerability-lookup-cnvd")
    assert source.terms_or_license_url is None
    assert served["cnvd_attribution"] == source.attribution
    assert "licence unverified" in served["cnvd_attribution"]
    assert "research use" in search.describe_cnvd_attribution()
    assert search.describe_cnvd().imported
    assert search.describe_cnvd().revision is None
    assert verify_corpus_store(scenario.target).manifest.store_format_version == 3


@pytest.mark.parametrize(
    "fields",
    [
        {"number": "invalid"},
        {"title": ""},
        {"description": None},
        {"serverity": "高\n"},
        {"cves": {"cve": "CVE-9999-0001"}},
        {"cves": [None]},
        {"cves": {"cve": {"cveNumber": 1}}},
        {"products": {"product": [1]}},
        {"products": None},
        {"submitTime": "2026-02-30"},
        {"openTime": "2026-10-02T00:00:00Z"},
        {"formalWay": 42},
    ],
    ids=[
        "id",
        "title",
        "description",
        "severity",
        "cve-object",
        "cve-list",
        "cve-text",
        "product-text",
        "products-null",
        "date",
        "timestamp",
        "advice",
    ],
)
def test_malformed_retained_field_refuses_whole_import_with_input_and_line(
    tmp_path: Path, fields: dict[str, Any]
) -> None:
    scenario = build_raw_cnvd_scenario(
        tmp_path, [build_raw_cnvd_record(1), build_raw_cnvd_record(2, **fields)]
    )

    report = run_test_migration(scenario.manifest, scenario.target)

    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.CNVD_INVALID_RECORD
    assert report.failure.input_position == 2
    assert report.failure.input_line == 2
    assert not scenario.target.exists()


def test_multiple_cve_ids_link_independently_and_all_pending_outcomes_keep_raw_fields(
    tmp_path: Path,
) -> None:
    citations = []
    for number in range(1, 5):
        citations.append({"cve": {"cveNumber": build_cve_id(number)}})
    scenario = build_raw_cnvd_scenario(
        tmp_path,
        [
            build_raw_cnvd_record(1, cves=citations),
            build_raw_cnvd_record(5, cves=[]),
            build_raw_cnvd_record(6, cves={"cve": {"cveNumber": "CVE-9999-0001\n"}}),
        ],
    )

    corpus, report = import_scenario(scenario)
    search = build_search_service(corpus)

    assert report.cnvd_outcomes == {
        CnvdOutcome.MERGED: 1,
        CnvdOutcome.WITHOUT_NVD_RECORD: 1,
        CnvdOutcome.FOR_REJECTED_NVD_RECORD: 1,
        CnvdOutcome.FOR_EXCLUDED_NVD_RECORD: 1,
        CnvdOutcome.WITHOUT_CVE_ID: 1,
        CnvdOutcome.UNRECOGNISED_CVE_ID: 1,
    }
    assert corpus.records[0].cnvd[0].cnvd_id == "CNVD-9999-00001"
    for number in range(2, 5):
        lookup = search.lookup(build_cve_id(number))
        assert lookup.pending_cnvd[0].cnvd_id == "CNVD-9999-00001"
        assert lookup.pending_cnvd[0].products == ("SYNTHETIC: Example Gateway <2.0",)
        assert lookup.cnvd_language == "zh"
    assert len(corpus.evidence) == 5


def test_repeated_import_identity_is_stable_and_increment_changes_it(tmp_path: Path) -> None:
    scenario = build_raw_cnvd_scenario(tmp_path, [build_raw_cnvd_record(1)])
    _, first = import_scenario(scenario)
    second = run_test_migration(scenario.manifest, scenario.target.parent / "second")
    repeated = run_test_migration(scenario.manifest, scenario.target)
    declarations = [
        build_declaration("nvdcve-2.0-9999.json"),
        build_declaration("nvdcve-2.0-modified.json"),
        build_declaration("base.ndjson", source="vulnerability-lookup-cnvd"),
        build_declaration(
            "increment.ndjson",
            source="vulnerability-lookup-cnvd",
            retrieved_at="2026-10-24T09:30:00Z",
        ),
    ]
    write_raw_cnvd_file(scenario.manifest.parent, "increment.ndjson", [build_raw_cnvd_record(2)])
    manifest = write_inputs_manifest(scenario.manifest.parent, declarations)

    changed = run_test_migration(manifest, scenario.target.parent / "changed")

    assert (
        first.import_identity_sha256
        == second.import_identity_sha256
        == repeated.import_identity_sha256
    )
    assert second.outcome is MigrationOutcome.IMPORTED
    assert repeated.outcome is MigrationOutcome.ALREADY_IMPORTED
    assert changed.outcome is MigrationOutcome.IMPORTED
    assert changed.import_identity_sha256 != first.import_identity_sha256


def test_parquet_served_entries_have_only_empty_raw_fields(tmp_path: Path) -> None:
    scenario = build_cnvd_scenario(tmp_path)
    corpus, _ = import_scenario(scenario)

    lookup = build_search_service(corpus).lookup(build_cve_id(1))

    for entry in lookup.candidates[0].record.cnvd:
        assert entry.products == ()
        assert entry.submit_time is None
        assert entry.open_time is None
        assert entry.handling_advice is None
    assert (
        lookup.cnvd_attribution
        == load_packaged_source_registry().find_source("circl-cnvd").attribution
    )


def test_repinning_raw_products_still_fails_the_bound_source_anchor(tmp_path: Path) -> None:
    scenario = build_raw_cnvd_scenario(tmp_path, [build_raw_cnvd_record(1)])
    import_scenario(scenario)
    records_path = scenario.target / "records.jsonl"
    records_bytes = records_path.read_bytes().replace(b"Example Gateway", b"Changed Gateway")
    records_path.write_bytes(records_bytes)
    manifest_path = scenario.target / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    for pin in manifest["files"]:
        if pin["path"] == records_path.name:
            pin["sha256"] = sha256_hex(records_bytes)
            pin["size_bytes"] = len(records_bytes)
    manifest_path.write_bytes(canonical_json_bytes(manifest))

    with pytest.raises(CorpusStoreIntegrityError, match="differs from its row anchor"):
        verify_corpus_store(scenario.target)


def test_format_2_parquet_store_loads_and_serves_the_same_entries_with_empty_raw_fields(
    tmp_path: Path,
) -> None:
    scenario = build_cnvd_scenario(tmp_path)
    corpus, _ = import_scenario(scenario)
    expected = build_search_service(corpus).lookup(build_cve_id(1)).model_dump(mode="json")
    write_format_2_cnvd_store(scenario.target)

    loaded = load_corpus_store(scenario.target)
    served = build_search_service(loaded).lookup(build_cve_id(1)).model_dump(mode="json")

    assert loaded.manifest.store_format_version == 2
    assert served == expected
    for pending_entries in loaded.cnvd_index.pending_by_cve_id.values():
        assert pending_entries[0].entry.products == ()
        assert pending_entries[0].entry.handling_advice is None


def test_missing_optional_raw_fields_serve_empty_values_and_no_cve_is_counted(
    tmp_path: Path,
) -> None:
    record = build_raw_cnvd_record(1)
    for field_name in ("products", "submitTime", "openTime", "formalWay"):
        del record[field_name]
    scenario = build_raw_cnvd_scenario(tmp_path, [record, build_raw_cnvd_record(2, cves=[])])

    corpus, report = import_scenario(scenario)

    assert report.cnvd_outcomes[CnvdOutcome.WITHOUT_CVE_ID] == 1
    entry = corpus.records[0].cnvd[0]
    assert entry.products == ()
    assert entry.submit_time is None
    assert entry.open_time is None
    assert entry.handling_advice is None
    assert build_search_service(corpus).describe_cnvd().imported


@pytest.mark.parametrize(
    "cap", ["bytes", "rows", "entry"], ids=["file-cap", "total-row-cap", "line-cap"]
)
def test_raw_inputs_obey_resource_caps_and_leave_no_store(tmp_path: Path, cap: str) -> None:
    scenario = build_raw_cnvd_scenario(
        tmp_path,
        [build_raw_cnvd_record(1, description="SYNTHETIC: " + "x" * 4096)],
        increment_records=[build_raw_cnvd_record(2)],
    )
    overrides = {
        "bytes": {"max_raw_cnvd_bytes": 1},
        "rows": {"max_cnvd_rows": 1},
        "entry": {"max_entry_bytes": 2048},
    }
    dependencies = dataclasses.replace(
        scenario.dependencies, limits=MigrationLimits(**overrides[cap])
    )

    report = run_test_migration(scenario.manifest, scenario.target, dependencies=dependencies)

    assert report.failure is not None
    assert (
        report.failure.code
        is {
            "bytes": MigrationFailureCode.CNVD_FILE_TOO_LARGE,
            "rows": MigrationFailureCode.CNVD_TOO_MANY_ROWS,
            "entry": MigrationFailureCode.CNVD_INVALID_RECORD,
        }[cap]
    )
    assert not scenario.target.exists()


def test_cli_text_lookup_shows_raw_fields_and_research_credit(tmp_path: Path) -> None:
    scenario = build_raw_cnvd_scenario(tmp_path, [build_raw_cnvd_record(1)])
    corpus, _ = import_scenario(scenario)

    text = render_lookup_summary(build_search_service(corpus).lookup(build_cve_id(1)))

    assert "CNVD product: SYNTHETIC: Example Gateway <2.0" in text
    assert "CNVD submitTime: 2026-10-01" in text
    assert "CNVD openTime: 2026-10-02" in text
    assert "CNVD handling advice: SYNTHETIC:" in text
    assert "licence unverified" in text


def test_identical_increment_bytes_still_replace_provenance_and_change_import_identity(
    tmp_path: Path,
) -> None:
    base_directory = tmp_path / "base-only"
    base_directory.mkdir()
    base = build_raw_cnvd_scenario(base_directory, [build_raw_cnvd_record(1)])
    _, base_report = import_scenario(base)
    increment_directory = tmp_path / "with-increment"
    increment_directory.mkdir()
    increment = build_raw_cnvd_scenario(
        increment_directory,
        [build_raw_cnvd_record(1)],
        increment_records=[build_raw_cnvd_record(1)],
    )

    corpus, increment_report = import_scenario(increment)

    assert increment_report.import_identity_sha256 != base_report.import_identity_sha256
    assert len(corpus.records[0].cnvd) == 1
    for anchor in corpus.evidence:
        if anchor.source_name == "vulnerability-lookup-cnvd":
            assert anchor.retrieved_at.isoformat() == "2026-10-24T09:30:00+00:00"
