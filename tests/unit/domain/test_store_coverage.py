"""Coverage counts what records carry by month; the semantic digest ignores refresh noise."""

from datetime import UTC, datetime

import pytest

from tests.support.builders import build_cve_record, build_cvss_metric, build_versioned_product
from vulnwitness.domain.cve import KevEntry, Reference
from vulnwitness.domain.store_coverage import (
    diff_store_semantics,
    measure_store_coverage,
    semantic_record_sha256,
)

DIGEST = "a" * 64


def test_semantic_digest_ignores_last_modified_and_evidence_ids() -> None:
    record = build_cve_record(last_modified=datetime(2026, 1, 1, tzinfo=UTC))
    refreshed = record.model_copy(
        update={
            "last_modified": datetime(2026, 6, 17, tzinfo=UTC),
            "evidence_ids": ("ev:" + "b" * 64,),
        }
    )
    edited = record.model_copy(update={"cwe_ids": ("CWE-79",)})

    assert semantic_record_sha256(refreshed) == semantic_record_sha256(record)
    assert semantic_record_sha256(edited) != semantic_record_sha256(record)


def test_coverage_counts_each_month_and_the_total() -> None:
    enriched = build_cve_record(
        cve_id="CVE-2026-0001",
        published=datetime(2026, 3, 2, tzinfo=UTC),
        nvd_status="Analyzed",
        cvss=(build_cvss_metric(scorer="nvd@nist.gov", version="3.1"),),
        cwe_ids=("CWE-79",),
        affected=(build_versioned_product(),),
        references=(Reference(url="https://example.test/poc", tags=("Exploit",)),),
        kev=KevEntry(date_added=datetime(2026, 3, 5).date()),
    )
    not_scheduled = build_cve_record(
        cve_id="CVE-2026-0002",
        published=datetime(2026, 10, 2, tzinfo=UTC),
        nvd_status="Deferred",
        cvss=(build_cvss_metric(scorer="cna@example.test", version="4.0"),),
    )
    undated = build_cve_record(cve_id="CVE-2026-0003", nvd_status=None)

    coverage = measure_store_coverage("store", DIGEST, (enriched, not_scheduled, undated))

    months = []
    for month in coverage.months:
        months.append(month.month)
    assert months == ["2026-03", "2026-10", "unpublished"]
    march, october, unpublished = coverage.months
    assert (march.with_vulnerable_cpe, march.with_nvd_own_cvss3, march.with_cwe) == (1, 1, 1)
    assert (march.with_exploit_reference, march.kev_listed) == (1, 1)
    assert october.enrichment.not_scheduled == 1
    assert october.nvd_status == {"Deferred": 1}
    assert (october.with_nvd_own_cvss3, october.with_any_cvss, october.with_cvss4) == (0, 1, 1)
    assert unpublished.enrichment.not_recorded == 1
    assert coverage.total.month == "all"
    assert coverage.total.records == 3
    assert coverage.total.with_vulnerable_cpe == 1


def test_diff_tells_timestamp_refreshes_from_content_changes() -> None:
    kept = build_cve_record(cve_id="CVE-2026-0001")
    refreshed = build_cve_record(cve_id="CVE-2026-0002")
    edited = build_cve_record(cve_id="CVE-2026-0003")
    removed = build_cve_record(cve_id="CVE-2026-0004")
    added = build_cve_record(cve_id="CVE-2026-0005")
    new_time = datetime(2026, 6, 17, tzinfo=UTC)

    diff = diff_store_semantics(
        "old",
        (kept, refreshed, edited, removed),
        "new",
        (
            kept,
            refreshed.model_copy(update={"last_modified": new_time}),
            edited.model_copy(update={"last_modified": new_time, "cwe_ids": ("CWE-20",)}),
            added,
        ),
    )

    assert (diff.unchanged, diff.metadata_only, diff.changed) == (1, 1, 1)
    assert (diff.added_ids, diff.removed_ids, diff.changed_ids) == (
        ("CVE-2026-0005",),
        ("CVE-2026-0004",),
        ("CVE-2026-0003",),
    )
    assert diff.changed_fields == {"cwe_ids": 1}
    assert diff.old_semantic_content_sha256 != diff.new_semantic_content_sha256
    assert not diff.lists_truncated


@pytest.mark.parametrize("scorer", ["NVD", "nvd@nist.gov"])
def test_nvd_owned_metrics_count_as_nvd_coverage_and_not_source_coverage(scorer: str) -> None:
    record = build_cve_record(cvss=(build_cvss_metric(scorer=scorer),))

    coverage = measure_store_coverage("store", DIGEST, (record,))

    assert coverage.total.with_nvd_own_cvss3 == 1
    assert coverage.total.with_source_cvss == 0
