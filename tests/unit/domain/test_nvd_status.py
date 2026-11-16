"""NVD's displayed status labels sit beside the API values the feeds keep."""

import pytest

from tests.support.builders import build_cnvd_entry, build_cve_record
from vulnwitness.domain.nvd_status import (
    NVD_STATUSES,
    classify_nvd_enrichment,
    describe_nvd_status,
)
from vulnwitness.domain.source_comparison import NVD_STATUS_STATES, compare_cnvd_severity


@pytest.mark.parametrize(
    "api_value,described,enrichment",
    [
        ("Deferred", "Not Scheduled (API: Deferred)", "not_scheduled"),
        ("Modified", "Modified After Enrichment (API: Modified)", "enriched"),
        ("Analyzed", "Enriched (API: Analyzed)", "enriched"),
        ("Awaiting Analysis", "Awaiting Enrichment (API: Awaiting Analysis)", "pending"),
        ("Undergoing Analysis", "Undergoing Enrichment (API: Undergoing Analysis)", "pending"),
        ("Received", "Received", "pending"),
        ("Rejected", "Rejected", "rejected"),
        ("Lowest Priority", "Lowest Priority (unrecognised NVD status)", "unrecognised"),
    ],
)
def test_api_values_carry_nvd_display_labels(
    api_value: str, described: str, enrichment: str
) -> None:
    assert describe_nvd_status(api_value) == described
    assert classify_nvd_enrichment(api_value) == enrichment


def test_absent_status_is_not_recorded_rather_than_unrecognised() -> None:
    assert describe_nvd_status(None) == "not recorded"
    assert classify_nvd_enrichment(None) is None


def test_every_listed_status_has_a_comparison_state() -> None:
    assert set(NVD_STATUS_STATES) == set(NVD_STATUSES)


def test_rejected_record_compares_as_rejected_rather_than_status_unknown() -> None:
    comparison = compare_cnvd_severity(build_cnvd_entry(), build_cve_record(nvd_status="Rejected"))

    assert comparison.nvd_state == "rejected_by_nvd"
