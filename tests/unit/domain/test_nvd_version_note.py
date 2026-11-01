"""Version annotations compare fixture conditions without asserting affectedness."""

import pytest

from tests.support.builders import build_cve_record, build_versioned_product
from vulnwitness.domain.cve import VersionRange
from vulnwitness.domain.nvd_version_note import build_nvd_version_note, list_nvd_version_notes


@pytest.mark.parametrize(
    ("version", "condition", "expected_outcome"),
    [
        ("2.7", VersionRange(start_including="2.7"), "hit"),
        ("2.6", VersionRange(start_including="2.7"), "no_hit"),
        ("2.7", VersionRange(start_excluding="2.7"), "no_hit"),
        ("2.8", VersionRange(start_excluding="2.7"), "hit"),
        ("2.7", VersionRange(end_including="2.7"), "hit"),
        ("2.8", VersionRange(end_including="2.7"), "no_hit"),
        ("2.7", VersionRange(end_excluding="2.7"), "no_hit"),
        ("2.6", VersionRange(end_excluding="2.7"), "hit"),
        ("2.7", VersionRange(exact="2.7"), "hit"),
        ("2.8", VersionRange(exact="2.7"), "no_hit"),
        ("5.10", VersionRange(start_excluding="5.9"), "hit"),
        ("5.10", VersionRange(end_including="5.9"), "no_hit"),
        ("2.7", VersionRange(exact="2.7.0"), "hit"),
        ("2.7.0", VersionRange(start_excluding="2.7"), "no_hit"),
        ("2.7", VersionRange(end_including="2.7.0"), "hit"),
        ("2.7", VersionRange(start_including="2.0", end_excluding="3.0"), "hit"),
        ("3.0", VersionRange(start_including="2.0", end_excluding="3.0"), "no_hit"),
    ],
    ids=[
        "including_start_boundary",
        "below_start",
        "excluding_start_boundary",
        "above_start",
        "including_end_boundary",
        "above_end",
        "excluding_end_boundary",
        "below_end",
        "exact_equality",
        "exact_miss",
        "numeric_order_hit",
        "numeric_order_miss",
        "missing_segment_exact",
        "missing_segment_start",
        "missing_segment_end",
        "inside_both_bounds",
        "outside_both_bounds",
    ],
)
def test_numeric_conditions_report_hits_or_no_hits_at_their_boundaries(
    version: str, condition: VersionRange, expected_outcome: str
) -> None:
    # Arrange
    entry = build_versioned_product(version_ranges=(condition,))
    record = build_cve_record(affected=(entry,))

    # Act
    note = build_nvd_version_note(record, f"demo_gateway {version}")

    # Assert
    assert note.outcome == expected_outcome
    if note.outcome == "hit":
        assert note.matched_entry == entry
        assert note.matched_condition == condition
        assert note.wording == (
            f"Version {version} matches an NVD CPE version condition for democorp:demo_gateway; "
            "the full configuration and environment conditions were not evaluated."
        )
    else:
        assert note.wording == (
            f"Version {version} matches none of the NVD CPE version conditions listed for "
            "democorp:demo_gateway; this does not show the version is unaffected."
        )
        assert "not affected" not in note.wording.lower()


def test_second_range_hit_records_the_matching_condition() -> None:
    # Arrange
    second_condition = VersionRange(start_including="5.9", end_excluding="6.0")
    entry = build_versioned_product(
        version_ranges=(VersionRange(end_excluding="2.0"), second_condition)
    )
    record = build_cve_record(affected=(entry,))

    # Act
    note = build_nvd_version_note(record, "demo_gateway 5.10")

    # Assert
    assert note.outcome == "hit"
    assert note.matched_entry == entry
    assert note.matched_condition == second_condition


@pytest.mark.parametrize("product", ["DEMO_GATEWAY", "DEMoCorp"])
def test_whole_vendor_or_product_name_matches_case_insensitively(product: str) -> None:
    # Arrange
    entry = build_versioned_product(version_ranges=(VersionRange(exact="2.7"),))
    record = build_cve_record(affected=(entry,))

    # Act
    note = build_nvd_version_note(record, f"{product} 2.7")

    # Assert
    assert note.outcome == "hit"
    assert note.matched_entry == entry


@pytest.mark.parametrize("product", ["gateway", "another_product"])
def test_partial_or_other_product_name_is_unknown(product: str) -> None:
    # Arrange
    entry = build_versioned_product(version_ranges=(VersionRange(exact="2.7"),))
    record = build_cve_record(affected=(entry,))

    # Act
    note = build_nvd_version_note(record, f"{product} 2.7")

    # Assert
    assert note.outcome == "unknown"
    assert note.reason_code == "no_matching_product"


def test_wildcard_without_bounds_is_unknown() -> None:
    # Arrange
    record = build_cve_record(affected=(build_versioned_product(),))

    # Act
    note = build_nvd_version_note(record, "demo_gateway 2.7")

    # Assert
    assert note.outcome == "unknown"
    assert note.reason_code == "no_version_condition"


@pytest.mark.parametrize(
    "version", ["2.7.0-rc1", "1.2a", "2026-10-31", "go1.20", "2..7", "2.\u0667"]
)
@pytest.mark.parametrize("non_numeric_side", ["mention", "exact", "start", "end"])
def test_non_numeric_version_on_either_side_is_unknown(version: str, non_numeric_side: str) -> None:
    # Arrange
    mentioned_version = "2.7"
    condition = VersionRange(start_including="2.0", end_excluding="3.0")
    if non_numeric_side == "mention":
        mentioned_version = version
    elif non_numeric_side == "exact":
        condition = VersionRange(exact=version)
    elif non_numeric_side == "start":
        condition = VersionRange(start_including=version)
    else:
        condition = VersionRange(end_excluding=version)
    record = build_cve_record(affected=(build_versioned_product(version_ranges=(condition,)),))

    # Act
    note = build_nvd_version_note(record, f"demo_gateway {mentioned_version}")

    # Assert
    assert note.outcome == "unknown"
    assert note.reason_code == "version_not_comparable"


def test_non_numeric_exact_condition_hits_by_trimmed_equality() -> None:
    # Arrange
    entry = build_versioned_product(version_ranges=(VersionRange(exact=" 2.7.0-rc1 "),))
    record = build_cve_record(affected=(entry,))

    # Act
    note = build_nvd_version_note(record, "demo_gateway 2.7.0-rc1")

    # Assert
    assert note.outcome == "hit"
    assert note.matched_condition == entry.version_ranges[0]


@pytest.mark.parametrize("has_hit", [False, True], ids=["unknown_without_hit", "hit_wins"])
def test_uncomparable_condition_keeps_a_miss_unknown_but_allows_another_hit(
    has_hit: bool,
) -> None:
    # Arrange
    condition = VersionRange(exact="2.7" if has_hit else "2.0")
    record = build_cve_record(
        affected=(
            build_versioned_product(version_ranges=(VersionRange(exact="2.7-rc1"),)),
            build_versioned_product(version_ranges=(condition,)),
        )
    )

    # Act
    note = build_nvd_version_note(record, "demo_gateway 2.7")

    # Assert
    if has_hit:
        assert note.outcome == "hit"
        assert note.matched_entry == record.affected[1]
    else:
        assert note.outcome == "unknown"
        assert note.reason_code == "version_not_comparable"


def test_unaffected_entry_cannot_supply_a_hit() -> None:
    # Arrange
    entry = build_versioned_product(
        status="unaffected", version_ranges=(VersionRange(exact="2.7"),)
    )
    record = build_cve_record(affected=(entry,))

    # Act
    note = build_nvd_version_note(record, "demo_gateway 2.7")

    # Assert
    assert note.outcome == "unknown"
    assert note.reason_code == "no_matching_product"


def test_missing_condition_keeps_a_comparable_miss_unknown() -> None:
    # Arrange
    record = build_cve_record(
        affected=(
            build_versioned_product(version_ranges=(VersionRange(exact="2.0"),)),
            build_versioned_product(),
        )
    )

    # Act
    note = build_nvd_version_note(record, "demo_gateway 2.7")

    # Assert
    assert note.outcome == "unknown"
    assert note.reason_code == "no_version_condition"


def test_unknown_entry_status_can_supply_a_version_condition_hit() -> None:
    # Arrange
    entry = build_versioned_product(status="unknown", version_ranges=(VersionRange(exact="2.7"),))
    record = build_cve_record(affected=(entry,))

    # Act
    note = build_nvd_version_note(record, "demo_gateway 2.7")

    # Assert
    assert note.outcome == "hit"
    assert note.matched_entry.status == "unknown"


def test_no_mentions_produces_no_annotation() -> None:
    # Arrange
    record = build_cve_record()

    # Act
    notes = list_nvd_version_notes(record, ())

    # Assert
    assert notes is None
