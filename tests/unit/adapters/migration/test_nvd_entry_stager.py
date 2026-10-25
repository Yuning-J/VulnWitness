"""Proves how the stager reads an NVD modification time (ADR 0008 §5): ``parse_nvd_time``
reads every form a feed writes, as UTC, and gives ``None`` for a time UTC cannot
express; ``to_microseconds`` counts exact microseconds from the Unix epoch on either
side of it and far into the future, so candidates compare in time order."""

from datetime import UTC, datetime

import pytest

from cve_kgrag.adapters.migration.nvd_entry_stager import parse_nvd_time, to_microseconds

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    ("moment", "expected_microseconds"),
    [
        (datetime(1969, 12, 31, 23, 59, 59, 500_000, tzinfo=UTC), -500_000),
        (EPOCH, 0),
        (datetime(2026, 10, 24, 8, 30, tzinfo=UTC), 1_792_830_600_000_000),
        (datetime(5000, 1, 1, 0, 0, 0, 999_999, tzinfo=UTC), 95_617_584_000_999_999),
    ],
    ids=["half_second_before_the_epoch", "the_epoch", "current_time", "far_future_with_fraction"],
)
def test_to_microseconds_counts_exact_microseconds_from_the_epoch(
    moment: datetime, expected_microseconds: int
) -> None:
    # Act
    microseconds = to_microseconds(moment)

    # Assert
    assert microseconds == expected_microseconds


def test_to_microseconds_keeps_time_order_across_the_epoch() -> None:
    # Arrange
    moments_in_order = [
        datetime(1969, 12, 31, 23, 59, 58, 999_999, tzinfo=UTC),
        datetime(1969, 12, 31, 23, 59, 59, 999_999, tzinfo=UTC),
        EPOCH,
        datetime(1970, 1, 1, 0, 0, 0, 1, tzinfo=UTC),
    ]

    # Act
    microseconds_in_order: list[int] = []
    for moment in moments_in_order:
        microseconds_in_order.append(to_microseconds(moment))

    # Assert
    assert microseconds_in_order == [-1_000_001, -1, 0, 1]


@pytest.mark.parametrize(
    ("time_text", "expected_moment"),
    [
        ("2099-01-03T00:00:00.000Z", datetime(2099, 1, 3, tzinfo=UTC)),
        ("2099-01-03T00:00:00.000", datetime(2099, 1, 3, tzinfo=UTC)),
        ("2099-01-03T02:00:00+02:00", datetime(2099, 1, 3, tzinfo=UTC)),
        ("2099-01-02T19:00:00-05:00", datetime(2099, 1, 3, tzinfo=UTC)),
        ("2099-01-03T00:00Z", datetime(2099, 1, 3, tzinfo=UTC)),
        ("2099-01-03T00:00", datetime(2099, 1, 3, tzinfo=UTC)),
        ("2099-01-03T00:00:00.5Z", datetime(2099, 1, 3, 0, 0, 0, 500_000, tzinfo=UTC)),
        ("2099-01-03T00:00:00.1234567Z", datetime(2099, 1, 3, 0, 0, 0, 123_456, tzinfo=UTC)),
    ],
    ids=[
        "z_suffix",
        "no_offset_is_utc",
        "positive_offset",
        "negative_offset",
        "minutes_with_z",
        "minutes_without_offset",
        "short_fraction",
        "fraction_truncated_to_microseconds",
    ],
)
def test_parse_nvd_time_reads_every_feed_form_as_utc(
    time_text: str, expected_moment: datetime
) -> None:
    # Act
    moment = parse_nvd_time(time_text)

    # Assert
    assert moment == expected_moment
    assert moment is not None and moment.tzinfo is UTC


@pytest.mark.parametrize(
    "time_text",
    ["9999-12-31T23:59:00-01:00", "0001-01-01T00:00:00+01:00"],
    ids=["after_the_last_utc_moment", "before_the_first_utc_moment"],
)
def test_parse_nvd_time_returns_none_for_a_time_utc_cannot_express(time_text: str) -> None:
    # Act
    moment = parse_nvd_time(time_text)

    # Assert
    assert moment is None
