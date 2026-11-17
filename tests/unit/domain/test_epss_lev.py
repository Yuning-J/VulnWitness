"""NIST CSWP 41 LEV over supplied EPSS observations: a lower bound with its coverage."""

from datetime import date, timedelta

import pytest

from vulnwitness.domain.epss import EpssObservation, compute_lev, latest_observation

DAY0 = date(2026, 1, 1)


def observe(offset: int, epss: float) -> EpssObservation:
    return EpssObservation(score_date=DAY0 + timedelta(days=offset), epss=epss, percentile=0.5)


def test_daily_scores_give_lev2() -> None:
    estimate = compute_lev([observe(0, 0.3), observe(1, 0.3), observe(2, 0.3)], DAY0 + timedelta(2))

    assert estimate.lev == pytest.approx(1 - (1 - 0.3 / 30) ** 3)
    assert (estimate.covered_days, estimate.span_days) == (3, 3)


def test_thirty_day_spacing_gives_lev() -> None:
    estimate = compute_lev([observe(0, 0.5), observe(30, 0.5)], DAY0 + timedelta(59))

    assert estimate.lev == pytest.approx(0.75)
    assert (estimate.covered_days, estimate.span_days) == (60, 60)


def test_the_last_window_stops_at_the_reference_date() -> None:
    estimate = compute_lev([observe(0, 0.6)], DAY0 + timedelta(14))

    assert estimate.lev == pytest.approx(0.6 * 15 / 30)
    assert estimate.covered_days == 15


def test_uncovered_days_lower_the_bound_and_are_counted() -> None:
    estimate = compute_lev([observe(0, 0.5), observe(60, 0.5)], DAY0 + timedelta(60))

    assert estimate.lev == pytest.approx(1 - 0.5 * (1 - 0.5 / 30))
    assert (estimate.covered_days, estimate.span_days) == (31, 61)


def test_scores_after_the_reference_date_are_not_used() -> None:
    observations = [observe(0, 0.1), observe(10, 0.9)]

    estimate = compute_lev(observations, DAY0 + timedelta(5))
    latest = latest_observation(observations, DAY0 + timedelta(5))

    assert estimate.lev == pytest.approx(0.1 * 6 / 30)
    assert latest is not None and latest.epss == 0.1
    with pytest.raises(ValueError, match="no EPSS observation"):
        compute_lev(observations, DAY0 - timedelta(1))
