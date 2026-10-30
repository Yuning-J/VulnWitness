"""Okapi BM25 weights: textbook k1 = 1.2 and b = 0.75, checked against hand-computed values."""

import pytest

from cve_kgrag.domain.bm25 import (
    compute_inverse_document_frequency,
    compute_length_saturation,
    compute_term_weight,
)


@pytest.mark.parametrize(
    ("document_count", "document_frequency", "expected_idf"),
    [(3, 1, 0.980829), (3, 3, 0.133531), (100, 1, 4.209655)],
    ids=["one_of_three", "every_document", "one_of_a_hundred"],
)
def test_inverse_document_frequency_matches_the_okapi_formula(
    document_count: int, document_frequency: int, expected_idf: float
) -> None:
    idf = compute_inverse_document_frequency(document_count, document_frequency)

    assert idf == pytest.approx(expected_idf, abs=1e-6)


def test_term_in_every_document_still_weighs_more_than_zero() -> None:
    idf = compute_inverse_document_frequency(5, 5)

    assert idf > 0


@pytest.mark.parametrize(
    ("document_length", "average_length", "expected_saturation"),
    [(100, 100.0, 1.2), (200, 100.0, 2.1), (50, 100.0, 0.75), (0, 0.0, 0.3)],
    ids=["average_length", "twice_the_average", "half_the_average", "no_words_anywhere"],
)
def test_length_saturation_grows_with_length_relative_to_the_average(
    document_length: int, average_length: float, expected_saturation: float
) -> None:
    saturation = compute_length_saturation(document_length, average_length)

    assert saturation == pytest.approx(expected_saturation)


@pytest.mark.parametrize(
    ("idf", "term_count", "length_saturation", "expected_weight"),
    [(1.0, 1, 1.2, 1.0), (2.0, 3, 1.2, 3.142857)],
    ids=["one_span_average_length", "three_spans_average_length"],
)
def test_term_weight_matches_the_okapi_formula(
    idf: float, term_count: int, length_saturation: float, expected_weight: float
) -> None:
    weight = compute_term_weight(idf, term_count, length_saturation)

    assert weight == pytest.approx(expected_weight, abs=1e-6)


def test_term_weight_saturates_below_idf_times_k1_plus_one() -> None:
    two_span_weight = compute_term_weight(1.0, 2, 1.2)
    thousand_span_weight = compute_term_weight(1.0, 1000, 1.2)

    assert two_span_weight < thousand_span_weight < 2.2
