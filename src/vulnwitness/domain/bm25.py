"""Okapi BM25 term weighting shared by the CVE lexical index and the FiGHT source.

k1 and b are the textbook defaults, fitted to neither corpus. Each index decides what a
term and a document length are; these functions only weigh them. A term's weight is
``idf * tf * (k1 + 1) / (tf + length_saturation)``, evaluated in that order so that two
indexes summing the same weights get the same float.
"""

import math

TERM_SATURATION_K1 = 1.2
LENGTH_NORMALIZATION_B = 0.75
# Scores are rounded to this many places before ranking, so float noise in the last
# bits never decides an order; ties then go to the index's own key.
SCORE_DECIMALS = 6


def compute_inverse_document_frequency(document_count: int, document_frequency: int) -> float:
    """``ln(1 + (N - df + 0.5) / (df + 0.5))``: never negative, even for a term in every
    document."""
    return math.log(1 + (document_count - document_frequency + 0.5) / (document_frequency + 0.5))


def compute_length_saturation(document_length: int, average_length: float) -> float:
    """A document's share of every term's saturation, ``k1 * (1 - b + b * length / average)``.

    An average of 0 means no document holds a word, so no search reads the value; the
    length ratio is then taken as 0 rather than dividing by zero.
    """
    length_ratio = document_length / average_length if average_length else 0.0
    return TERM_SATURATION_K1 * (1 - LENGTH_NORMALIZATION_B + LENGTH_NORMALIZATION_B * length_ratio)


def compute_term_weight(
    inverse_document_frequency: float, term_count: int, length_saturation: float
) -> float:
    """One term's contribution to a document's score; ``term_count`` is its tf there."""
    return (
        inverse_document_frequency
        * term_count
        * (TERM_SATURATION_K1 + 1)
        / (term_count + length_saturation)
    )
