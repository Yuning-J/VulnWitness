"""In-memory BM25 index over CVE descriptions, vendors, products and CWE IDs.

The index is inverted: each term keeps the records that hold it in three arrays of machine
numbers, so a term costs one ``TermPostings`` and three arrays however many records hold
it. A search adds up scores in a dict of numbers for the records holding a query term and
builds match objects only for the ``limit`` best, so a term found in most records costs
arithmetic, not an object per record that lives until the ranking ends.
"""

import heapq
import math
from array import array
from bisect import bisect_left
from collections import Counter
from collections.abc import Iterable, Set
from dataclasses import dataclass

from cve_kgrag.domain.cve import CveRecord
from cve_kgrag.domain.search import RetrievalMatch, RetrievalOutcome
from cve_kgrag.domain.taxonomy import BackendStatus
from cve_kgrag.domain.text import tokenize

# Standard Okapi BM25 parameters.
TERM_SATURATION_K1 = 1.2
LENGTH_NORMALIZATION_B = 0.75
INDEXED_FIELDS = ("description", "vendor", "product", "cwe_ids")
SCORE_DECIMALS = 6


@dataclass(frozen=True, slots=True)
class TermPostings:
    """The records holding one term, in ascending CVE ID order: each record's position in
    the index, how often the term occurs in it, and one bit per ``INDEXED_FIELDS`` entry
    whose text holds the term."""

    record_positions: "array[int]"
    term_counts: "array[int]"
    field_masks: "array[int]"


def extract_field_texts(record: CveRecord) -> dict[str, list[str]]:
    field_texts: dict[str, list[str]] = {}
    for field_name in INDEXED_FIELDS:
        field_texts[field_name] = []
    for description in record.descriptions:
        field_texts["description"].append(description.value)
    for affected_product in record.list_implicated_products():
        field_texts["vendor"].append(affected_product.vendor)
        field_texts["product"].append(affected_product.product)
    field_texts["cwe_ids"].extend(record.cwe_ids)
    return field_texts


def count_record_terms(record: CveRecord) -> tuple[Counter[str], dict[str, int]]:
    """How often each term occurs across the record's indexed fields, and the bit mask of
    the fields holding it."""
    term_counts: Counter[str] = Counter()
    field_masks: dict[str, int] = {}
    field_texts = extract_field_texts(record)
    for field_number, field_name in enumerate(INDEXED_FIELDS):
        field_tokens = tokenize(" ".join(field_texts[field_name]))
        term_counts.update(field_tokens)
        for token in field_tokens:
            field_masks[token] = field_masks.get(token, 0) | (1 << field_number)
    return term_counts, field_masks


def list_fields_in_mask(field_mask: int) -> tuple[str, ...]:
    """The ``INDEXED_FIELDS`` names whose bit is set in ``field_mask``, in that order."""
    fields_in_mask: list[str] = []
    for field_number, field_name in enumerate(INDEXED_FIELDS):
        if field_mask & (1 << field_number):
            fields_in_mask.append(field_name)
    return tuple(fields_in_mask)


class Bm25LexicalIndex:
    """Implements ``LexicalRetriever``; built once from records, read-only afterwards."""

    def __init__(self, records: Iterable[CveRecord]) -> None:
        self._cve_ids: list[str] = []
        record_lengths: list[int] = []
        self._postings: dict[str, TermPostings] = {}
        for record in sorted(records, key=lambda record: record.cve_id):
            record_position = len(self._cve_ids)
            self._cve_ids.append(record.cve_id)
            term_counts, field_masks = count_record_terms(record)
            record_lengths.append(sum(term_counts.values()))
            for term, term_count in term_counts.items():
                self._add_posting(term, record_position, term_count, field_masks[term])
        average_length = sum(record_lengths) / len(record_lengths) if record_lengths else 0.0
        # Each record's share of a term's saturation, K1 * (1 - B + B * length / average).
        # An average of 0 means no record holds a term, so no search reads it.
        self._length_saturations = array("d")
        for record_length in record_lengths:
            length_ratio = record_length / average_length if average_length else 0.0
            self._length_saturations.append(
                TERM_SATURATION_K1
                * (1 - LENGTH_NORMALIZATION_B + LENGTH_NORMALIZATION_B * length_ratio)
            )

    def search(
        self, query_text: str, limit: int, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        # Terms are scored in sorted order so a record's score sums the same terms in the
        # same order whatever the query's word order.
        query_terms = sorted(set(tokenize(query_text)))
        record_scores: dict[int, float] = {}
        for term in query_terms:
            postings = self._postings.get(term)
            if postings is None:
                continue
            inverse_document_frequency = self._compute_inverse_document_frequency(postings)
            for record_position, term_count in zip(
                postings.record_positions, postings.term_counts, strict=True
            ):
                if (
                    allowed_cve_ids is not None
                    and self._cve_ids[record_position] not in allowed_cve_ids
                ):
                    continue
                saturation = term_count + self._length_saturations[record_position]
                record_scores[record_position] = (
                    record_scores.get(record_position, 0.0)
                    + inverse_document_frequency
                    * term_count
                    * (TERM_SATURATION_K1 + 1)
                    / saturation
                )
        # Best rounded score first, ties by position, which is ascending CVE ID order.
        ranked_positions = heapq.nsmallest(
            limit,
            record_scores,
            key=lambda record_position: (
                -round(record_scores[record_position], SCORE_DECIMALS),
                record_position,
            ),
        )
        matches: list[RetrievalMatch] = []
        for record_position in ranked_positions:
            matches.append(
                self._build_match(record_position, record_scores[record_position], query_terms)
            )
        return RetrievalOutcome(status=BackendStatus.OK, matches=tuple(matches))

    def _add_posting(
        self, term: str, record_position: int, term_count: int, field_mask: int
    ) -> None:
        postings = self._postings.get(term)
        if postings is None:
            postings = TermPostings(array("I"), array("I"), array("B"))
            self._postings[term] = postings
        postings.record_positions.append(record_position)
        postings.term_counts.append(term_count)
        postings.field_masks.append(field_mask)

    def _compute_inverse_document_frequency(self, postings: TermPostings) -> float:
        record_count = len(self._cve_ids)
        document_frequency = len(postings.record_positions)
        return math.log(1 + (record_count - document_frequency + 0.5) / (document_frequency + 0.5))

    def _build_match(
        self, record_position: int, score: float, query_terms: list[str]
    ) -> RetrievalMatch:
        matched_terms: list[str] = []
        field_mask = 0
        for term in query_terms:
            postings = self._postings.get(term)
            if postings is None:
                continue
            posting_number = bisect_left(postings.record_positions, record_position)
            if (
                posting_number < len(postings.record_positions)
                and postings.record_positions[posting_number] == record_position
            ):
                matched_terms.append(term)
                field_mask |= postings.field_masks[posting_number]
        return RetrievalMatch(
            cve_id=self._cve_ids[record_position],
            score=round(score, SCORE_DECIMALS),
            matched_fields=list_fields_in_mask(field_mask),
            matched_terms=tuple(matched_terms),
        )
