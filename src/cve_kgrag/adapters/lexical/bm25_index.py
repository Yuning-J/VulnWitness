"""In-memory BM25 index over CVE descriptions, vendors, products and CWE IDs."""

import math
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


@dataclass(frozen=True)
class IndexedDocument:
    cve_id: str
    term_counts: Counter[str]
    length: int
    terms_by_field: dict[str, frozenset[str]]


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


def index_record(record: CveRecord) -> IndexedDocument:
    term_counts: Counter[str] = Counter()
    terms_by_field: dict[str, frozenset[str]] = {}
    for field_name, texts in extract_field_texts(record).items():
        field_tokens = tokenize(" ".join(texts))
        term_counts.update(field_tokens)
        terms_by_field[field_name] = frozenset(field_tokens)
    return IndexedDocument(
        cve_id=record.cve_id,
        term_counts=term_counts,
        length=sum(term_counts.values()),
        terms_by_field=terms_by_field,
    )


class Bm25LexicalIndex:
    """Implements ``LexicalRetriever``; built once from records, read-only afterwards."""

    def __init__(self, records: Iterable[CveRecord]) -> None:
        self._documents: list[IndexedDocument] = []
        for record in sorted(records, key=lambda record: record.cve_id):
            self._documents.append(index_record(record))
        self._document_frequency: Counter[str] = Counter()
        for document in self._documents:
            self._document_frequency.update(document.term_counts.keys())
        total_length = sum(document.length for document in self._documents)
        self._average_length = total_length / len(self._documents) if self._documents else 0.0

    def search(
        self, query_text: str, limit: int, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        query_terms = list(dict.fromkeys(tokenize(query_text)))
        matches: list[RetrievalMatch] = []
        for document in self._documents:
            if allowed_cve_ids is not None and document.cve_id not in allowed_cve_ids:
                continue
            matched_terms: list[str] = []
            for term in sorted(query_terms):
                if term in document.term_counts:
                    matched_terms.append(term)
            if not matched_terms:
                continue
            matches.append(
                RetrievalMatch(
                    cve_id=document.cve_id,
                    score=round(self._score(document, matched_terms), 6),
                    matched_fields=self._fields_containing(document, matched_terms),
                    matched_terms=tuple(matched_terms),
                )
            )
        matches.sort(key=lambda match: (-match.score, match.cve_id))
        return RetrievalOutcome(status=BackendStatus.OK, matches=tuple(matches[:limit]))

    def _score(self, document: IndexedDocument, matched_terms: list[str]) -> float:
        document_count = len(self._documents)
        length_ratio = document.length / self._average_length
        score = 0.0
        for term in matched_terms:
            document_frequency = self._document_frequency[term]
            inverse_document_frequency = math.log(
                1 + (document_count - document_frequency + 0.5) / (document_frequency + 0.5)
            )
            term_frequency = document.term_counts[term]
            saturation = term_frequency + TERM_SATURATION_K1 * (
                1 - LENGTH_NORMALIZATION_B + LENGTH_NORMALIZATION_B * length_ratio
            )
            score += (
                inverse_document_frequency * term_frequency * (TERM_SATURATION_K1 + 1) / saturation
            )
        return score

    def _fields_containing(self, document: IndexedDocument, terms: list[str]) -> tuple[str, ...]:
        matched_fields: list[str] = []
        for field_name in INDEXED_FIELDS:
            if any(term in document.terms_by_field[field_name] for term in terms):
                matched_fields.append(field_name)
        return tuple(matched_fields)
