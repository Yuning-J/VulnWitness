"""Load-time postings for exact product fields and eligible description tokens."""

from collections.abc import Sequence

from vulnwitness.domain.cve import CveRecord
from vulnwitness.domain.text import tokenize


class ProductQueryIndex:
    """Record IDs only; same-entry and consecutive-phrase checks belong to the query.

    Description postings contain only records with no implicated products. Unaffected
    entries therefore do not prevent a record from entering the description index.
    Build once alongside a read-only repository and share it across requests.
    """

    def __init__(self, records: Sequence[CveRecord]) -> None:
        self._vendor_records: dict[str, set[str]] = {}
        self._product_records: dict[str, set[str]] = {}
        self._description_records: dict[str, set[str]] = {}
        for record in records:
            implicated_entries = record.list_implicated_products()
            for entry in implicated_entries:
                self._vendor_records.setdefault(entry.vendor.casefold(), set()).add(record.cve_id)
                self._product_records.setdefault(entry.product.casefold(), set()).add(record.cve_id)
            if not implicated_entries:
                for description in record.descriptions:
                    for token in tokenize(description.value):
                        self._description_records.setdefault(token, set()).add(record.cve_id)

    def find_candidates(
        self, vendor: str | None, product: str | None, phrase_tokens: list[str]
    ) -> set[str]:
        """A superset of matches, including product mentions whose vendor is unconfirmed.

        Intersect only the product phrase tokens for descriptions: intersecting vendor
        tokens here would lose the vendor-unconfirmed count.
        """
        field_postings: list[set[str]] = []
        if vendor is not None:
            field_postings.append(self._vendor_records.get(vendor, set()))
        if product is not None:
            field_postings.append(self._product_records.get(product, set()))
        candidates = intersect_postings(field_postings)
        description_postings: list[set[str]] = []
        for token in set(phrase_tokens):
            description_postings.append(self._description_records.get(token, set()))
        candidates.update(intersect_postings(description_postings))
        return candidates


def intersect_postings(postings: list[set[str]]) -> set[str]:
    """Copy the smallest posting before intersecting, keeping shared indexes immutable."""
    if not postings:
        return set()
    ordered_postings = sorted(postings, key=len)
    record_ids = ordered_postings[0].copy()
    for posting in ordered_postings[1:]:
        record_ids.intersection_update(posting)
        if not record_ids:
            break
    return record_ids
