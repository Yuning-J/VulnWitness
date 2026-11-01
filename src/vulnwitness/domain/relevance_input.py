"""The assessor's bounded candidate representation, shared with the experiment."""

from vulnwitness.domain.cve import CveRecord
from vulnwitness.domain.relevance import DESCRIPTION_CAP_CHARS, AssessorCandidate, AssessorProduct


def read_english_description(record: CveRecord) -> str:
    for description in record.descriptions:
        if description.lang == "en":
            return description.value
    return ""


def list_product_names(record: CveRecord) -> list[AssessorProduct]:
    """Implicated vendor/product pairs, once each in the record's order."""
    seen_pairs: set[tuple[str, str]] = set()
    product_names: list[AssessorProduct] = []
    for affected_product in record.list_implicated_products():
        name_pair = (affected_product.vendor, affected_product.product)
        if name_pair not in seen_pairs:
            seen_pairs.add(name_pair)
            product_names.append(AssessorProduct(vendor=name_pair[0], product=name_pair[1]))
    return product_names


def build_assessor_candidate(key: str, record: CveRecord) -> AssessorCandidate:
    products = list_product_names(record)
    return AssessorCandidate(
        key=key,
        description=read_english_description(record)[:DESCRIPTION_CAP_CHARS],
        affected_products=tuple(products),
        cwe_ids=record.cwe_ids,
    )
