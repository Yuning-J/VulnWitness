"""Terms backed by the question or the products of admitted CVE records."""

from collections.abc import Sequence

from cve_kgrag.domain.cpe import split_cpe
from cve_kgrag.domain.cve import CveRecord
from cve_kgrag.domain.relevance import TermSource
from cve_kgrag.domain.text import list_query_terms, normalize_query


def is_question_component(component: str, question: str) -> bool:
    """A component is a contiguous sequence of the question's normalized search terms."""
    component_terms = list_query_terms(normalize_query(component))
    question_terms = list_query_terms(normalize_query(question))
    if not component_terms:
        return False
    for position in range(len(question_terms) - len(component_terms) + 1):
        if question_terms[position : position + len(component_terms)] == component_terms:
            return True
    return False


def list_term_sources(
    question_terms: Sequence[str], records: Sequence[CveRecord]
) -> dict[str, TermSource]:
    """First source per term: question, then admitted record/field in encounter order."""
    sources: dict[str, TermSource] = {}
    for term in question_terms:
        sources[term] = TermSource(term=term, field="question")
    for record in records:
        for product in record.list_implicated_products():
            for field, name in (("vendor", product.vendor), ("product", product.product)):
                for term in list_query_terms(name):
                    if term not in sources:
                        sources[term] = TermSource.model_validate(
                            {"term": term, "cve_id": record.cve_id, "field": field}
                        )
            if product.cpe is None:
                continue
            components = split_cpe(product.cpe)
            if len(components) < 3:
                continue
            for term in list_query_terms(components[2]):
                if term not in sources:
                    sources[term] = TermSource(term=term, cve_id=record.cve_id, field="cpe_product")
    return sources
