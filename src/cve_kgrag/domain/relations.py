"""The relations a CVE record asserts, which the graph channel follows between records."""

from cve_kgrag.domain.cve import CveRecord, purl_package_identity
from cve_kgrag.domain.search import GraphRelation

Relation = tuple[GraphRelation, str]


def record_relations(record: CveRecord) -> frozenset[Relation]:
    """Relations the record itself asserts: its CWEs and its implicated products.

    A purl relation names the package without version, so different affected
    versions of one package are related.
    """
    relations: set[Relation] = set()
    for cwe_id in record.cwe_ids:
        relations.add(("cwe", cwe_id))
    for affected_product in record.list_implicated_products():
        vendor = affected_product.vendor.casefold()
        relations.add(("vendor", vendor))
        relations.add(("product", f"{vendor}/{affected_product.product.casefold()}"))
        if affected_product.cpe:
            relations.add(("cpe", affected_product.cpe))
        if affected_product.purl:
            relations.add(("purl", purl_package_identity(affected_product.purl)))
    return frozenset(relations)
