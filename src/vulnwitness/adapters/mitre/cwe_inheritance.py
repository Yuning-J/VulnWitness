"""Infer CAPEC links from the nearest parents in CWE view 1000's hierarchy."""

from xml.etree.ElementTree import Element

from vulnwitness.domain.weakness_associations import CweCapecInheritance


def read_cwe_parents(weakness: Element) -> tuple[str, ...]:
    """Use view 1000 ChildOf relations, preferring its marked primary parents.

    Ordinal is scoped to a view, not a designation of a primary catalogue view.
    View 1000 is the Complete Weakness Hierarchy in CWE 5.0.
    """
    parents: set[str] = set()
    primary_parents: set[str] = set()
    for relation in weakness.findall("./{*}Related_Weaknesses/{*}Related_Weakness"):
        if relation.attrib["Nature"] != "ChildOf" or relation.attrib["View_ID"] != "1000":
            continue
        parent_id = "CWE-" + relation.attrib["CWE_ID"]
        parents.add(parent_id)
        if relation.attrib.get("Ordinal") == "Primary":
            primary_parents.add(parent_id)
    return tuple(sorted(primary_parents or parents))


def collect_cwe_inheritance(
    cwe_id: str,
    direct_capecs: dict[str, tuple[str, ...]],
    cwes_with_direct_links: set[str],
    parents: dict[str, tuple[str, ...]],
) -> tuple[CweCapecInheritance, ...]:
    """Breadth-first search stops at the first depth with catalogue CAPEC links.

    Keep all paths to linked ancestors at that depth. A CWE with any catalogue
    link, including a deprecated CAPEC, never inherits. Missing parents cannot
    bridge a chain; cycles encountered during traversal refuse the build.
    """
    if cwe_id in cwes_with_direct_links:
        return ()
    pending: list[tuple[str, tuple[str, ...]]] = [(cwe_id, ())]
    while pending:
        inheritances: list[CweCapecInheritance] = []
        next_parents: list[tuple[str, tuple[str, ...]]] = []
        for ancestor_id, chain in pending:
            if ancestor_id in cwes_with_direct_links:
                if direct_capecs[ancestor_id]:
                    inheritances.append(
                        CweCapecInheritance(
                            inherited_from_cwe=ancestor_id,
                            parent_chain=chain,
                            capec_ids=direct_capecs[ancestor_id],
                        )
                    )
                continue
            for parent_id in parents[ancestor_id]:
                if parent_id == cwe_id or parent_id in chain:
                    raise ValueError("CWE ChildOf chain contains a cycle")
                if parent_id in parents:
                    next_parents.append((parent_id, (*chain, parent_id)))
        if inheritances:
            return tuple(inheritances)
        pending = next_parents
    return ()
