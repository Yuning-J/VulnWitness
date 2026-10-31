"""Exact served-name recognition; ambiguous names stay on lexical retrieval."""

import re
from collections.abc import Sequence

from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.product_query import ProductIdentity, ProductQueryRequest
from cve_kgrag.domain.product_recognition import ProductRecognition

# Vocabulary exclusions only: these names remain ordinary lexical search terms.
COLLISION_NAMES = frozenset({"service", "known", "smf"})


def find_name_pattern(name: str) -> re.Pattern[str]:
    return re.compile(r"(?<![0-9a-z_.-])" + re.escape(name) + r"(?![0-9a-z_.-])")


def recognize_product(
    query: str, mentions: Sequence[str], catalog: EvidenceCatalog, limit: int
) -> tuple[ProductRecognition | None, tuple[str, ...]]:
    """Recognize one whole phrase, preferring affectedness extraction when available.

    A vendor may own many products. A product must belong to exactly one vendor;
    a name used as both vendor and product must identify that same vendor. Vendor
    phrases take precedence over product-only phrases. Multiple remaining phrases
    are ambiguous. Contained shorter names defer to the longest phrase.
    """
    vocabulary = find_question_phrases(query)
    mention_versions: dict[str, str] = {}
    for mention in mentions:
        name, version = mention.rsplit(" ", 1)
        mention_versions[name] = version
    names: list[str] = []
    for name in sorted(vocabulary):
        if name in COLLISION_NAMES or not catalog.names_product(name):
            continue
        names.append(name)
    if mention_versions:
        names = []
        for name in mention_versions:
            if name not in COLLISION_NAMES:
                names.append(name)
    longest_names: list[str] = []
    for name in names:
        if not any(name != other and find_name_pattern(name).search(other) for other in names):
            longest_names.append(name)
    if not longest_names:
        return None, ()
    # An explicit vendor selects its family; incidental product words in the
    # question do not narrow it to one of that vendor's products.
    vendor_names: list[str] = []
    for name in longest_names:
        if any(identity.vendor == name for identity in catalog.find_product_identities(name)):
            vendor_names.append(name)
    if vendor_names:
        longest_names = vendor_names
    if len(longest_names) != 1:
        return None, tuple(sorted(longest_names))
    name = longest_names[0]
    selector = resolve_name(name, catalog.find_product_identities(name), limit)
    if selector is None:
        return None, (name,)
    recognized_version = mention_versions.get(name)
    if recognized_version is None:
        version_match = re.search(
            find_name_pattern(name).pattern + r" (v?[0-9]+(?:\.[0-9]+)+)(?![0-9a-z]|\.[0-9])",
            query,
        )
        if version_match is not None:
            recognized_version = version_match.group(1)
    selector = selector.model_copy(update={"version": recognized_version})
    return ProductRecognition(
        name=name,
        basis="affectedness_mention" if name in mention_versions else "exact_phrase",
        request=selector,
    ), ()


def find_question_phrases(query: str) -> set[str]:
    """Bound name probes by question length, preserving punctuation inside phrases."""
    words = tuple(re.finditer(r"[0-9a-z]+(?:[_.-][0-9a-z]+)*", query))
    phrases: set[str] = set()
    for start_index, first_word in enumerate(words):
        for last_word in words[start_index:]:
            phrases.add(query[first_word.start() : last_word.end()])
    return phrases


def resolve_name(
    name: str, identities: Sequence[ProductIdentity], limit: int
) -> ProductQueryRequest | None:
    product_vendors: set[str] = set()
    is_vendor = False
    for identity in identities:
        if identity.vendor == name:
            is_vendor = True
        if identity.product == name:
            product_vendors.add(identity.vendor)
    if len(product_vendors) > 1 or (is_vendor and product_vendors - {name}):
        return None
    if is_vendor:
        return ProductQueryRequest(vendor=name, limit=limit)
    if product_vendors:
        return ProductQueryRequest(vendor=next(iter(product_vendors)), product=name, limit=limit)
    return None


def remove_recognized_versions(query: str, mentions: Sequence[str]) -> str:
    """Remove extracted served-name version spans; preserve numbers elsewhere."""
    for mention in mentions:
        name, version = mention.rsplit(" ", 1)
        pattern = re.compile(
            r"(?<![0-9a-z_.-])("
            + re.escape(name)
            + r" )"
            + re.escape(version)
            + r"(?![0-9a-z]|\.[0-9])"
        )
        query = pattern.sub(r"\1", query)
    return query
