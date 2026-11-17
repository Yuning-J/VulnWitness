"""Product inventory entry over structured records and CPE-less description mentions."""

from collections.abc import Sequence

from vulnwitness.application.product_query_index import ProductQueryIndex
from vulnwitness.domain.cve import AffectedProduct, CveRecord, SourceAffectedProduct
from vulnwitness.domain.evidence import EvidenceAnchor
from vulnwitness.domain.evidence_catalog import EvidenceCatalog
from vulnwitness.domain.nvd_version_note import (
    NvdVersionNote,
    NvdVersionUnknown,
    build_nvd_version_note_for_entries,
)
from vulnwitness.domain.product_query import (
    MAX_SOURCE_NAMED_CANDIDATES,
    DescriptionMentionBasis,
    ProductFieldBasis,
    ProductMatchBasis,
    ProductQueryRequest,
    ProductQueryResponse,
    ProductVulnerability,
    SourceNamedCandidate,
    list_product_identities,
)
from vulnwitness.domain.product_query_cursor import (
    InvalidProductCursor,
    build_product_cursor,
    read_product_cursor,
)
from vulnwitness.domain.source_product import list_entry_names, normalize_source_name
from vulnwitness.domain.source_version_note import build_source_version_notes
from vulnwitness.domain.text import tokenize
from vulnwitness.domain.validation import (
    EvidenceValidationError,
    find_anchor_violations,
    find_uncatalogued_record_violations,
)
from vulnwitness.ports.repositories import CveRepository

VERSION_GROUPS = {"hit": 0, "unknown": 1, "no_hit": 2}


def description_names_phrase(record: CveRecord, phrase_tokens: list[str]) -> bool:
    """Consecutive whole tokens within one description, using the project tokenizer."""
    if not phrase_tokens:
        return False
    for description in record.descriptions:
        description_tokens = tokenize(description.value)
        for start in range(len(description_tokens) - len(phrase_tokens) + 1):
            if description_tokens[start : start + len(phrase_tokens)] == phrase_tokens:
                return True
    return False


def group_product_vulnerability(candidate: ProductVulnerability) -> tuple[int, int, float, str]:
    """Version fact, basis, newest publication (missing last), then CVE ID; never a score."""
    version_group = 0
    if candidate.nvd_version_note is not None:
        version_group = VERSION_GROUPS[candidate.nvd_version_note.outcome]
    basis_group = 0 if candidate.basis.kind == "product_field" else 1
    published = candidate.record.published
    publication_order = float("inf") if published is None else -published.timestamp()
    return version_group, basis_group, publication_order, candidate.record.cve_id


def annotate_product_version(
    entries: Sequence[AffectedProduct], name: str, version: str | None, record: CveRecord
) -> NvdVersionNote | None:
    """Reuse the NVD note for field matches; mention-only evidence cannot decide a condition."""
    if version is None:
        return None
    mention = f"{name} {version}"
    if entries:
        return build_nvd_version_note_for_entries(entries, mention, version, record)
    return NvdVersionUnknown(
        mention=mention,
        reason_code="description_mention_only",
        wording=(
            f"Version {version}: NVD CPE version condition unknown; "
            "description mention only, with no implicated product version data."
        ),
    )


def find_source_named_entry(
    record: CveRecord, vendor: str | None, product: str | None
) -> tuple[str, SourceAffectedProduct] | None:
    """The first source-stated product entry naming both requested names, in feed order."""
    for block in record.source_affected:
        for entry in block.products:
            for entry_vendor, entry_product in list_entry_names(entry):
                if vendor is not None and entry_vendor != vendor:
                    continue
                if product is not None and entry_product != product:
                    continue
                return block.source, entry
    return None


def candidate_order(cve_id: str) -> tuple[int, int]:
    """Newest CVE IDs first: year, then sequence number, both descending."""
    _, year, number = cve_id.split("-")
    return -int(year), -int(number)


class ProductQueryService:
    """Read every matching CVE without lexical scoring or version filtering.

    Vendor and product compare as whole case-folded names, as the structured search
    filter does. Both constraints must hold on the same implicated entry. Records with
    no implicated entries may instead match each explicit name as a description phrase.
    The repository owns CVE-ID uniqueness, so one record produces at most one item and
    field matches win.
    """

    def __init__(self, repository: CveRepository, evidence_catalog: EvidenceCatalog) -> None:
        self._repository = repository
        self._evidence_catalog = evidence_catalog
        self._index = ProductQueryIndex(repository.list_cves())

    def query(self, request: ProductQueryRequest) -> ProductQueryResponse:
        """Return a counted page and all matched identities. Raise ``InvalidProductCursor``
        for invalid continuations, or ``EvidenceValidationError`` for invalid evidence.
        """
        offset = read_product_cursor(request)
        vendor = request.vendor.casefold() if request.vendor is not None else None
        product = request.product.casefold() if request.product is not None else None
        name = product if product is not None else vendor
        assert name is not None  # The request contract requires one name.
        phrase_tokens = tokenize(name)
        vendor_tokens = tokenize(vendor) if vendor is not None else None
        description_mentions_vendor_unconfirmed = 0
        vulnerabilities: list[ProductVulnerability] = []
        matched_entries: list[AffectedProduct] = []
        for cve_id in self._index.find_candidates(vendor, product, phrase_tokens):
            record = self._repository.get_cve(cve_id)
            assert record is not None  # Index and repository share one immutable corpus.
            basis: ProductMatchBasis
            implicated_entries = record.list_implicated_products()
            matching_entries: list[AffectedProduct] = []
            for entry in implicated_entries:
                if vendor is not None and entry.vendor.casefold() != vendor:
                    continue
                if product is not None and entry.product.casefold() != product:
                    continue
                matching_entries.append(entry)
            if matching_entries:
                basis = ProductFieldBasis(
                    matched_products=list_product_identities(matching_entries)
                )
                matched_entries.extend(matching_entries)
            elif not implicated_entries and description_names_phrase(record, phrase_tokens):
                if (
                    product is not None
                    and vendor_tokens is not None
                    and not description_names_phrase(record, vendor_tokens)
                ):
                    description_mentions_vendor_unconfirmed += 1
                    continue
                basis = DescriptionMentionBasis(matched_phrase=" ".join(phrase_tokens))
            else:
                continue
            vulnerabilities.append(
                ProductVulnerability(
                    record=record,
                    basis=basis,
                    source_version_notes=(
                        build_source_version_notes(
                            record,
                            f"{name} {request.version}",
                            request.version,
                            vendor=vendor,
                            product=product,
                            store_format_version=self._evidence_catalog.store_format_version,
                        )
                        if request.version is not None
                        else None
                    ),
                    nvd_version_note=annotate_product_version(
                        matching_entries, name, request.version, record
                    ),
                )
            )
        vulnerabilities.sort(key=group_product_vulnerability)
        matched_ids = {vulnerability.record.cve_id for vulnerability in vulnerabilities}
        source_named = self._find_source_named(vendor, product, matched_ids)
        if request.cursor is not None and offset >= len(vulnerabilities):
            raise InvalidProductCursor("Invalid product query cursor.")
        page_end = offset + request.limit
        listed_vulnerabilities = tuple(vulnerabilities[offset:page_end])
        next_cursor = None
        if page_end < len(vulnerabilities):
            next_cursor = build_product_cursor(request, page_end)
        return ProductQueryResponse(
            vendor=vendor,
            product=product,
            version=request.version,
            limit=request.limit,
            cursor=request.cursor,
            next_cursor=next_cursor,
            items=listed_vulnerabilities,
            total_available=len(vulnerabilities),
            description_mentions_vendor_unconfirmed=description_mentions_vendor_unconfirmed,
            matched_products=list_product_identities(matched_entries),
            evidence=self._collect_evidence(listed_vulnerabilities),
            source_named_total=len(source_named),
            source_named_candidates=tuple(source_named[:MAX_SOURCE_NAMED_CANDIDATES]),
        )

    def _find_source_named(
        self, vendor: str | None, product: str | None, matched_ids: set[str]
    ) -> list[SourceNamedCandidate]:
        """Records the inventory left out whose source-stated entry names both names."""
        wanted_vendor = normalize_source_name(vendor) if vendor is not None else None
        wanted_product = normalize_source_name(product) if product is not None else None
        candidates: list[SourceNamedCandidate] = []
        for cve_id in self._index.find_source_named(vendor, product) - matched_ids:
            record = self._repository.get_cve(cve_id)
            assert record is not None  # Index and repository share one immutable corpus.
            match = find_source_named_entry(record, wanted_vendor, wanted_product)
            if match is not None:
                source, entry = match
                candidates.append(
                    SourceNamedCandidate(
                        cve_id=cve_id,
                        source=source,
                        vendor=entry.vendor,
                        product=entry.product,
                        nvd_status=record.nvd_status,
                    )
                )
        candidates.sort(key=lambda candidate: candidate_order(candidate.cve_id))
        return candidates

    def _collect_evidence(
        self, vulnerabilities: tuple[ProductVulnerability, ...]
    ) -> tuple[EvidenceAnchor, ...]:
        records: list[CveRecord] = []
        anchors_by_id: dict[str, EvidenceAnchor] = {}
        for vulnerability in vulnerabilities:
            record = vulnerability.record
            records.append(record)
            for evidence_id in record.evidence_ids:
                anchor = self._evidence_catalog.get_evidence(evidence_id)
                if anchor is None:
                    raise EvidenceValidationError(
                        [f"{record.cve_id}: missing evidence {evidence_id}"]
                    )
                anchors_by_id[evidence_id] = anchor
        violations = find_anchor_violations(anchors_by_id.values())
        violations.extend(find_uncatalogued_record_violations(records, self._evidence_catalog))
        if violations:
            raise EvidenceValidationError(violations)
        anchors: list[EvidenceAnchor] = []
        for evidence_id in sorted(anchors_by_id):
            anchors.append(anchors_by_id[evidence_id])
        return tuple(anchors)
