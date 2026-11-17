"""Explicit product reads, grouped deterministically without a relevance ranking."""

from collections.abc import Iterable
from functools import partial
from operator import is_
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, model_validator

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.cve import AffectedProduct, CveId, CveRecord
from vulnwitness.domain.evidence import EvidenceAnchor
from vulnwitness.domain.nvd_version_note import NvdVersionNote
from vulnwitness.domain.search import (
    MAX_RESULTS_PER_CALL,
    SCHEMA_VERSION,
    FilterName,
    JsonInteger,
    SchemaVersion,
)
from vulnwitness.domain.source_version_note import SourceVersionNote

PRODUCT_ORDER_DESCRIPTION = (
    "Grouping, not ranking: with a version, hit, unknown, then no_hit; "
    "then product_field before description_mention, newest published first "
    "(missing dates last), then CVE ID ascending. Version never excludes a CVE."
)


class ProductQueryRequest(ContractModel):
    """At least one whole vendor or product name; version is never search text."""

    model_config = ConfigDict(
        json_schema_extra={
            "anyOf": [
                {"required": ["vendor"], "properties": {"vendor": {"type": "string"}}},
                {"required": ["product"], "properties": {"product": {"type": "string"}}},
            ]
        }
    )

    vendor: FilterName | None = Field(
        default=None,
        description="Exact CPE vendor name, case-folded; punctuation and whitespace retained.",
    )
    product: FilterName | None = Field(
        default=None,
        description="Exact CPE product name, case-folded; punctuation and whitespace retained.",
    )
    version: FilterName | None = None
    limit: JsonInteger = Field(default=20, ge=1, le=MAX_RESULTS_PER_CALL)
    cursor: str | None = Field(
        default=None,
        max_length=8192,
        description=(
            "Opaque continuation from next_cursor; pass unchanged with the same vendor, "
            "product, version and limit against the same served corpus."
        ),
    )

    @model_validator(mode="after")
    def require_product_or_vendor(self) -> Self:
        if self.vendor is None and self.product is None:
            raise ValueError("at least one of product or vendor is required")
        return self


class ProductIdentity(ContractModel):
    """One matched vendor:product, with both names case-folded."""

    vendor: str
    product: str


class ProductFieldBasis(ContractModel):
    kind: Literal["product_field"] = "product_field"
    matched_products: tuple[ProductIdentity, ...] = Field(min_length=1)


class DescriptionMentionBasis(ContractModel):
    kind: Literal["description_mention"] = "description_mention"
    matched_phrase: str = Field(min_length=1, description="Consecutive project-tokenizer tokens.")


ProductMatchBasis = Annotated[
    ProductFieldBasis | DescriptionMentionBasis, Field(discriminator="kind")
]


class ProductVulnerability(ContractModel):
    record: CveRecord
    basis: ProductMatchBasis
    nvd_version_note: NvdVersionNote | None = None
    source_version_notes: tuple[SourceVersionNote, ...] | None = Field(
        default=None,
        exclude_if=partial(is_, None),
        description="Source statements in feed order; omitted without a version or before "
        "store format 4, empty when no source product matches. Never applicability.",
    )
    applicability: Literal["unknown"] = "unknown"


MAX_SOURCE_NAMED_CANDIDATES = 50
SOURCE_NAMED_STATEMENT = (
    "Records whose CNA or ADP affected data names the requested vendor and product, "
    "compared case-folded with spaces, hyphens and underscores alike, that neither NVD's CPE "
    "data nor a description mention matched. The names are the source's untrusted text; a "
    "candidate is for review and is not part of the inventory or its count."
)


class SourceNamedCandidate(ContractModel):
    cve_id: CveId
    source: str = Field(description="The CNA or ADP whose affected data names the product.")
    vendor: str | None = Field(description="The source's vendor text, verbatim; untrusted.")
    product: str | None = Field(description="The source's product text, verbatim; untrusted.")
    nvd_status: str | None = Field(description="NVD 2.0 vulnStatus verbatim.")


class ProductQueryResponse(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    vendor: str | None
    product: str | None
    version: str | None
    limit: JsonInteger = Field(ge=1, le=MAX_RESULTS_PER_CALL, description="Requested page size.")
    cursor: str | None = Field(
        description="The requested continuation, or null for the first page."
    )
    next_cursor: str | None = Field(description="Opaque continuation, or null on the final page.")
    items: tuple[ProductVulnerability, ...] = Field(
        max_length=MAX_RESULTS_PER_CALL, description=PRODUCT_ORDER_DESCRIPTION
    )
    total_available: JsonInteger = Field(ge=0, description="Matching CVEs across all pages.")
    description_mentions_vendor_unconfirmed: JsonInteger = Field(
        ge=0,
        description=(
            "CVEs with no implicated products whose descriptions name the requested product "
            "but not the requested vendor as whole-token phrases, excluded across all pages. "
            "Zero unless both vendor and product are supplied; mentions do not establish ownership."
        ),
    )
    matched_products: tuple[ProductIdentity, ...] = Field(
        description=(
            "All matched vendor:product pairs across all pages, sorted by vendor then product. "
            "Without a vendor, every matching vendor is included; narrow with vendor."
        )
    )
    evidence: tuple[EvidenceAnchor, ...]
    source_named_total: JsonInteger = Field(
        default=0, ge=0, description="Source-named candidates across the whole corpus."
    )
    source_named_candidates: tuple[SourceNamedCandidate, ...] = Field(
        default=(),
        max_length=MAX_SOURCE_NAMED_CANDIDATES,
        description=SOURCE_NAMED_STATEMENT + " Newest CVE IDs first, capped; identical on "
        "every page.",
    )


def list_product_identities(entries: Iterable[AffectedProduct]) -> tuple[ProductIdentity, ...]:
    """Unique case-folded vendor/product identities, sorted independently of record order."""
    identities: set[tuple[str, str]] = set()
    for entry in entries:
        identities.add((entry.vendor.casefold(), entry.product.casefold()))
    products: list[ProductIdentity] = []
    for vendor, product in sorted(identities):
        products.append(ProductIdentity(vendor=vendor, product=product))
    return tuple(products)
