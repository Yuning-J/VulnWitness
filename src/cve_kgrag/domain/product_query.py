"""Explicit product reads, grouped deterministically without a relevance ranking."""

from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, model_validator

from cve_kgrag.domain.contract_model import ContractModel
from cve_kgrag.domain.cve import CveRecord
from cve_kgrag.domain.evidence import EvidenceAnchor
from cve_kgrag.domain.nvd_version_note import NvdVersionNote
from cve_kgrag.domain.search import (
    MAX_RESULTS_PER_CALL,
    SCHEMA_VERSION,
    FilterName,
    JsonInteger,
    SchemaVersion,
)

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
    limit: JsonInteger = Field(default=10, ge=1, le=MAX_RESULTS_PER_CALL)

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
    applicability: Literal["unknown"] = "unknown"


class ProductQueryResponse(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    vendor: str | None
    product: str | None
    version: str | None
    limit: JsonInteger = Field(ge=1, le=MAX_RESULTS_PER_CALL, description="Requested list cap.")
    items: tuple[ProductVulnerability, ...] = Field(
        max_length=MAX_RESULTS_PER_CALL, description=PRODUCT_ORDER_DESCRIPTION
    )
    total_available: JsonInteger = Field(ge=0, description="Matching CVEs before the cap.")
    description_mentions_vendor_unconfirmed: JsonInteger = Field(
        ge=0,
        description=(
            "CVEs with no implicated products whose descriptions name the requested product "
            "but not the requested vendor as whole-token phrases, excluded before the cap. "
            "Zero unless both vendor and product are supplied; mentions do not establish ownership."
        ),
    )
    matched_products: tuple[ProductIdentity, ...] = Field(
        description=(
            "All matched vendor:product pairs before the cap, sorted by vendor then product. "
            "Without a vendor, every matching vendor is included; narrow with vendor."
        )
    )
    evidence: tuple[EvidenceAnchor, ...]
