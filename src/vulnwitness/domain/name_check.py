"""Deterministic CNVD title overlap with NVD CPE names, computed only for serving."""

import re
from operator import not_
from typing import Final, Literal, Self

from pydantic import ConfigDict, Field, model_validator

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.cve import CnvdEntry, CveRecord

NAME_CHECK_STATEMENT: Final = (
    "Name overlap is evidence for review, not a judgement that the link is right or wrong. "
    "Either source's names may be wrong."
)
NAME_PREFIXES: Final = ("多款", "多个")
NAME_RUN: Final = re.compile(r"[A-Za-z0-9 ._+\-/&,'():!]*")
TOKEN_SEPARATORS: Final = re.compile(r"[\s._+\-/&,'():!]+")
ORGANISATION_SUFFIXES: Final = frozenset(
    {"project", "inc", "llc", "corporation", "foundation", "software", "technologies"}
)
NameCheckResult = Literal[
    "vendor_product_overlap", "product_overlap", "vendor_overlap", "no_overlap", "uncheckable"
]
UncheckableReason = Literal["no_nvd_record", "no_affected_products", "no_extractable_name"]


class NvdNamePair(ContractModel):
    vendor: str = Field(min_length=1)
    product: str = Field(min_length=1)


class CnvdNameCheck(ContractModel):
    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {"properties": {"result": {"const": "uncheckable"}}},
                    "then": {
                        "required": ["uncheckable_reason"],
                        "properties": {"uncheckable_reason": {"type": "string"}},
                    },
                    "else": {"not": {"required": ["uncheckable_reason"]}},
                },
                {
                    "if": {"properties": {"result": {"enum": ["no_overlap", "uncheckable"]}}},
                    "then": {"properties": {"nvd_pair": {"type": "null"}}},
                    "else": {"properties": {"nvd_pair": {"type": "object"}}},
                },
            ]
        }
    )

    result: NameCheckResult
    uncheckable_reason: UncheckableReason | None = Field(default=None, exclude_if=not_)
    rule: Literal["cnvd_title_vs_nvd_cpe_names"] = "cnvd_title_vs_nvd_cpe_names"
    cnvd_name: str | None
    nvd_pair: NvdNamePair | None
    statement: Literal[
        "Name overlap is evidence for review, not a judgement that the link is right or wrong. "
        "Either source's names may be wrong."
    ] = NAME_CHECK_STATEMENT

    @model_validator(mode="after")
    def check_label_consistency(self) -> Self:
        if (self.result == "uncheckable") != (self.uncheckable_reason is not None):
            raise ValueError("a reason is required exactly when the name check is uncheckable")
        has_overlap = self.result not in ("no_overlap", "uncheckable")
        if has_overlap != (self.nvd_pair is not None):
            raise ValueError("an NVD pair is required exactly when names overlap")
        return self


def tokenise_name(name: str) -> tuple[str, ...]:
    tokens = []
    for token in TOKEN_SEPARATORS.split(name.lower()):
        if token:
            tokens.append(token)
    return tuple(tokens)


def check_cnvd_name(entry: CnvdEntry, record: CveRecord | None) -> CnvdNameCheck:
    """Label title/CPE overlap using ADR 0017's fixed rule, without judging the link.

    Every affected pair participates regardless of status. Missing NVD records take
    precedence over missing affected products, then missing extractable title names.
    Overlap ties use the first qualifying pair in vendor/product order.
    """
    title = entry.title
    for prefix in NAME_PREFIXES:
        if title.startswith(prefix):
            title = title.removeprefix(prefix)
            break
    name_run = NAME_RUN.match(title)
    assert name_run is not None
    cnvd_name = name_run.group().strip()
    reason: UncheckableReason | None = None
    if record is None:
        reason = "no_nvd_record"
    elif not record.affected:
        reason = "no_affected_products"
    elif not cnvd_name:
        reason = "no_extractable_name"
    if reason is not None:
        return CnvdNameCheck(
            result="uncheckable",
            uncheckable_reason=reason,
            cnvd_name=cnvd_name or None,
            nvd_pair=None,
        )
    assert record is not None
    title_tokens = tokenise_name(cnvd_name)
    joined_title_tokens: set[str] = set()
    for start in range(len(title_tokens)):
        for end in range(start + 2, len(title_tokens) + 1):
            joined_title_tokens.add("".join(title_tokens[start:end]))
    nvd_pairs: set[tuple[str, str]] = set()
    for affected in record.affected:
        nvd_pairs.add((affected.vendor, affected.product))
    product_pair: NvdNamePair | None = None
    vendor_pair: NvdNamePair | None = None
    for vendor, product in sorted(nvd_pairs):
        vendor_tokens = tokenise_name(vendor)
        product_tokens = tokenise_name(product)
        vendor_overlaps = "".join(vendor_tokens) in joined_title_tokens or any(
            token in title_tokens and token not in ORGANISATION_SUFFIXES for token in vendor_tokens
        )
        product_overlaps = "".join(product_tokens) in joined_title_tokens or (
            bool(product_tokens) and product_tokens[0] in title_tokens
        )
        nvd_pair = NvdNamePair(vendor=vendor, product=product)
        if vendor_overlaps and product_overlaps:
            return CnvdNameCheck(
                result="vendor_product_overlap", cnvd_name=cnvd_name, nvd_pair=nvd_pair
            )
        if product_overlaps and product_pair is None:
            product_pair = nvd_pair
        if vendor_overlaps and vendor_pair is None:
            vendor_pair = nvd_pair
    if product_pair is not None:
        return CnvdNameCheck(result="product_overlap", cnvd_name=cnvd_name, nvd_pair=product_pair)
    if vendor_pair is not None:
        return CnvdNameCheck(result="vendor_overlap", cnvd_name=cnvd_name, nvd_pair=vendor_pair)
    return CnvdNameCheck(result="no_overlap", cnvd_name=cnvd_name, nvd_pair=None)
