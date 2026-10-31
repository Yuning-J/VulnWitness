"""Auxiliary product recognition recorded with an investigation."""

from typing import Literal

from cve_kgrag.domain.contract_model import ContractModel
from cve_kgrag.domain.product_query import ProductQueryRequest


class ProductRecognition(ContractModel):
    name: str
    basis: Literal["affectedness_mention", "exact_phrase"]
    request: ProductQueryRequest
