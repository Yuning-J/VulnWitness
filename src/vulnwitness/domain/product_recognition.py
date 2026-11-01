"""Auxiliary product recognition recorded with an investigation."""

from typing import Literal

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.product_query import ProductQueryRequest


class ProductRecognition(ContractModel):
    name: str
    basis: Literal["affectedness_mention", "exact_phrase"]
    request: ProductQueryRequest
