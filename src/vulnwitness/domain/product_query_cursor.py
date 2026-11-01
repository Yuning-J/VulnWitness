"""Opaque, stateless offsets bound to the normalized product request."""

import base64
from typing import Literal

from pydantic import Field, StrictInt

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.product_query import ProductQueryRequest
from vulnwitness.domain.search import MAX_RESULTS_PER_CALL


class InvalidProductCursor(ValueError):
    """The cursor is malformed, belongs to another request, or is outside its matches."""


class ProductQueryCursor(ContractModel):
    format: Literal[1] = 1
    vendor: str | None
    product: str | None
    version: str | None
    limit: StrictInt = Field(ge=1, le=MAX_RESULTS_PER_CALL)
    offset: StrictInt = Field(gt=0)


def build_product_cursor(request: ProductQueryRequest, offset: int) -> str:
    """Encode a continuation; clients pass it back unchanged with the same request."""
    continuation = ProductQueryCursor(
        vendor=request.vendor.casefold() if request.vendor is not None else None,
        product=request.product.casefold() if request.product is not None else None,
        version=request.version,
        limit=request.limit,
        offset=offset,
    )
    return base64.urlsafe_b64encode(continuation.model_dump_json().encode()).decode().rstrip("=")


def read_product_cursor(request: ProductQueryRequest) -> int:
    """Return the requested offset, raising ``InvalidProductCursor`` on invalid input.

    This is an offset over an immutable served corpus; continue against that same
    corpus. Cursors provide validation, not authentication or authorization.
    """
    if request.cursor is None:
        return 0
    try:
        cursor_bytes = base64.b64decode(
            request.cursor + "=" * (-len(request.cursor) % 4), altchars=b"-_", validate=True
        )
        continuation = ProductQueryCursor.model_validate_json(cursor_bytes)
    except ValueError:
        raise InvalidProductCursor("Invalid product query cursor.") from None
    if build_product_cursor(request, continuation.offset) != request.cursor:
        raise InvalidProductCursor("Invalid product query cursor.")
    return continuation.offset
