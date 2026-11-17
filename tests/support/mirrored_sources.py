"""Synthetic mirrored source blocks for importer and presentation boundary tests."""

from typing import Any


def build_source_affected(**product_fields: Any) -> dict[str, Any]:
    product: dict[str, Any] = {
        "vendor": "Democorp",
        "product": "Gateway",
        "versions": [
            {
                "version": "11.2.0",
                "status": "affected",
                "lessThan": "11.2.10",
                "changes": [{"at": "11.2.7-h8", "status": "unaffected"}],
            }
        ],
    }
    product.update(product_fields)
    return {"source": "cna@democorp.example", "affectedData": [product]}


def build_ssvc(**point_values: str) -> dict[str, Any]:
    options: list[dict[str, str]] = []
    for name, value in point_values.items():
        options.append({name: value})
    return {
        "source": "adp@democorp.example",
        "ssvcData": {"role": "CISA Coordinator", "options": options},
    }
