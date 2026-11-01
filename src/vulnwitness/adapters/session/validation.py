"""Validate serialized session documents without losing duplicate JSON keys."""

import json
from typing import Any, TypeVar

from pydantic import BaseModel

ModelT = TypeVar("ModelT", bound=BaseModel)


def reject_duplicate_keys(entries: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in entries:
        if key in document:
            raise ValueError("duplicate JSON key")
        document[key] = value
    return document


def check_serialized_fields(document: Any, serialized: Any) -> None:
    """Serialized contracts require defaulted fields too, at every model boundary."""
    if isinstance(document, dict) and isinstance(serialized, dict):
        if document.keys() != serialized.keys():
            raise ValueError("document is missing fields required by its serialization schema")
        for key, value in document.items():
            check_serialized_fields(value, serialized[key])
    elif isinstance(document, list) and isinstance(serialized, list):
        for value, normalized in zip(document, serialized, strict=True):
            check_serialized_fields(value, normalized)


def parse_session_document(content: bytes, model: type[ModelT]) -> ModelT:
    document = json.loads(content, object_pairs_hook=reject_duplicate_keys)
    parsed = model.model_validate_json(content, strict=True)
    check_serialized_fields(document, parsed.model_dump(mode="json"))
    return parsed
