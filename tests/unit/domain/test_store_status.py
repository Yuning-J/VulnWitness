"""The store status contract (ADR 0009 §8): a store's digests are shown exactly when it is
ok, stores are shown exactly with a readable ``ACTIVE``, and a store name is one path
component that never starts with a dot and is never ``ACTIVE`` in any case."""

from typing import Any

import pytest
from pydantic import ValidationError

from vulnwitness.domain.search import SCHEMA_VERSION
from vulnwitness.domain.store_status import StoreStatus, is_store_name

IDENTITY = {
    "import_identity_sha256": "a" * 64,
    "corpus_content_sha256": "b" * 64,
    "cve_search_version": "corpus-store-v1@sha256:" + "b" * 64,
    "created_under_schema_version": "2.0.0-dev.25",
}


def build_store_fields(name: str, condition: str = "ok", **overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "name": name,
        "store_manifest_sha256": "c" * 64,
        "condition": condition,
        "identity": IDENTITY if condition == "ok" else None,
    }
    fields.update(overrides)
    return fields


def build_status_fields(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "active_record": "ok",
        "active_store": build_store_fields("second"),
        "previous_store": build_store_fields("first", "store_changed"),
    }
    fields.update(overrides)
    return fields


def test_status_with_an_ok_active_store_and_a_changed_previous_is_accepted() -> None:
    store_status = StoreStatus.model_validate(build_status_fields())

    assert store_status.previous_store is not None
    assert store_status.previous_store.identity is None


@pytest.mark.parametrize(
    "status_fields",
    [
        build_status_fields(active_store=build_store_fields("second", identity=None)),
        build_status_fields(
            active_store=build_store_fields("second", "active_store_changed", identity=IDENTITY)
        ),
        build_status_fields(active_store=build_store_fields("second", "store_changed")),
        build_status_fields(previous_store=build_store_fields("first", "active_store_missing")),
        build_status_fields(active_record="no_active_store"),
        build_status_fields(
            active_record="active_unreadable", active_store=None, previous_store=None
        )
        | {"previous_store": build_store_fields("first")},
        build_status_fields(active_store=None),
        build_status_fields(previous_store=build_store_fields("second")),
        build_status_fields(active_store=build_store_fields("ACTIVE")),
        build_status_fields(active_store=build_store_fields(".hidden")),
    ],
    ids=[
        "ok_store_without_identity",
        "changed_store_with_identity",
        "active_store_in_previous_store_terms",
        "previous_store_in_startup_terms",
        "stores_without_a_readable_record",
        "previous_store_without_a_readable_record",
        "readable_record_without_an_active_store",
        "one_store_twice",
        "store_named_active",
        "hidden_store_name",
    ],
)
def test_inconsistent_status_is_refused(status_fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        StoreStatus.model_validate(status_fields)


@pytest.mark.parametrize(
    ("name", "is_valid"),
    [
        ("nvd-2024.v1", True),
        ("A", True),
        ("x" * 64, True),
        ("x" * 65, False),
        (".partial", False),
        ("-store", False),
        ("_store", False),
        ("ACTIVE", False),
        ("Active", False),
        ("a/b", False),
        ("a b", False),
        ("", False),
        ("store\n", False),
    ],
)
def test_store_name_rule(name: str, is_valid: bool) -> None:
    assert is_store_name(name) is is_valid
