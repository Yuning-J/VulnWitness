"""Operator registers use declaration YAML, rejecting duplicate keys and aliases."""

import pytest
import yaml

from tests.support.priority import build_register_document
from vulnwitness.adapters.asset_register import AssetRegisterError, load_asset_register


def test_register_loader_preserves_assessment_and_canonical_digest() -> None:
    register_text = yaml.safe_dump(build_register_document())

    register = load_asset_register(register_text.encode())
    commented_register = load_asset_register(("# Operator register\n" + register_text).encode())

    assert register.assessments[0].assessor == "analyst"
    assert register.assessments[0].assessed_at.isoformat() == "2026-11-08"
    assert register.compute_content_sha256() == commented_register.compute_content_sha256()


@pytest.mark.parametrize(
    "register_bytes",
    [
        b"\xff",
        b"assets: [",
        b"format_version: 1\nformat_version: 1",
        b"assets: &assets []\nassessments: *assets",
        b"format_version: 2",
    ],
    ids=["non-utf8", "syntax", "duplicate-key", "alias", "wrong-contract"],
)
def test_invalid_declaration_yaml_is_rejected(register_bytes: bytes) -> None:
    with pytest.raises(AssetRegisterError):
        load_asset_register(register_bytes)
