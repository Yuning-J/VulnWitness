"""The operator register rejects ambiguous assessments and undeclared assets."""

import pytest
from pydantic import ValidationError

from tests.support.priority import build_register_document
from vulnwitness.domain.asset_register import AssetRegister


@pytest.mark.parametrize(
    ("malformation", "message"),
    [
        ("unknown-key", "Extra inputs"),
        ("asset-unknown-key", "Extra inputs"),
        ("assessment-unknown-key", "Extra inputs"),
        ("duplicate-asset", "duplicate asset name"),
        ("duplicate-assessment", "duplicate asset and CVE"),
        ("undeclared-asset", "undeclared asset"),
        ("affected-without-justification", "require a justification"),
        ("not-affected-without-justification", "require a justification"),
        ("blank-justification", "String should match"),
        ("bad-date", "valid date"),
        ("missing-assessor", "Field required"),
        ("bad-cve", "String should match"),
        ("bad-format", "Input should be 1"),
        ("boolean-format", "expected a JSON number"),
    ],
)
def test_invalid_register_is_rejected(malformation: str, message: str) -> None:
    register_document = build_register_document()
    asset = register_document["assets"][0]
    assessment = register_document["assessments"][0]
    if malformation == "unknown-key":
        register_document["extra"] = True
    elif malformation == "asset-unknown-key":
        asset["extra"] = True
    elif malformation == "assessment-unknown-key":
        assessment["extra"] = True
    elif malformation == "duplicate-asset":
        register_document["assets"].append(asset.copy())
    elif malformation == "duplicate-assessment":
        register_document["assessments"].append(assessment.copy())
    elif malformation == "undeclared-asset":
        assessment["asset"] = "missing"
    elif malformation in ("affected-without-justification", "not-affected-without-justification"):
        assessment["applicability"] = (
            "affected" if malformation.startswith("affected") else "not_affected"
        )
        del assessment["justification"]
    elif malformation == "blank-justification":
        assessment["justification"] = "  "
    elif malformation == "bad-date":
        assessment["assessed_at"] = "2026-02-30"
    elif malformation == "missing-assessor":
        del assessment["assessor"]
    elif malformation == "bad-cve":
        assessment["cve_id"] = "CVE-2026-bad"
    elif malformation == "bad-format":
        register_document["format_version"] = 2
    else:
        register_document["format_version"] = True

    with pytest.raises(ValidationError, match=message):
        AssetRegister.model_validate(register_document)


def test_unknown_applicability_can_be_unjustified_and_is_preserved() -> None:
    register_document = build_register_document()
    register_document["assessments"][0]["applicability"] = "unknown"
    del register_document["assessments"][0]["justification"]

    register = AssetRegister.model_validate(register_document)

    assert register.assessments[0].applicability == "unknown"
    assert register.assessments[0].justification is None


def test_register_digest_is_stable_and_changes_with_assessment() -> None:
    register_document = build_register_document()
    register = AssetRegister.model_validate(register_document)
    register_document["assessments"][0]["justification"] = "A different assessment basis."
    revised_register = AssetRegister.model_validate(register_document)

    assert register.compute_content_sha256() == register.compute_content_sha256()
    assert register.compute_content_sha256() != revised_register.compute_content_sha256()
