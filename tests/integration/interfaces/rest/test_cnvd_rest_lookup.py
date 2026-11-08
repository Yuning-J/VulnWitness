"""CNVD exact lookups through the REST app's in-process HTTP client."""

from pathlib import Path

import pytest

from tests.support.asgi import open_app_client
from tests.support.cnvd_inputs import LOOKUP_REVISION
from tests.support.cnvd_serving import (
    CNVD_LOOKUP_CASE_IDS,
    CNVD_LOOKUP_CASES,
    NVD_STATE_CASES,
    assert_cnvd_lookup,
    build_cnvd_capability_toolbox,
    build_cnvd_serving_toolbox,
    build_serving_cnvd_catalog,
)
from tests.support.rest_api import build_test_api
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.domain.cve_lookup import CNVD_NOT_FOUND_STATEMENT, CveLookupResponse

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize(
    "identifier,cve_id,severities,nvd_state,is_pending",
    CNVD_LOOKUP_CASES,
    ids=CNVD_LOOKUP_CASE_IDS,
)
async def test_lookup_serves_compared_cnvd_with_source_credit(
    tmp_path: Path,
    fixture_bundle: FixtureBundle,
    identifier: str,
    cve_id: str,
    severities: list[str],
    nvd_state: str,
    is_pending: bool,
) -> None:
    api = build_test_api(fixture_bundle, toolbox=build_cnvd_serving_toolbox(tmp_path))

    async with open_app_client(api) as client:
        answer = await client.post("/api/v2/lookup", json={"cve_id": identifier})

    assert answer.status_code == 200
    lookup = CveLookupResponse.model_validate_json(answer.content)
    assert lookup.result_sha256 == lookup.compute_result_sha256()
    assert_cnvd_lookup(answer.json(), cve_id, severities, nvd_state, is_pending)


@pytest.mark.parametrize(
    "status,expected",
    NVD_STATE_CASES,
    ids=["analyzed", "modified", "received", "awaiting", "undergoing", "deferred", "future"],
)
async def test_lookup_classifies_nvd_status(
    tmp_path: Path,
    fixture_bundle: FixtureBundle,
    status: str,
    expected: str,
) -> None:
    toolbox = build_cnvd_serving_toolbox(tmp_path, nvd_status=status)

    async with open_app_client(build_test_api(fixture_bundle, toolbox=toolbox)) as client:
        answer = await client.post("/api/v2/lookup", json={"cve_id": "CVE-9999-0001"})

    assert answer.status_code == 200
    assert_cnvd_lookup(answer.json(), "CVE-9999-0001", ["same", "lower"], expected, False)


async def test_lookup_without_nvd_cvss3_is_not_compared(
    tmp_path: Path,
    fixture_bundle: FixtureBundle,
) -> None:
    toolbox = build_cnvd_serving_toolbox(tmp_path, with_metrics=False)

    async with open_app_client(build_test_api(fixture_bundle, toolbox=toolbox)) as client:
        answer = await client.post("/api/v2/lookup", json={"cve_id": "CVE-9999-0001"})

    assert_cnvd_lookup(
        answer.json(), "CVE-9999-0001", ["not_compared", "not_compared"], "analysed", False
    )


@pytest.mark.parametrize(
    "identifier",
    ["CNVD-9999-99999", "CVE-9999-9999", "CVE-9999-0008"],
    ids=["unknown-cnvd", "unknown-cve", "nvd-only"],
)
async def test_lookup_without_cnvd_content_omits_cnvd_attribution(
    tmp_path: Path,
    fixture_bundle: FixtureBundle,
    identifier: str,
) -> None:
    api = build_test_api(fixture_bundle, toolbox=build_cnvd_serving_toolbox(tmp_path))

    async with open_app_client(api) as client:
        answer = await client.post("/api/v2/lookup", json={"cve_id": identifier})

    assert answer.status_code == 200
    assert "cnvd_attribution" not in answer.json()
    assert "cnvd_language" not in answer.json()
    assert "source_comparison" not in answer.text
    if identifier.startswith("CNVD-"):
        assert answer.json()["not_found_statement"] == CNVD_NOT_FOUND_STATEMENT
        assert answer.json()["status"] == "no_match"


@pytest.mark.parametrize(
    "identifier",
    [
        "CNVD-9999-123",
        "CNVD-9999-1234567",
        "CNVD-9999-\uff11\uff12\uff13\uff14",
        "CNVD-9999-00001\n",
    ],
    ids=["short", "long", "unicode", "newline"],
)
async def test_lookup_rejects_invalid_cnvd_at_boundary(
    fixture_bundle: FixtureBundle, identifier: str
) -> None:
    async with open_app_client(build_test_api(fixture_bundle)) as client:
        answer = await client.post("/api/v2/lookup", json={"cve_id": identifier})

    assert answer.status_code == 422
    assert answer.json()["code"] == "invalid_arguments"


@pytest.mark.parametrize(
    "store_kind,has_cnvd,holds_cnvd",
    [
        ("cnvd-store", True, True),
        ("format-1", False, False),
        ("no-cnvd-input", False, False),
        ("unlinked-cnvd", True, False),
    ],
    ids=["cnvd-store", "format-1", "no-cnvd-input", "all-cnvd-unlinked"],
)
async def test_capabilities_report_cnvd_import_and_revision(
    tmp_path: Path,
    fixture_bundle: FixtureBundle,
    store_kind: str,
    has_cnvd: bool,
    holds_cnvd: bool,
) -> None:
    toolbox = build_cnvd_capability_toolbox(tmp_path, store_kind)

    async with open_app_client(build_test_api(fixture_bundle, toolbox=toolbox)) as client:
        answer = await client.get("/api/v2/capabilities")

    assert answer.status_code == 200
    assert answer.json()["cnvd"] == {
        "imported": has_cnvd,
        "revision": LOOKUP_REVISION if has_cnvd else None,
    }


@pytest.mark.parametrize("language", ["zh-Hans", None], ids=["declared", "undeclared"])
async def test_lookup_uses_only_served_revisions_language(
    tmp_path: Path, fixture_bundle: FixtureBundle, language: str | None
) -> None:
    toolbox = build_cnvd_serving_toolbox(
        tmp_path, cnvd_catalog=build_serving_cnvd_catalog(language)
    )

    async with open_app_client(build_test_api(fixture_bundle, toolbox=toolbox)) as client:
        answer = await client.post("/api/v2/lookup", json={"cve_id": "CVE-9999-0001"})

    assert answer.status_code == 200
    assert answer.json().get("cnvd_language") == language
    assert ("cnvd_language" in answer.json()) == (language is not None)
    assert answer.json()["cnvd_attribution"]
    assert (
        answer.json()["candidates"][0]["record"]["cnvd"][0]["source_comparison"]["grade_relative"]
        == "same"
    )
