"""The pinned trustify-mcp tool surface (ADR 0003 §5) is unmodified and shaped as the ADR states."""

import hashlib
import json
from pathlib import Path
from typing import Any

from cve_kgrag.adapters.provenance.source_registry import (
    default_source_registry_file,
    load_source_registry,
)

PINNED_COMMIT = "ac8955f768a5bfef6f1c9a5c1d02ec5b5cf9bf5e"
SNAPSHOT_DIR = Path(__file__).resolve().parent / "data" / f"trustify_mcp_{PINNED_COMMIT[:7]}"
TOOLS_FILE = SNAPSHOT_DIR / "tools.json"
LICENCE_FILE = SNAPSHOT_DIR / "LICENSE"

# EXPECTED_TOOLS_LIST_RESPONSE from tests/integration_test.rs at the pinned commit.
TOOLS_SHA256 = "a877d200e29b8aeea33e81c1ee1453b1575e15e33d9cc3613e4158a3332baa64"
# The Apache-2.0 LICENSE at the pinned commit.
LICENCE_SHA256 = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"

PINNED_TOOL_NAMES = {
    "trustify_advisory_details",
    "trustify_vulnerabilities_for_multiple_purls",
    "url_encode",
    "trustify_sbom_details",
    "trustify_sboms_list",
    "trustify_vulnerability_details",
    "trustify_sbom_list_advisories",
    "trustify_sbom_list_packages",
    "trustify_info",
    "trustify_vulnerabilities_list",
    "trustify_purl_vulnerabilities",
    "trustify_advisories_list",
}
PRODUCT_NAME_FRAGMENTS = ("product", "vendor", "name")


def read_input_schemas_by_tool() -> dict[str, dict[str, Any]]:
    tool_listing = json.loads(TOOLS_FILE.read_text(encoding="utf-8"))
    input_schemas_by_tool: dict[str, dict[str, Any]] = {}
    for tool in tool_listing["tools"]:
        input_schemas_by_tool[tool["name"]] = tool["inputSchema"]
    return input_schemas_by_tool


def test_snapshot_bytes_match_the_pinned_excerpt_hash() -> None:
    snapshot_digest = hashlib.sha256(TOOLS_FILE.read_bytes()).hexdigest()

    assert snapshot_digest == TOOLS_SHA256


def test_licence_copy_is_the_pinned_apache_2_0_text() -> None:
    licence_digest = hashlib.sha256(LICENCE_FILE.read_bytes()).hexdigest()

    assert licence_digest == LICENCE_SHA256


def test_snapshot_lists_exactly_the_twelve_pinned_tools() -> None:
    tool_listing = json.loads(TOOLS_FILE.read_text(encoding="utf-8"))

    listed_tool_names: list[str] = []
    for tool in tool_listing["tools"]:
        listed_tool_names.append(tool["name"])

    assert len(listed_tool_names) == 12
    assert set(listed_tool_names) == PINNED_TOOL_NAMES


def test_purl_tool_takes_only_package_uri_or_purl() -> None:
    purl_input_schema = read_input_schemas_by_tool()["trustify_purl_vulnerabilities"]

    assert set(purl_input_schema["properties"]) == {"package_uri_or_purl"}
    assert purl_input_schema["required"] == ["package_uri_or_purl"]


def test_cve_tool_takes_only_cve_id() -> None:
    cve_input_schema = read_input_schemas_by_tool()["trustify_vulnerability_details"]

    assert set(cve_input_schema["properties"]) == {"cve_id"}
    assert cve_input_schema["required"] == ["cve_id"]


def test_no_tool_takes_a_product_name() -> None:
    input_schemas_by_tool = read_input_schemas_by_tool()

    product_name_fields: set[str] = set()
    for input_schema in input_schemas_by_tool.values():
        for field_name in input_schema["properties"]:
            if any(fragment in field_name for fragment in PRODUCT_NAME_FRAGMENTS):
                product_name_fields.add(field_name)

    assert product_name_fields == set()


def test_source_registry_pins_the_snapshot_commit() -> None:
    registry = load_source_registry(default_source_registry_file())

    trustify_mcp_sources = []
    for source in registry.sources:
        if source.name == "trustify-mcp":
            trustify_mcp_sources.append(source)

    assert len(trustify_mcp_sources) == 1
    assert PINNED_COMMIT in trustify_mcp_sources[0].version_strategy
    assert trustify_mcp_sources[0].terms_or_license_url == (
        f"https://github.com/guacsec/trustify-mcp/blob/{PINNED_COMMIT}/LICENSE"
    )


def test_source_registry_names_every_part_the_snapshot_commits() -> None:
    tool_listing = json.loads(TOOLS_FILE.read_text(encoding="utf-8"))
    registry = load_source_registry(default_source_registry_file())

    committed_tool_parts: set[str] = set()
    for tool in tool_listing["tools"]:
        committed_tool_parts.update(tool)
    registry_notes: list[str] = []
    for source in registry.sources:
        if source.name == "trustify-mcp":
            registry_notes.append(source.notes)

    assert committed_tool_parts == {"name", "description", "inputSchema"}
    assert len(registry_notes) == 1
    assert "names, descriptions and input schemas" in registry_notes[0]
