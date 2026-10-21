"""Loader for the checksum-pinned synthetic CVE fixture shipped with the package.

The fixture is authored test data: every record uses a ``CVE-9999-*`` ID and a
fictional vendor, so it can never be mistaken for a real advisory. Loading is
read-only, deterministic and fails closed when a file's SHA-256 differs from the
manifest.
"""

import json
from dataclasses import dataclass
from importlib.resources import files
from importlib.resources.abc import Traversable
from typing import Any, Literal

from pydantic import AwareDatetime, Field

from cve_kgrag.domain.contract_model import ContractModel
from cve_kgrag.domain.cve import CveRecord
from cve_kgrag.domain.evidence import (
    MAX_EXCERPT_CHARS,
    SHA256_PATTERN,
    UNSEALED_EVIDENCE_ID,
    EvidenceAnchor,
    seal_evidence_anchor,
)
from cve_kgrag.domain.hashing import canonical_sha256, sha256_hex
from cve_kgrag.domain.taxonomy import (
    AssertionKind,
    KnowledgeScope,
    SourceType,
    TrustLevel,
)

MANIFEST_FILE = "manifest.json"
RECORDS_FILE = "records.json"


class FixtureIntegrityError(ValueError):
    """The fixture on disk does not match its manifest; nothing from it is loaded."""


class FixtureFile(ContractModel):
    path: str
    sha256: str = Field(pattern=SHA256_PATTERN)


class FixtureManifest(ContractModel):
    fixture_id: str = Field(pattern=r"^[a-z0-9-]+$")
    version: str
    generated_at: AwareDatetime
    synthetic: Literal[True]
    description: str
    license: str
    files: tuple[FixtureFile, ...]


@dataclass(frozen=True)
class FixtureBundle:
    manifest: FixtureManifest
    records: tuple[CveRecord, ...]
    evidence: tuple[EvidenceAnchor, ...]


def default_fixture_dir() -> Traversable:
    return files("cve_kgrag").joinpath("fixtures", "synthetic")


def read_verified_file(fixture_dir: Traversable, fixture_file: FixtureFile) -> bytes:
    content = fixture_dir.joinpath(fixture_file.path).read_bytes()
    actual_sha256 = sha256_hex(content)
    if actual_sha256 != fixture_file.sha256:
        raise FixtureIntegrityError(
            f"{fixture_file.path}: sha256 {actual_sha256} does not match manifest "
            f"{fixture_file.sha256}"
        )
    return content


def build_anchor(manifest: FixtureManifest, index: int, entry: dict[str, Any]) -> EvidenceAnchor:
    cve_id = entry["cve_id"]
    locator = f"{RECORDS_FILE}#/records/{index}"
    content_sha256 = canonical_sha256(entry)
    unsealed_anchor = EvidenceAnchor(
        evidence_id=UNSEALED_EVIDENCE_ID,
        source_name=manifest.fixture_id,
        source_type=SourceType.SYNTHETIC_FIXTURE,
        authoritative_record_id=cve_id,
        source_uri=f"urn:cve-kgrag:fixture:{manifest.fixture_id}:{manifest.version}",
        source_version=manifest.version,
        retrieved_at=manifest.generated_at,
        content_sha256=content_sha256,
        locator=locator,
        excerpt=entry["descriptions"][0]["value"][:MAX_EXCERPT_CHARS],
        scope=KnowledgeScope.IMPLEMENTATION_VULNERABILITY,
        assertion_kind=AssertionKind.ASSERTED,
        license_or_terms_ref=manifest.license,
        trust_level=TrustLevel.SYNTHETIC,
    )
    return seal_evidence_anchor(unsealed_anchor)


def load_fixture_bundle(fixture_dir: Traversable) -> FixtureBundle:
    """Verify every manifest checksum, then build records and their evidence anchors."""
    manifest = FixtureManifest.model_validate_json(fixture_dir.joinpath(MANIFEST_FILE).read_bytes())
    verified_contents: dict[str, bytes] = {}
    for fixture_file in manifest.files:
        verified_contents[fixture_file.path] = read_verified_file(fixture_dir, fixture_file)
    if RECORDS_FILE not in verified_contents:
        raise FixtureIntegrityError(f"manifest does not pin {RECORDS_FILE}")

    entries = json.loads(verified_contents[RECORDS_FILE])["records"]
    records: list[CveRecord] = []
    anchors: list[EvidenceAnchor] = []
    for index, entry in enumerate(entries):
        if "evidence_ids" in entry:
            raise FixtureIntegrityError(
                f"{entry['cve_id']}: evidence IDs are derived by the loader, not authored"
            )
        anchor = build_anchor(manifest, index, entry)
        anchors.append(anchor)
        records.append(CveRecord.model_validate({**entry, "evidence_ids": [anchor.evidence_id]}))
    return FixtureBundle(manifest=manifest, records=tuple(records), evidence=tuple(anchors))
