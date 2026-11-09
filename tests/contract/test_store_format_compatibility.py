"""Store format 1 stays readable (ADR 0009 §15): the compatibility store the importer at
28e5b4d wrote is still verified and loaded whole, with the records, evidence and dataset
version it held then; and any change to the schemas of what a store persists raises the
alarm that makes someone judge it.

The store's bytes are pinned here, outside it, so the store and the reader cannot both
change while this test still passes. Its README says how it was written; it is never
regenerated with a later importer.
"""

import hashlib
import json

from tests.support.corpus_stores import COMPATIBILITY_STORE
from vulnwitness.adapters.store.corpus_store import load_corpus_store, verify_corpus_store
from vulnwitness.domain.cnvd import PendingCnvdEntry
from vulnwitness.domain.corpus_store_manifest import STORE_FORMAT_SCHEMA_SHA256, CorpusStoreManifest
from vulnwitness.domain.cve import CveRecord
from vulnwitness.domain.evidence import EvidenceAnchor
from vulnwitness.domain.hashing import canonical_sha256
from vulnwitness.domain.served_dataset import ServedDataset, ServedDatasetKind
from vulnwitness.schema_snapshots import render_schema

PINNED_FILE_SHA256 = {
    "anchors.jsonl": "0ba19427011f5c654577952ad6636ee931bd52b984e8fa5b3e60e015b8e5fd10",
    "manifest.json": "c17f09856dc00eaf75a97dba788dc8154bb36714ada7e9a6a2fb56b8e798702f",
    "records.jsonl": "2c5f0e7f568c4d508f7d42fb11f1b271421b2e55791661e99350e8bedb5b4572",
}
EVIDENCE_IDS_BY_CVE = {
    "CVE-9999-0001": ("ev:bf5a052d854806df98f8e7f5", "ev:66388f844f28425bdef8ca45"),
    "CVE-9999-0002": ("ev:78dd6d4f7453c25b22f3933d",),
    "CVE-9999-0003": ("ev:fcfa19d421268f4829a3ea7d",),
    "CVE-9999-0004": ("ev:437e2a8fb30fcbcd29456f39", "ev:5536a9ff2701e77a599e8875"),
    "CVE-9999-0010": ("ev:737d3d349c5d5735a8d218a5", "ev:f384b4ef87310c7a60e648d2"),
    "CVE-9999-0011": ("ev:06c285a47450a3600d480e0d",),
    "CVE-9999-0012": ("ev:fd5501584bfb4f381a3ce9da",),
}
CVE_SEARCH_VERSION = (
    "corpus-store-v1@sha256:dbb234a598f6e570671c6a076715e20c4a009b8b15dd76063acbff726d914d9c"
)


def test_compatibility_store_holds_exactly_its_pinned_bytes() -> None:
    file_sha256: dict[str, str] = {}
    for store_file in sorted(COMPATIBILITY_STORE.iterdir()):
        file_sha256[store_file.name] = hashlib.sha256(store_file.read_bytes()).hexdigest()

    assert file_sha256 == PINNED_FILE_SHA256


def test_compatibility_store_verifies_under_its_manifest_digest() -> None:
    verified_store = verify_corpus_store(COMPATIBILITY_STORE)

    assert verified_store.store_manifest_sha256 == PINNED_FILE_SHA256["manifest.json"]
    assert verified_store.manifest.schema_version == "2.0.0-dev.25"


def test_compatibility_store_loads_every_record_with_its_evidence() -> None:
    corpus_store = load_corpus_store(COMPATIBILITY_STORE)

    evidence_ids_by_cve: dict[str, tuple[str, ...]] = {}
    for record in corpus_store.records:
        evidence_ids_by_cve[record.cve_id] = record.evidence_ids
    served_evidence_ids: set[str] = set()
    for anchor in corpus_store.evidence:
        served_evidence_ids.add(anchor.evidence_id)
    cited_evidence_ids: set[str] = set()
    for evidence_ids in EVIDENCE_IDS_BY_CVE.values():
        cited_evidence_ids.update(evidence_ids)
    assert evidence_ids_by_cve == EVIDENCE_IDS_BY_CVE
    assert served_evidence_ids == cited_evidence_ids


def test_compatibility_store_serves_the_dataset_version_its_files_name() -> None:
    served_dataset = load_corpus_store(COMPATIBILITY_STORE).describe_served_dataset()

    assert served_dataset == ServedDataset(
        kind=ServedDatasetKind.CORPUS_STORE, cve_search_version=CVE_SEARCH_VERSION
    )


def test_persisted_models_match_the_schemas_format_3_was_judged_against() -> None:
    # Format 3 persists these four models; schema changes require judging the format
    # against ADR 0008 §9, including rules not captured by the published schemas.
    persisted_schemas: dict[str, object] = {}
    for contract_name, model in (
        ("corpus_store_manifest", CorpusStoreManifest),
        ("cve_record", CveRecord),
        ("evidence_anchor", EvidenceAnchor),
        ("pending_cnvd_entry", PendingCnvdEntry),
    ):
        persisted_schemas[contract_name] = json.loads(render_schema(model, "serialization"))

    assert canonical_sha256(persisted_schemas) == STORE_FORMAT_SCHEMA_SHA256
