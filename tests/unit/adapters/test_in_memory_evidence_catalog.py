"""The evidence catalog returns exactly the anchors, records and techniques it was built from."""

import pytest

from tests.support.builders import build_anchor, build_cve_record, build_threat_context_item
from vulnwitness.adapters.memory.in_memory_evidence_catalog import InMemoryEvidenceCatalog
from vulnwitness.domain.validation import EvidenceValidationError


def test_catalog_returns_the_entry_held_under_an_id_and_none_otherwise() -> None:
    anchor = build_anchor()
    record = build_cve_record()
    technique = build_threat_context_item()

    evidence_catalog = InMemoryEvidenceCatalog(
        (anchor, anchor), (record, record), (technique, technique)
    )

    assert evidence_catalog.get_evidence(anchor.evidence_id) == anchor
    assert evidence_catalog.get_evidence("ev:" + "f" * 24) is None
    assert evidence_catalog.get_cve(record.cve_id) == record
    assert evidence_catalog.get_cve("CVE-9999-4242") is None
    assert evidence_catalog.get_technique(technique.technique_id) == technique
    assert evidence_catalog.get_technique("FGT9999") is None


def test_catalog_with_two_different_anchors_under_one_id_is_rejected() -> None:
    anchor = build_anchor()
    altered_anchor = anchor.model_copy(update={"excerpt": "FORGED SOURCE EXCERPT"})

    with pytest.raises(EvidenceValidationError, match="two different anchors share"):
        InMemoryEvidenceCatalog((anchor, altered_anchor), ())


def test_catalog_with_two_different_records_under_one_id_is_rejected() -> None:
    record = build_cve_record()
    altered_record = build_cve_record(
        descriptions=[{"lang": "en", "value": "FORGED description", "source": "test"}]
    )

    with pytest.raises(EvidenceValidationError, match="two different records share"):
        InMemoryEvidenceCatalog((build_anchor(),), (record, altered_record))


def test_catalog_with_two_different_techniques_under_one_id_is_rejected() -> None:
    technique = build_threat_context_item()
    altered_technique = build_threat_context_item(name="FORGED technique name")

    with pytest.raises(EvidenceValidationError, match="two different techniques share"):
        InMemoryEvidenceCatalog((), (), (technique, altered_technique))
