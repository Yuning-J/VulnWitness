"""Fact extraction retains accumulated KEV evidence across recorded candidates."""

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from tests.support.priority import REFERENCE_DATE, build_priority_inputs, build_priority_session
from vulnwitness.adapters.session.check import SessionChecker
from vulnwitness.application.priority_session import extract_priority_facts
from vulnwitness.domain.cve import KevEntry
from vulnwitness.domain.cve_lookup import CveLookupResponse
from vulnwitness.domain.tool_contracts import KnowledgeCapabilities


def test_candidate_without_kev_information_preserves_an_existing_positive_listing(
    tmp_path: Path,
) -> None:
    directory = build_priority_session(
        tmp_path / "sessions",
        record_capabilities=False,
        record_overrides={"kev": KevEntry(date_added="2026-01-01")},
    )
    contents = SessionChecker(directory).check_with_contents()
    lookup = contents.responses[1]
    assert isinstance(lookup, CveLookupResponse)
    listed = lookup.candidates[0]
    unknown = listed.model_copy(update={"record": listed.record.model_copy(update={"kev": None})})
    lookup = lookup.model_copy(update={"candidates": (listed, unknown)})
    contents = replace(contents, responses={1: lookup})
    asset, assessment, _ = build_priority_inputs()
    assessment = assessment.model_copy(update={"cve_id": listed.record.cve_id})

    extracted = extract_priority_facts(contents, asset, assessment, REFERENCE_DATE)

    assert extracted.facts.kev.value == "listed"
    assert extracted.facts.kev.evidence_ids == listed.record.evidence_ids[:1]


def test_later_positive_candidate_keeps_the_used_snapshots_after_reference_date_flag(
    tmp_path: Path,
) -> None:
    directory = build_priority_session(tmp_path / "sessions")
    contents = SessionChecker(directory).check_with_contents()
    capabilities = contents.responses[1]
    lookup = contents.responses[2]
    assert isinstance(capabilities, KnowledgeCapabilities)
    assert isinstance(lookup, CveLookupResponse)
    unlisted = lookup.candidates[0]
    listed = unlisted.model_copy(
        update={
            "record": unlisted.record.model_copy(update={"kev": KevEntry(date_added="2026-01-01")})
        }
    )
    lookup = lookup.model_copy(update={"candidates": (unlisted, listed)})
    capabilities = capabilities.model_copy(
        update={
            "kev": capabilities.kev.model_copy(
                update={"retrieved_at": datetime(2026, 11, 9, tzinfo=UTC)}
            )
        }
    )
    contents = replace(contents, responses={1: capabilities, 2: lookup})
    asset, assessment, _ = build_priority_inputs()
    assessment = assessment.model_copy(update={"cve_id": listed.record.cve_id})

    extracted = extract_priority_facts(contents, asset, assessment, REFERENCE_DATE)

    assert extracted.facts.kev.value == "listed"
    assert extracted.used_after_reference_date_information is True
    assert len(extracted.calls) == 2
