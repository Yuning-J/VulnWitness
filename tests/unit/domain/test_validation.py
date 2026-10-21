"""Claim/evidence referential integrity and scope invariants."""

import pytest
from pydantic import ValidationError

from cve_kgrag.adapters.memory.in_memory_evidence_catalog import InMemoryEvidenceCatalog
from cve_kgrag.domain.evidence import EvidenceAnchor, seal_evidence_anchor
from cve_kgrag.domain.search import Candidate, ScopeAssessment, SearchResponse
from cve_kgrag.domain.taxonomy import (
    AssertionKind,
    BackendFailureDetail,
    KnowledgeScope,
    ResultStatus,
    RetrievalChannel,
    SourceType,
)
from cve_kgrag.domain.threat_context import KnownFightSnapshot
from cve_kgrag.domain.validation import (
    EvidenceValidationError,
    find_pinned_fight_violations,
    validate_claims,
    validate_search_response,
    validate_served_anchor,
)
from tests.support.builders import build_anchor, build_claim, build_cve_record
from tests.support.investigation import list_packaged_fight_anchors

FIGHT_CONTEXT_ANCHOR = build_anchor(
    authoritative_record_id="FGT1234",
    locator="fight.yaml#/techniques/0",
    evidence_id="ev:" + "a" * 24,
    scope=KnowledgeScope.PROTOCOL_THREAT_CONTEXT,
)


def build_test_evidence_catalog() -> InMemoryEvidenceCatalog:
    """The catalog of a service over the test record and anchors."""
    return InMemoryEvidenceCatalog((build_anchor(), FIGHT_CONTEXT_ANCHOR), (build_cve_record(),))


def test_claim_citing_known_same_scope_evidence_passes() -> None:
    validate_claims([build_claim()], [build_anchor()])


def test_claim_citing_unknown_evidence_is_rejected() -> None:
    claim = build_claim(evidence_ids=["ev:" + "f" * 24])

    with pytest.raises(EvidenceValidationError, match="unknown evidence"):
        validate_claims([claim], [build_anchor()])


def test_protocol_context_claim_citing_cve_evidence_is_rejected() -> None:
    claim = build_claim(
        statement="5G-AKA is vulnerable.",
        scope=KnowledgeScope.PROTOCOL_THREAT_CONTEXT,
    )

    with pytest.raises(
        EvidenceValidationError,
        match="protocol_threat_context claim cites implementation_vulnerability",
    ):
        validate_claims([claim], [build_anchor()])


def test_implementation_claim_citing_only_protocol_context_is_rejected() -> None:
    claim = build_claim(evidence_ids=[FIGHT_CONTEXT_ANCHOR.evidence_id])

    with pytest.raises(
        EvidenceValidationError,
        match="implementation_vulnerability claim cites protocol_threat_context",
    ):
        validate_claims([claim], [FIGHT_CONTEXT_ANCHOR])


@pytest.mark.parametrize(
    "relabeled_anchor",
    [
        build_anchor(scope=KnowledgeScope.PROTOCOL_THREAT_CONTEXT),
        build_anchor(
            authoritative_record_id="cve-9999-0001", scope=KnowledgeScope.PROTOCOL_THREAT_CONTEXT
        ),
        build_anchor(
            authoritative_record_id="nvd-feed-2026",
            source_type=SourceType.NVD_API_2,
            scope=KnowledgeScope.PROTOCOL_THREAT_CONTEXT,
        ),
    ],
    ids=["cve_record_id", "lower_case_cve_record_id", "nvd_source"],
)
def test_cve_evidence_relabeled_as_protocol_context_cannot_support_a_protocol_claim(
    relabeled_anchor: EvidenceAnchor,
) -> None:
    claim = build_claim(
        statement="5G-AKA is vulnerable.",
        scope=KnowledgeScope.PROTOCOL_THREAT_CONTEXT,
        evidence_ids=[relabeled_anchor.evidence_id],
    )

    with pytest.raises(EvidenceValidationError, match="CVE evidence must be"):
        validate_claims([claim], [relabeled_anchor])


def test_claim_citing_evidence_about_another_record_is_rejected() -> None:
    claim = build_claim(subject_id="CVE-9999-0002")

    with pytest.raises(EvidenceValidationError, match="about CVE-9999-0001, not CVE-9999-0002"):
        validate_claims([claim], [build_anchor()])


@pytest.mark.parametrize(
    "evidence_ids",
    [["CVE-9999-0001"], ["https://nvd.example/CVE-9999-0001"], ["ev:short"], []],
    ids=["cve_id", "url", "short_ev_id", "no_evidence"],
)
def test_claim_citing_anything_but_evidence_ids_is_rejected(evidence_ids: list[str]) -> None:
    with pytest.raises(ValidationError, match="evidence_ids"):
        build_claim(evidence_ids=evidence_ids)


@pytest.mark.parametrize(
    "tampered_field",
    [
        {"content_sha256": "f" * 64},
        {"locator": "records#/1"},
        {"source_name": "other-source"},
        {"source_uri": "https://attacker.invalid/forged", "excerpt": "FORGED SOURCE EXCERPT"},
    ],
    ids=["content_hash", "locator", "source_name", "source_uri_and_excerpt"],
)
def test_anchor_altered_after_its_id_was_derived_is_rejected(
    tampered_field: dict[str, str],
) -> None:
    tampered_anchor = build_anchor().model_copy(update=tampered_field)

    with pytest.raises(EvidenceValidationError, match="not derived from the anchor's"):
        validate_claims([build_claim()], [tampered_anchor])


def test_asserted_claim_resting_on_inferred_evidence_is_rejected() -> None:
    inferred_anchor = build_anchor(
        assertion_kind=AssertionKind.INFERRED, inference_method="cwe-mapping"
    )

    claim = build_claim(evidence_ids=[inferred_anchor.evidence_id])

    with pytest.raises(EvidenceValidationError, match="inferred evidence"):
        validate_claims([claim], [inferred_anchor])


def test_formal_protocol_finding_is_never_originated() -> None:
    formal_anchor = build_anchor(scope=KnowledgeScope.FORMAL_PROTOCOL_FINDING)
    claim = build_claim(
        scope=KnowledgeScope.FORMAL_PROTOCOL_FINDING, evidence_ids=[formal_anchor.evidence_id]
    )

    with pytest.raises(EvidenceValidationError) as raised:
        validate_claims([claim], [formal_anchor])

    assert len(raised.value.violations) == 2


def build_sealed_response(
    candidate: Candidate | None,
    evidence: tuple[object, ...],
    status: ResultStatus = ResultStatus.OK,
    lexical_status: str = "ok",
    channels_executed: tuple[RetrievalChannel, ...] = (RetrievalChannel.LEXICAL,),
) -> SearchResponse:
    lexical_outcome: dict[str, object] = {"channel": "lexical", "status": lexical_status}
    if lexical_status != "ok":
        lexical_outcome["detail"] = BackendFailureDetail.UNREACHABLE.value
    unsealed = SearchResponse(
        query="q",
        normalized_query="q",
        status=status,
        channels_executed=channels_executed,
        channel_outcomes=(lexical_outcome,),
        candidates=() if candidate is None else (candidate,),
        evidence=evidence,
        warnings=(),
        result_sha256="0" * 64,
    )
    return unsealed.model_copy(update={"result_sha256": unsealed.compute_result_sha256()})


def build_candidate(**overrides: object) -> Candidate:
    fields: dict[str, object] = {
        "rank": 1,
        "record": build_cve_record(),
        "relevance_score": 0.01,
        "channel_hits": [
            {
                "channel": "lexical",
                "channel_rank": 1,
                "raw_score": 1.0,
                "matched_fields": ["description"],
                "matched_terms": ["test"],
            }
        ],
        "scope_assessment": ScopeAssessment(
            scope=KnowledgeScope.IMPLEMENTATION_VULNERABILITY, basis="CVE record"
        ),
        "missing_fields": [],
    }
    fields.update(overrides)
    return Candidate.model_validate(fields)


def test_search_response_with_anchored_candidate_passes() -> None:
    response = build_sealed_response(build_candidate(), (build_anchor(),))

    validate_search_response(response, build_test_evidence_catalog())


def test_search_response_missing_cited_anchor_is_rejected() -> None:
    response = build_sealed_response(build_candidate(), ())

    with pytest.raises(EvidenceValidationError, match="missing from response"):
        validate_search_response(response, build_test_evidence_catalog())


def test_search_response_candidate_without_own_record_anchor_is_rejected() -> None:
    record = build_cve_record(cve_id="CVE-9999-0042")
    response = build_sealed_response(build_candidate(record=record), (build_anchor(),))

    with pytest.raises(EvidenceValidationError, match="no evidence anchor for the record itself"):
        validate_search_response(response, build_test_evidence_catalog())


def test_search_response_cve_candidate_scoped_as_protocol_context_is_rejected() -> None:
    protocol_scope = ScopeAssessment(scope=KnowledgeScope.PROTOCOL_THREAT_CONTEXT, basis="wrong")
    response = build_sealed_response(
        build_candidate(scope_assessment=protocol_scope), (build_anchor(),)
    )

    with pytest.raises(EvidenceValidationError, match="must be implementation_vulnerability"):
        validate_search_response(response, build_test_evidence_catalog())


def test_search_response_with_tampered_hash_is_rejected() -> None:
    sealed = build_sealed_response(build_candidate(), (build_anchor(),))
    tampered = sealed.model_copy(update={"query": "different"})

    with pytest.raises(EvidenceValidationError, match="result_sha256"):
        validate_search_response(tampered, build_test_evidence_catalog())


def test_resealed_search_response_claiming_another_schema_version_is_rejected() -> None:
    sealed = build_sealed_response(build_candidate(), (build_anchor(),))
    relabeled = sealed.model_copy(update={"schema_version": "2.0.0-dev.8"})
    resealed = relabeled.model_copy(update={"result_sha256": relabeled.compute_result_sha256()})

    with pytest.raises(EvidenceValidationError, match="schema_version is not"):
        validate_search_response(resealed, build_test_evidence_catalog())


def test_search_response_candidate_citing_protocol_context_evidence_is_rejected() -> None:
    record = build_cve_record(
        evidence_ids=[build_anchor().evidence_id, FIGHT_CONTEXT_ANCHOR.evidence_id]
    )
    response = build_sealed_response(
        build_candidate(record=record), (build_anchor(), FIGHT_CONTEXT_ANCHOR)
    )

    with pytest.raises(EvidenceValidationError, match="cites protocol_threat_context evidence"):
        validate_search_response(response, build_test_evidence_catalog())


@pytest.mark.parametrize(
    ("has_candidate", "status", "lexical_status", "channels_executed", "violation"),
    [
        (True, ResultStatus.OK, "error", (RetrievalChannel.LEXICAL,), "backend failure"),
        (
            False,
            ResultStatus.NO_MATCH,
            "unavailable",
            (RetrievalChannel.LEXICAL,),
            "backend failure",
        ),
        (True, ResultStatus.NO_MATCH, "ok", (RetrievalChannel.LEXICAL,), "cannot be no_match"),
        (False, ResultStatus.OK, "ok", (RetrievalChannel.LEXICAL,), "must contain an answer"),
        (True, ResultStatus.OK, "ok", (RetrievalChannel.SEMANTIC,), "do not correspond"),
    ],
    ids=[
        "error_as_ok",
        "unavailable_as_no_match",
        "candidates_as_no_match",
        "ok_without_candidates",
        "outcomes_differ_from_channels",
    ],
)
def test_search_response_with_inconsistent_status_is_rejected(
    has_candidate: bool,
    status: ResultStatus,
    lexical_status: str,
    channels_executed: tuple[RetrievalChannel, ...],
    violation: str,
) -> None:
    candidate = build_candidate() if has_candidate else None
    evidence = (build_anchor(),) if has_candidate else ()
    response = build_sealed_response(candidate, evidence, status, lexical_status, channels_executed)

    with pytest.raises(EvidenceValidationError, match=violation):
        validate_search_response(response, build_test_evidence_catalog())


def test_search_response_anchor_absent_from_the_catalog_is_rejected() -> None:
    uncatalogued_anchor = build_anchor(source_uri="https://attacker.invalid/forged")
    record = build_cve_record(evidence_ids=[uncatalogued_anchor.evidence_id])
    response = build_sealed_response(build_candidate(record=record), (uncatalogued_anchor,))

    with pytest.raises(EvidenceValidationError) as raised:
        validate_search_response(response, build_test_evidence_catalog())

    assert raised.value.violations == (
        f"{uncatalogued_anchor.evidence_id}: not an anchor this service's sources hold",
        "CVE-9999-0001: differs from the record this service's sources hold",
    )


def test_search_response_anchor_differing_from_the_catalogued_one_is_rejected() -> None:
    forged_anchor = build_anchor().model_copy(
        update={"source_uri": "https://attacker.invalid/forged", "excerpt": "FORGED SOURCE EXCERPT"}
    )
    response = build_sealed_response(build_candidate(), (forged_anchor,))

    with pytest.raises(EvidenceValidationError) as raised:
        validate_search_response(response, build_test_evidence_catalog())

    assert raised.value.violations == (
        f"{forged_anchor.evidence_id}: not derived from the anchor's provenance fields",
        f"{forged_anchor.evidence_id}: differs from the anchor this service's sources hold",
    )


def test_fight_anchor_served_alone_without_a_pinned_snapshot_is_rejected() -> None:
    fight_anchor = list_packaged_fight_anchors()[0]

    with pytest.raises(EvidenceValidationError, match="no FiGHT snapshot is pinned"):
        validate_served_anchor(fight_anchor, None)


def test_pinned_fight_anchor_served_alone_passes(
    pinned_fight_snapshot: KnownFightSnapshot,
) -> None:
    for fight_anchor in list_packaged_fight_anchors():
        validate_served_anchor(fight_anchor, pinned_fight_snapshot)


def test_cve_anchor_served_alone_passes_without_a_pinned_snapshot() -> None:
    validate_served_anchor(build_anchor(), None)


@pytest.mark.parametrize("field_name", ["locator", "source_name"])
def test_fight_anchor_in_a_response_with_text_of_its_source_s_choosing_is_rejected(
    pinned_fight_snapshot: KnownFightSnapshot, field_name: str
) -> None:
    fight_anchor = list_packaged_fight_anchors()[0]
    relabelled_anchor = seal_evidence_anchor(
        fight_anchor.model_copy(update={field_name: "CONFIRMED: demo_gateway is affected"})
    )

    violations = find_pinned_fight_violations([relabelled_anchor], (), pinned_fight_snapshot)

    assert violations == [
        f"{relabelled_anchor.evidence_id}: FiGHT evidence provenance differs from the pinned "
        "snapshot"
    ]
