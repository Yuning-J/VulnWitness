"""The topic-context validator rejects responses that mix scopes or misuse evidence."""

from typing import Any

import pytest

from cve_kgrag.adapters.fight.snapshot_catalog import (
    default_fight_snapshot_catalog_file,
    load_fight_snapshot_catalog,
)
from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.composition import build_topic_context_service
from cve_kgrag.domain.evidence import EvidenceAnchor, seal_evidence_anchor
from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.search import ScopeAssessment
from cve_kgrag.domain.taxonomy import (
    AssertionKind,
    BackendFailureDetail,
    KnowledgeScope,
    ResultStatus,
    SourceType,
)
from cve_kgrag.domain.threat_context import SnapshotCoverage
from cve_kgrag.domain.topic_context import (
    KnowledgeSource,
    QueryScope,
    SourceOutcome,
    TopicContextRequest,
    TopicContextResponse,
    TopicContextWarning,
    TopicContextWarningCode,
)
from cve_kgrag.domain.validation import (
    EvidenceValidationError,
    validate_claims,
    validate_topic_context_response,
)
from tests.support.builders import build_anchor, build_claim

PACKAGED_CATALOG = load_fight_snapshot_catalog(default_fight_snapshot_catalog_file())
EXCERPT_SHA256 = "08cd11d579889c819c00888ecbb85d6d4b470b8fdf9fea833324441e28635726"
UPSTREAM_SHA256 = "59a9addbd75d8680091797d66d5b237d9d026512990c61a6f51692ca94d2a7a8"
PINNED_EXCERPT = PACKAGED_CATALOG.find(EXCERPT_SHA256)
FULL_UPSTREAM = PACKAGED_CATALOG.find(UPSTREAM_SHA256)


def explore(bundle: FixtureBundle, scope: QueryScope) -> TopicContextResponse:
    return build_topic_context_service(bundle).explore(
        TopicContextRequest(query="5gaka", scope=scope, limit=20)
    )


def reseal(response: TopicContextResponse, **changes: Any) -> TopicContextResponse:
    edited_response = response.model_copy(update=changes)
    return edited_response.model_copy(
        update={"result_sha256": edited_response.compute_result_sha256()}
    )


def test_cve_moved_into_a_protocol_only_answer_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.PROTOCOL_CONTEXT_ONLY)
    excluded_topic_candidates = []
    for excluded_candidate in response.excluded_implementation_candidates:
        excluded_topic_candidates.append(excluded_candidate.candidate)
    forged_response = reseal(
        response,
        implementation_candidates=tuple(excluded_topic_candidates),
        excluded_implementation_candidates=(),
    )

    with pytest.raises(EvidenceValidationError, match="cannot contain CVE candidates"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def test_resealed_response_claiming_another_schema_version_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.MIXED)
    forged_response = reseal(response, schema_version="2.0.0-dev.8")

    with pytest.raises(EvidenceValidationError, match="schema_version is not"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def test_excluded_section_in_a_mixed_answer_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    protocol_answer = explore(fixture_bundle, QueryScope.PROTOCOL_CONTEXT_ONLY)
    mixed_answer = explore(fixture_bundle, QueryScope.MIXED)
    forged_response = reseal(
        mixed_answer,
        implementation_candidates=(),
        excluded_implementation_candidates=protocol_answer.excluded_implementation_candidates,
    )

    with pytest.raises(EvidenceValidationError, match="only a protocol_context_only answer"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def test_cve_candidate_relabeled_as_protocol_context_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.IMPLEMENTATION_ONLY)
    topic_candidate = response.implementation_candidates[0]
    relabeled_candidate = topic_candidate.candidate.model_copy(
        update={
            "scope_assessment": ScopeAssessment(
                scope=KnowledgeScope.PROTOCOL_THREAT_CONTEXT, basis="forged"
            )
        }
    )
    forged_response = reseal(
        response,
        implementation_candidates=(
            topic_candidate.model_copy(update={"candidate": relabeled_candidate}),
            *response.implementation_candidates[1:],
        ),
    )

    with pytest.raises(EvidenceValidationError, match="must be implementation_vulnerability"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def test_threat_context_item_citing_another_techniques_anchor_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.PROTOCOL_CONTEXT_ONLY)
    first_item, second_item = response.protocol_context[0], response.protocol_context[1]
    forged_item = first_item.model_copy(update={"evidence_ids": second_item.evidence_ids})
    forged_response = reseal(
        response, protocol_context=(forged_item, *response.protocol_context[1:])
    )

    with pytest.raises(EvidenceValidationError, match="no evidence anchor for the technique"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def test_fight_outage_hidden_from_source_outcomes_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.MIXED)
    forged_response = reseal(
        response,
        protocol_context=(),
        evidence=response.evidence[:0],
        implementation_candidates=(),
        source_outcomes=response.source_outcomes[1:],
        status=ResultStatus.NO_MATCH,
    )

    with pytest.raises(EvidenceValidationError, match="exactly the consulted sources"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def test_successful_fight_outcome_without_threat_context_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.IMPLEMENTATION_ONLY)
    fight_outcome = SourceOutcome(source=KnowledgeSource.MITRE_FIGHT, status=ResultStatus.OK)
    forged_response = reseal(
        response,
        requested_scope=QueryScope.MIXED,
        source_outcomes=(fight_outcome, *response.source_outcomes),
    )

    with pytest.raises(EvidenceValidationError, match="must contribute threat context"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def test_status_ignoring_a_failed_answer_source_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.MIXED)
    failed_cve_outcome = SourceOutcome(
        source=KnowledgeSource.CVE_SEARCH, status=ResultStatus.BACKEND_ERROR
    )
    forged_response = reseal(
        response,
        source_outcomes=(response.source_outcomes[0], failed_cve_outcome),
        implementation_candidates=(),
        evidence=tuple(list_item_anchors(response)),
    )

    with pytest.raises(EvidenceValidationError, match="should be partial"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def list_item_anchors(response: TopicContextResponse) -> list[EvidenceAnchor]:
    item_evidence_ids: set[str] = set()
    for item in response.protocol_context:
        item_evidence_ids.update(item.evidence_ids)
    item_anchors: list[EvidenceAnchor] = []
    for anchor in response.evidence:
        if anchor.evidence_id in item_evidence_ids:
            item_anchors.append(anchor)
    return item_anchors


def test_threat_context_in_an_implementation_only_answer_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    mixed_answer = explore(fixture_bundle, QueryScope.MIXED)
    implementation_answer = explore(fixture_bundle, QueryScope.IMPLEMENTATION_ONLY)
    forged_response = reseal(
        implementation_answer,
        protocol_context=mixed_answer.protocol_context,
        evidence=mixed_answer.evidence,
    )

    with pytest.raises(EvidenceValidationError, match="cannot contain threat context"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def test_uncited_evidence_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.MIXED)
    forged_response = reseal(
        response, evidence=(*response.evidence, build_anchor(evidence_id="ev:" + "e" * 24))
    )

    with pytest.raises(EvidenceValidationError, match="exactly the anchors"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def test_answer_reported_as_no_match_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    forged_response = reseal(
        explore(fixture_bundle, QueryScope.MIXED), status=ResultStatus.NO_MATCH
    )

    with pytest.raises(EvidenceValidationError, match="should be ok"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


@pytest.mark.parametrize(
    ("scope", "source_type"),
    [
        (KnowledgeScope.IMPLEMENTATION_VULNERABILITY, SourceType.MITRE_FIGHT_YAML),
        (KnowledgeScope.UNKNOWN, SourceType.MITRE_FIGHT_YAML),
        (KnowledgeScope.IMPLEMENTATION_VULNERABILITY, SourceType.SYNTHETIC_FIXTURE),
    ],
    ids=[
        "fight_source_as_implementation",
        "fight_source_as_unknown",
        "technique_id_as_implementation",
    ],
)
def test_fight_evidence_relabeled_away_from_threat_context_is_rejected(
    scope: KnowledgeScope, source_type: SourceType
) -> None:
    anchor = build_anchor(authoritative_record_id="FGT5040", source_type=source_type, scope=scope)
    claim = build_claim(subject_id="FGT5040", scope=scope, evidence_ids=[anchor.evidence_id])

    with pytest.raises(EvidenceValidationError, match="FiGHT evidence must be"):
        validate_claims([claim], [anchor])


def test_threat_context_beside_a_failed_fight_outcome_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.MIXED)
    failed_fight = SourceOutcome(
        source=KnowledgeSource.MITRE_FIGHT,
        status=ResultStatus.SOURCE_UNAVAILABLE,
        detail=BackendFailureDetail.UNREACHABLE,
    )
    forged_response = reseal(
        response,
        source_outcomes=(failed_fight, response.source_outcomes[1]),
        status=ResultStatus.PARTIAL,
    )

    with pytest.raises(EvidenceValidationError, match="needs a successful FiGHT outcome"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def test_cve_candidates_beside_a_no_match_cve_outcome_are_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.IMPLEMENTATION_ONLY)
    empty_cve_search = SourceOutcome(
        source=KnowledgeSource.CVE_SEARCH, status=ResultStatus.NO_MATCH
    )
    forged_response = reseal(response, source_outcomes=(empty_cve_search,))

    with pytest.raises(EvidenceValidationError, match="need a CVE search outcome"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def test_successful_cve_outcome_without_candidates_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.IMPLEMENTATION_ONLY)
    forged_response = reseal(
        response, implementation_candidates=(), evidence=(), status=ResultStatus.NO_MATCH
    )

    with pytest.raises(EvidenceValidationError, match="must contribute a candidate"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def test_threat_context_citing_inferred_fight_evidence_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.PROTOCOL_CONTEXT_ONLY)
    item = response.protocol_context[0]
    real_anchor = response.evidence[0]
    for anchor in response.evidence:
        if anchor.evidence_id == item.evidence_ids[0]:
            real_anchor = anchor
    inferred_anchor = real_anchor.model_copy(
        update={"assertion_kind": AssertionKind.INFERRED, "inference_method": "guess"}
    )
    forged_evidence: list[EvidenceAnchor] = []
    for anchor in response.evidence:
        forged_evidence.append(
            inferred_anchor if anchor.evidence_id == real_anchor.evidence_id else anchor
        )
    forged_response = reseal(response, evidence=tuple(forged_evidence))

    with pytest.raises(EvidenceValidationError, match="cites inferred evidence"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


@pytest.mark.parametrize(
    ("record_id", "source_type"),
    [
        ("fgt1499.503", SourceType.SYNTHETIC_FIXTURE),
        ("TA0006", SourceType.MITRE_FIGHT_YAML),
    ],
    ids=["lower_case_technique_id", "fight_tactic_record"],
)
def test_fight_evidence_detected_by_id_case_or_source_cannot_be_implementation(
    record_id: str, source_type: SourceType
) -> None:
    anchor = build_anchor(
        authoritative_record_id=record_id,
        source_type=source_type,
        scope=KnowledgeScope.IMPLEMENTATION_VULNERABILITY,
    )

    with pytest.raises(EvidenceValidationError, match="FiGHT evidence must be"):
        validate_claims([], [anchor])


def build_forged_fight_outcome(response: TopicContextResponse, **fields: Any) -> SourceOutcome:
    return response.source_outcomes[0].model_copy(update=fields)


def remove_excerpt_warning(response: TopicContextResponse) -> tuple[TopicContextWarning, ...]:
    kept_warnings: list[TopicContextWarning] = []
    for warning in response.warnings:
        if warning.code is not TopicContextWarningCode.SOURCE_SNAPSHOT_IS_EXCERPT:
            kept_warnings.append(warning)
    return tuple(kept_warnings)


def test_fight_outcome_claiming_another_snapshot_than_its_evidence_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.PROTOCOL_CONTEXT_ONLY)
    forged_outcome = build_forged_fight_outcome(
        response,
        source_version="3.1.0@" + "0" * 40 + "+sha256:" + "1" * 64,
        coverage=SnapshotCoverage.FULL,
    )
    forged_response = reseal(
        response,
        source_outcomes=(forged_outcome, *response.source_outcomes[1:]),
        warnings=remove_excerpt_warning(response),
    )

    with pytest.raises(EvidenceValidationError, match="another snapshot than the pinned one"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def test_successful_fight_outcome_without_snapshot_identity_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.PROTOCOL_CONTEXT_ONLY)
    forged_outcome = build_forged_fight_outcome(response, source_version=None, coverage=None)
    forged_response = reseal(
        response,
        source_outcomes=(forged_outcome, *response.source_outcomes[1:]),
        warnings=remove_excerpt_warning(response),
    )

    with pytest.raises(EvidenceValidationError, match="reports None coverage"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def test_excerpt_served_without_its_warning_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.PROTOCOL_CONTEXT_ONLY)
    forged_response = reseal(response, warnings=remove_excerpt_warning(response))

    with pytest.raises(EvidenceValidationError, match="excerpt warning must appear"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def test_excerpt_relabeled_as_full_coverage_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.PROTOCOL_CONTEXT_ONLY)
    forged_outcome = build_forged_fight_outcome(response, coverage=SnapshotCoverage.FULL)
    forged_response = reseal(
        response,
        source_outcomes=(forged_outcome, *response.source_outcomes[1:]),
        warnings=remove_excerpt_warning(response),
    )

    with pytest.raises(EvidenceValidationError, match="the pinned snapshot is excerpt"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def relabel_fight_evidence(
    response: TopicContextResponse, source_version: str
) -> tuple[EvidenceAnchor, ...]:
    relabeled_evidence: list[EvidenceAnchor] = []
    for anchor in response.evidence:
        if anchor.source_type is SourceType.MITRE_FIGHT_YAML:
            anchor = anchor.model_copy(update={"source_version": source_version})
        relabeled_evidence.append(anchor)
    return tuple(relabeled_evidence)


def test_excerpt_answer_relabeled_wholesale_as_the_full_file_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    assert FULL_UPSTREAM is not None
    response = explore(fixture_bundle, QueryScope.PROTOCOL_CONTEXT_ONLY)
    forged_outcome = build_forged_fight_outcome(
        response, source_version=FULL_UPSTREAM.source_version, coverage=SnapshotCoverage.FULL
    )
    forged_response = reseal(
        response,
        source_outcomes=(forged_outcome, *response.source_outcomes[1:]),
        evidence=relabel_fight_evidence(response, FULL_UPSTREAM.source_version),
        warnings=remove_excerpt_warning(response),
    )

    with pytest.raises(EvidenceValidationError, match="another snapshot than the pinned one"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def test_excerpt_warning_without_a_fight_outcome_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    protocol_answer = explore(fixture_bundle, QueryScope.PROTOCOL_CONTEXT_ONLY)
    implementation_answer = explore(fixture_bundle, QueryScope.IMPLEMENTATION_ONLY)
    excerpt_warning = protocol_answer.warnings[-1]
    forged_response = reseal(
        implementation_answer, warnings=(*implementation_answer.warnings, excerpt_warning)
    )

    with pytest.raises(EvidenceValidationError, match="excerpt warning must appear"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


@pytest.mark.parametrize(
    "warning_edit", ["wrong_count", "duplicated"], ids=["wrong_count", "duplicated"]
)
def test_excerpt_warning_must_state_the_pinned_size_exactly_once(
    fixture_bundle: FixtureBundle, warning_edit: str, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.PROTOCOL_CONTEXT_ONLY)
    excerpt_warning = response.warnings[-1]
    edited_warnings = {
        "wrong_count": (
            *remove_excerpt_warning(response),
            excerpt_warning.model_copy(
                update={"subject": "mitre_fight: excerpt of 183 techniques"}
            ),
        ),
        "duplicated": (*response.warnings, excerpt_warning),
    }[warning_edit]
    forged_response = reseal(response, warnings=edited_warnings)

    with pytest.raises(EvidenceValidationError, match="excerpt warning must appear"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def test_fight_answer_without_a_pinned_snapshot_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.PROTOCOL_CONTEXT_ONLY)

    with pytest.raises(EvidenceValidationError, match="no FiGHT snapshot is pinned"):
        validate_topic_context_response(
            reseal(response, warnings=remove_excerpt_warning(response)),
            None,
            packaged_evidence_catalog,
        )


def test_fight_anchor_with_other_provenance_than_the_pinned_snapshot_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.PROTOCOL_CONTEXT_ONLY)
    moved_evidence: list[EvidenceAnchor] = []
    for anchor in response.evidence:
        if anchor.source_type is SourceType.MITRE_FIGHT_YAML:
            anchor = anchor.model_copy(update={"source_uri": "https://example.com/other.yaml"})
        moved_evidence.append(anchor)
    forged_response = reseal(response, evidence=tuple(moved_evidence))

    with pytest.raises(EvidenceValidationError, match="provenance differs from the pinned"):
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)


def test_technique_outside_the_pinned_excerpt_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    assert PINNED_EXCERPT is not None
    response = explore(fixture_bundle, QueryScope.PROTOCOL_CONTEXT_ONLY)
    narrower_excerpt = PINNED_EXCERPT.model_copy(
        update={"technique_ids": ("FGT1562.501",), "technique_count": 1}
    )

    with pytest.raises(EvidenceValidationError, match="not in the pinned snapshot"):
        validate_topic_context_response(response, narrower_excerpt, packaged_evidence_catalog)


def test_excerpt_searched_without_matches_keeps_its_warning(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.PROTOCOL_CONTEXT_ONLY)
    fight_no_match = build_forged_fight_outcome(response, status=ResultStatus.NO_MATCH)
    no_match_answer = reseal(
        response,
        protocol_context=(),
        evidence=tuple(list_candidate_anchors(response)),
        source_outcomes=(fight_no_match, *response.source_outcomes[1:]),
        status=ResultStatus.NO_MATCH,
    )

    validate_topic_context_response(no_match_answer, PINNED_EXCERPT, packaged_evidence_catalog)
    with pytest.raises(EvidenceValidationError, match="excerpt warning must appear"):
        validate_topic_context_response(
            reseal(no_match_answer, warnings=remove_excerpt_warning(no_match_answer)),
            PINNED_EXCERPT,
            packaged_evidence_catalog,
        )


def list_candidate_anchors(response: TopicContextResponse) -> list[EvidenceAnchor]:
    candidate_anchors: list[EvidenceAnchor] = []
    for anchor in response.evidence:
        if anchor.source_type is not SourceType.MITRE_FIGHT_YAML:
            candidate_anchors.append(anchor)
    return candidate_anchors


def test_cve_anchor_with_a_forged_source_and_recomputed_id_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    response = explore(fixture_bundle, QueryScope.IMPLEMENTATION_ONLY)
    genuine_anchor = list_candidate_anchors(response)[0]
    forged_anchor = seal_evidence_anchor(
        genuine_anchor.model_copy(
            update={
                "source_uri": "https://attacker.invalid/forged",
                "excerpt": "FORGED SOURCE EXCERPT",
            }
        )
    )
    rewritten_json = response.model_dump_json().replace(
        genuine_anchor.evidence_id, forged_anchor.evidence_id
    )
    rewritten_response = TopicContextResponse.model_validate_json(rewritten_json)
    forged_evidence: list[EvidenceAnchor] = []
    for anchor in rewritten_response.evidence:
        if anchor.evidence_id == forged_anchor.evidence_id:
            anchor = forged_anchor
        forged_evidence.append(anchor)
    forged_response = reseal(rewritten_response, evidence=tuple(forged_evidence))

    with pytest.raises(EvidenceValidationError) as raised:
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)
    # The rewritten record cites the forged ID, so it no longer equals the stored record.
    assert raised.value.violations == (
        f"{genuine_anchor.authoritative_record_id}: weakness associations differ from the "
        "mapping snapshot",
        f"{forged_anchor.evidence_id}: not an anchor this service's sources hold",
        f"{genuine_anchor.authoritative_record_id}: differs from the record this service's "
        "sources hold",
    )


def test_resealed_response_serving_a_forged_technique_is_rejected(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    """The reviewer's forgery: a technique renamed and given other tactics, behind its genuine
    anchor."""
    response = build_topic_context_service(fixture_bundle).explore(
        TopicContextRequest(query="5G AKA", scope=QueryScope.MIXED)
    )
    validate_topic_context_response(response, PINNED_EXCERPT, packaged_evidence_catalog)
    item = response.protocol_context[0]
    forged_tactic_names: list[str] = []
    for _ in item.tactic_names:
        forged_tactic_names.append("FORGED")
    forged_item = item.model_copy(
        update={"name": "FORGED technique name", "tactic_names": tuple(forged_tactic_names)}
    )
    forged_response = reseal(
        response, protocol_context=(forged_item, *response.protocol_context[1:])
    )

    with pytest.raises(EvidenceValidationError) as raised:
        validate_topic_context_response(forged_response, PINNED_EXCERPT, packaged_evidence_catalog)

    assert raised.value.violations == (
        f"{item.technique_id}: differs from the technique this service's sources hold",
    )


def test_served_technique_differing_only_in_what_its_search_matched_passes(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    """``matched_fields`` and ``matched_terms`` come from the search, not the source, so the
    catalog re-check ignores them."""
    response = explore(fixture_bundle, QueryScope.PROTOCOL_CONTEXT_ONLY)
    served_item = response.protocol_context[0]
    catalogued_item = packaged_evidence_catalog.get_technique(served_item.technique_id)
    assert served_item.matched_terms
    assert served_item != catalogued_item

    # Raises nothing.
    validate_topic_context_response(response, PINNED_EXCERPT, packaged_evidence_catalog)
