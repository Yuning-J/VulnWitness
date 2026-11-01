"""A FiGHT snapshot is served only when its pin and shape check out; status text is kept."""

from datetime import date
from typing import Any

import pytest

from tests.support.builders import (
    FIGHT_TEST_COMMIT,
    build_catalog,
    build_fight_document,
    build_fight_technique,
    build_known_snapshot,
)
from tests.support.clocks import FIXED_STARTED_AT, read_fixed_clock
from tests.support.collect import list_technique_ids
from vulnwitness.adapters.fight.pinned_yaml import (
    FightSnapshotError,
    PinnedFightYamlSource,
    UnavailableFightSource,
)
from vulnwitness.adapters.fight.snapshot_catalog import (
    default_fight_snapshot_catalog_file,
    load_fight_snapshot_catalog,
)
from vulnwitness.domain.hashing import sha256_hex
from vulnwitness.domain.taxonomy import BackendStatus, KnowledgeScope, SourceType
from vulnwitness.domain.threat_context import ObservationStatus, SnapshotCoverage


def load_snapshot(snapshot: bytes, **catalog_entry: Any) -> PinnedFightYamlSource:
    """Load ``snapshot`` with a catalog that lists it (full coverage unless overridden)."""
    catalog = build_catalog(build_known_snapshot(snapshot, **catalog_entry))
    return PinnedFightYamlSource(snapshot, sha256_hex(snapshot), catalog, read_fixed_clock)


def load_source(techniques: list[dict[str, Any]]) -> PinnedFightYamlSource:
    technique_ids: set[object] = set()
    for technique in techniques:
        technique_ids.add(technique.get("id"))
    return load_snapshot(build_fight_document(techniques), technique_count=len(technique_ids))


def test_snapshot_whose_hash_differs_from_the_pin_is_refused() -> None:
    snapshot = build_fight_document([build_fight_technique()])
    catalog = build_catalog(build_known_snapshot(snapshot))

    with pytest.raises(FightSnapshotError, match="does not match the pinned"):
        PinnedFightYamlSource(snapshot, "f" * 64, catalog, read_fixed_clock)


def test_snapshot_missing_from_the_reviewed_catalog_is_refused() -> None:
    snapshot = build_fight_document([build_fight_technique()])
    other_snapshot = build_fight_document([build_fight_technique(name="Other")])
    catalog = build_catalog(build_known_snapshot(other_snapshot))

    with pytest.raises(FightSnapshotError, match="not in the reviewed catalog"):
        PinnedFightYamlSource(snapshot, sha256_hex(snapshot), catalog, read_fixed_clock)


def test_packaged_catalog_refuses_a_file_it_does_not_list() -> None:
    snapshot = build_fight_document([build_fight_technique()])
    packaged_catalog = load_fight_snapshot_catalog(default_fight_snapshot_catalog_file())

    with pytest.raises(FightSnapshotError, match="not in the reviewed catalog"):
        PinnedFightYamlSource(snapshot, sha256_hex(snapshot), packaged_catalog, read_fixed_clock)


@pytest.mark.parametrize(
    "techniques",
    [
        [build_fight_technique(status="Rumoured")],
        [build_fight_technique(id="T1557")],
        [build_fight_technique(tactics=["TA0099"])],
        [build_fight_technique(id="FGT9001.501", **{"subtechnique-of": "FGT9002"})],
        [build_fight_technique(id="FGT9001.501")],
        [build_fight_technique(), build_fight_technique()],
        [build_fight_technique(procedureexamples="none")],
        [build_fight_technique(name="")],
        [build_fight_technique(**{"subtechnique-of": "FGT9001"})],
        [build_fight_technique(tactics=["TA0006", "TA0006"])],
        [build_fight_technique(tactics=[])],
        [build_fight_technique(tactics=[["TA0006"]])],
        [build_fight_technique(id="TA0006")],
        [build_fight_technique(added=date(2026, 1, 1))],
    ],
    ids=[
        "unknown_status",
        "malformed_id",
        "unknown_tactic",
        "wrong_parent",
        "sub_technique_without_parent",
        "duplicate_id",
        "procedures_not_a_list",
        "empty_name",
        "own_parent",
        "repeated_tactic",
        "no_tactic",
        "tactic_not_a_string",
        "tactic_id_as_technique_id",
        "yaml_date_value",
    ],
)
def test_snapshot_with_unexpected_shape_is_refused(techniques: list[dict[str, Any]]) -> None:
    with pytest.raises(FightSnapshotError):
        load_source(techniques)


@pytest.mark.parametrize(
    ("source_status", "expected_status"),
    [
        ("Theoretical", ObservationStatus.THEORETICAL),
        ("POC", ObservationStatus.PROOF_OF_CONCEPT),
        ("Proof Of Concept", ObservationStatus.PROOF_OF_CONCEPT),
        ("Observed", ObservationStatus.OBSERVED),
        ("Observed In 4G; Possible In 5G", ObservationStatus.OBSERVED_OUTSIDE_5G),
        ("Observed In Enterprise", ObservationStatus.OBSERVED_OUTSIDE_5G),
    ],
)
def test_status_is_normalized_and_its_published_text_kept(
    source_status: str, expected_status: ObservationStatus
) -> None:
    source = load_source([build_fight_technique(status=source_status)])

    item = source.search(["KeyHub"], 5).items[0]

    assert item.status is expected_status
    assert item.source_status == source_status


def build_scored_technique(
    technique_id: str, name: str, bluf: str, description: str
) -> dict[str, Any]:
    """A technique whose scored texts a test fixes in full, with one shared procedure, so
    two techniques given texts of equal word counts have equal BM25 lengths."""
    return build_fight_technique(
        id=technique_id,
        name=name,
        bluf=bluf,
        description=description,
        procedureexamples=[{"name": "Replay", "description": "Replays traffic."}],
    )


def load_order_scenario() -> PinnedFightYamlSource:
    """FGT9001 and FGT9003 name the common KeyHub and DKX once each; FGT9002 names only
    the rare Zeta, three times. All three have the same word count."""
    return load_source(
        [
            build_scored_technique(
                "FGT9001", "Demo Technique", "Abuses the KeyHub.", "Replays DKX messages."
            ),
            build_scored_technique(
                "FGT9002", "Demo Technique", "Abuses the Zeta.", "Replays Zeta Zeta."
            ),
            build_scored_technique(
                "FGT9003", "Demo Technique", "Abuses the KeyHub.", "Replays DKX messages."
            ),
        ]
    )


def test_search_orders_by_bm25_score_not_by_distinct_terms_named() -> None:
    source = load_order_scenario()

    outcome = source.search(["KeyHub", "DKX", "Zeta"], 5)

    assert list_technique_ids(outcome.items) == ["FGT9002", "FGT9001", "FGT9003"]
    assert outcome.matched_count == 3


@pytest.mark.parametrize(
    "terms",
    [["Zeta", "DKX", "KeyHub"], ["DKX", "Zeta", "KeyHub"]],
    ids=["reversed", "shuffled"],
)
def test_search_order_does_not_depend_on_the_order_of_the_sent_terms(terms: list[str]) -> None:
    source = load_order_scenario()

    outcome = source.search(terms, 5)

    assert list_technique_ids(outcome.items) == ["FGT9002", "FGT9001", "FGT9003"]


def test_term_named_in_several_fields_scores_each_span() -> None:
    source = load_source(
        [
            build_scored_technique(
                "FGT9001", "Demo Technique", "Abuses the hub.", "Abuse of Zeta."
            ),
            build_scored_technique(
                "FGT9002", "Zeta Technique", "Abuses the Zeta.", "Abuse of Zeta."
            ),
        ]
    )

    outcome = source.search(["Zeta"], 5)

    assert list_technique_ids(outcome.items) == ["FGT9002", "FGT9001"]
    assert outcome.items[0].matched_fields == ("name", "bluf", "description")


def test_alias_spellings_of_one_term_count_once_as_the_first_spelling() -> None:
    # FGT9002 names KeyHub twice, FGT9001 names DKX once, at equal length and equal df:
    # FGT9001 would come first only if DKX and D-KX were scored as two terms.
    source = load_source(
        [
            build_scored_technique("FGT9001", "Demo Technique", "Abuses the DKX.", "Abuse of hub."),
            build_scored_technique(
                "FGT9002", "Demo Technique", "Abuses the KeyHub.", "Abuse of KeyHub."
            ),
        ]
    )

    outcome = source.search(["DKX", "D-KX", "KeyHub"], 5)

    assert list_technique_ids(outcome.items) == ["FGT9002", "FGT9001"]
    assert outcome.items[1].matched_terms == ("DKX",)


def test_matched_terms_follow_the_sent_order_with_the_first_alias_spelling() -> None:
    # KeyHub sits in the bluf, D-KX in the description and DKX in the procedure:
    # field order would put KeyHub first, and keeping both spellings would add D-KX.
    source = load_source([build_fight_technique(description="[SYNTHETIC] D-KX.")])

    outcome = source.search(["DKX", "D-KX", "KeyHub"], 5)

    assert outcome.items[0].matched_terms == ("DKX", "KeyHub")


def test_technique_naming_no_term_is_not_returned() -> None:
    source = load_source([build_fight_technique()])

    assert source.search(["SUCI"], 5).items == ()


def test_search_names_each_sent_term_no_technique_holds_once_in_sent_order() -> None:
    source = load_source([build_fight_technique()])

    outcome = source.search(["SUCI", "KeyHub", "gtp", "Suci"], 5)

    assert outcome.unindexed_terms == ("SUCI", "gtp")
    assert list_technique_ids(outcome.items) == ["FGT9001"]


def test_unconfigured_source_names_no_unindexed_term() -> None:
    assert UnavailableFightSource().search(["SUCI"], 5).unindexed_terms == ()


def test_each_item_cites_an_authoritative_threat_context_anchor() -> None:
    source = load_source([build_fight_technique()])

    outcome = source.search(["KeyHub"], 5)

    anchor = outcome.evidence[0]
    assert outcome.items[0].evidence_ids == (anchor.evidence_id,)
    assert anchor.scope is KnowledgeScope.PROTOCOL_THREAT_CONTEXT
    assert anchor.source_type is SourceType.MITRE_FIGHT_YAML
    assert anchor.authoritative_record_id == "FGT9001"
    assert anchor.source_version.startswith(f"0.0.0@{FIGHT_TEST_COMMIT}+sha256:")
    assert anchor.excerpt == "A demo adversary abuses the KeyHub."


def test_unconfigured_source_is_unavailable_not_empty() -> None:
    outcome = UnavailableFightSource().search(["KeyHub"], 5)

    assert outcome.status is BackendStatus.UNAVAILABLE
    assert outcome.items == ()


@pytest.mark.parametrize(
    "snapshot",
    [
        b"id: FiGHT\nid: FiGHT\ntactics: []\ntechniques: []\n",
        b"\xff\xfe not utf-8",
        b"- just a list\n",
        b"? [a, b]\n: 1\ntactics: []\ntechniques: []\n",
        b"[" * 100000,
        b"tactics:\n- {id: TA0006, name: A}\n- {id: TA0006, name: B}\ntechniques: []\n",
        b"tactics:\n- {id: X1, name: A}\ntechniques: []\n",
    ],
    ids=[
        "duplicate_key",
        "not_utf8",
        "not_a_mapping",
        "unhashable_key",
        "deep_nesting",
        "repeated_tactic_id",
        "malformed_tactic_id",
    ],
)
def test_unparseable_or_ambiguous_snapshot_is_refused(snapshot: bytes) -> None:
    with pytest.raises(FightSnapshotError):
        load_snapshot(snapshot)


def test_describe_reports_the_verified_snapshot_and_its_ingestion_time() -> None:
    snapshot = build_fight_document([build_fight_technique()])

    snapshot_info = load_snapshot(snapshot).describe()

    assert snapshot_info.snapshot_sha256 == sha256_hex(snapshot)
    assert snapshot_info.coverage is SnapshotCoverage.FULL
    assert snapshot_info.ingested_at == FIXED_STARTED_AT
    assert snapshot_info.technique_count == 1
    assert snapshot_info.tactic_count == 2


def test_tactic_names_are_searchable_through_their_techniques() -> None:
    source = load_source([build_fight_technique()])

    outcome = source.search(["Credential Access"], 5)

    assert list_technique_ids(outcome.items) == ["FGT9001"]
    assert outcome.items[0].matched_fields == ("tactics",)
    assert outcome.items[0].tactic_names == ("Credential Access",)


def test_matched_fields_follow_the_documented_field_order() -> None:
    source = load_source([build_fight_technique(name="KeyHub Abuse")])

    item = source.search(["KeyHub", "DKX"], 5).items[0]

    assert item.matched_fields == ("name", "bluf", "description", "procedureexamples")


def test_search_returns_at_most_the_limit() -> None:
    source = load_source([build_fight_technique(id="FGT9001"), build_fight_technique(id="FGT9002")])

    assert len(source.search(["KeyHub"], 1).items) == 1


def test_term_never_matches_across_two_procedure_texts() -> None:
    procedures = [
        {"name": "First", "description": "ends with D"},
        {"name": "KX", "description": "x"},
    ]
    source = load_source(
        [build_fight_technique(description="[SYNTHETIC] Unrelated.", procedureexamples=procedures)]
    )

    assert source.search(["D-KX"], 5).items == ()


def test_excerpt_collapses_whitespace_of_the_bluf() -> None:
    source = load_source([build_fight_technique(bluf="Line one\r\n  line two about KeyHub.")])

    assert source.search(["KeyHub"], 5).evidence[0].excerpt == "Line one line two about KeyHub."


@pytest.mark.parametrize(
    ("catalog_entry", "violation"),
    [
        ({"technique_count": 183}, "1 techniques, 183 catalogued"),
        ({"tactic_count": 15}, "2 tactics, 15 catalogued"),
        (
            {
                "coverage": SnapshotCoverage.EXCERPT,
                "derived_from_sha256": "5" * 64,
                "technique_ids": ["FGT9999"],
                "tactic_ids": ["TA0006", "TA0007"],
            },
            "differ from the catalogued technique IDs",
        ),
        (
            {
                "coverage": SnapshotCoverage.EXCERPT,
                "derived_from_sha256": "5" * 64,
                "technique_ids": ["FGT9001"],
                "tactic_ids": ["TA0006", "TA0040"],
            },
            "differ from the catalogued tactic IDs",
        ),
    ],
    ids=["technique_count", "tactic_count", "technique_ids", "tactic_ids"],
)
def test_snapshot_differing_from_its_catalog_entry_is_refused(
    catalog_entry: dict[str, Any], violation: str
) -> None:
    snapshot = build_fight_document([build_fight_technique()])
    full_entry = build_known_snapshot(b"upstream", snapshot_sha256="5" * 64)
    catalog = build_catalog(full_entry, build_known_snapshot(snapshot, **catalog_entry))

    with pytest.raises(FightSnapshotError, match=violation):
        PinnedFightYamlSource(snapshot, sha256_hex(snapshot), catalog, read_fixed_clock)


def test_empty_snapshot_can_never_match_a_catalog_entry() -> None:
    snapshot = b"tactics: []\ntechniques: []\n"

    with pytest.raises(FightSnapshotError, match="0 techniques, 1 catalogued"):
        load_snapshot(snapshot)


def test_coverage_comes_from_the_catalog_entry() -> None:
    snapshot = build_fight_document([build_fight_technique()])

    snapshot_info = load_snapshot(snapshot).describe()

    assert snapshot_info.coverage is SnapshotCoverage.FULL
    assert (
        snapshot_info.source_version == f"0.0.0@{FIGHT_TEST_COMMIT}+sha256:{sha256_hex(snapshot)}"
    )


def test_search_outcome_names_the_snapshot_its_anchors_come_from() -> None:
    outcome = load_source([build_fight_technique()]).search(["KeyHub"], 5)

    assert outcome.snapshot is not None
    assert outcome.evidence[0].source_version == outcome.snapshot.source_version
