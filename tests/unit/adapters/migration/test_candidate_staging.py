"""Proves how the importer chooses each CVE's winner among its staged NVD candidates
(ADR 0008 §5) and how the staging database hands candidates and anchors back (§8).

``resolve_cve`` is pure, so its cases build ``StagedCandidate`` values directly: the
latest modification time decides, equal candidates are broken by the fixed tie-break,
disagreeing formats drop the 1.1 candidates, a rejected winner withdraws the CVE, and a
malformed or unorderable candidate fails closed. ``CandidateStaging`` is run on a real
SQLite file under ``tmp_path`` with small injected limits to reach its caps, and a
database or disk error from it fails as ``staging_failed``."""

import shutil
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from cve_kgrag.adapters.migration.candidate_staging import (
    SIZE_CHECK_INTERVAL_ROWS,
    CandidateStaging,
    CandidateState,
    CveResolution,
    StagedCandidate,
    resolve_cve,
)
from cve_kgrag.adapters.migration.migration_limits import MigrationLimits
from cve_kgrag.domain.corpus_store_manifest import NvdFeedFormat
from cve_kgrag.domain.migration_report import (
    CandidateOutcome,
    CveOutcome,
    MigrationFailed,
    MigrationFailureCode,
)

CVE_ID = "CVE-9999-0001"
# 2099-01-03T00:00:00Z and one day earlier, in microseconds since the epoch.
LATEST_US = 4_070_995_200_000_000
OLDER_US = LATEST_US - 86_400_000_000
# 2026-10-24T08:30:00Z and one hour later.
RETRIEVED_US = 1_792_830_600_000_000
LATER_RETRIEVED_US = RETRIEVED_US + 3_600_000_000
SEMANTIC_A = "a" * 64
SEMANTIC_B = "b" * 64
REJECTED_SEMANTIC = "e" * 64
CONTENT_SMALL = "1" * 64
CONTENT_LARGE = "9" * 64
SOURCE_URI_SMALL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2098.json.gz"
SOURCE_URI_LARGE = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2099.json.gz"
# Input 1's version is the smaller one, so a tie-break by input position would choose
# the other candidate.
SOURCE_VERSIONS = {0: "sha256:" + "f" * 64, 1: "sha256:" + "0" * 64}

CHOSEN = CandidateOutcome.CHOSEN
SUPERSEDED = CandidateOutcome.SUPERSEDED
IDENTICAL = CandidateOutcome.IDENTICAL_DUPLICATE
DROPPED = CandidateOutcome.DROPPED_FOR_FORMAT
MALFORMED = CandidateOutcome.MALFORMED
EXCLUDED = CandidateOutcome.IN_EXCLUDED_CVE


def build_active(
    semantic_sha256: str = SEMANTIC_A,
    last_modified_us: int | None = LATEST_US,
    feed_format: NvdFeedFormat = NvdFeedFormat.V2_0,
    cve_id: str = CVE_ID,
) -> StagedCandidate:
    return StagedCandidate(
        cve_id=cve_id,
        last_modified_us=last_modified_us,
        feed_format=feed_format,
        state=CandidateState.ACTIVE,
        semantic_sha256=semantic_sha256,
        input_position=0,
        entry_index=0,
        retrieved_at_us=RETRIEVED_US,
        source_uri=SOURCE_URI_LARGE,
        content_sha256=CONTENT_LARGE,
        raw_entry='{"id":"' + cve_id + '"}',
    )


def build_rejected(
    last_modified_us: int | None = LATEST_US, feed_format: NvdFeedFormat = NvdFeedFormat.V2_0
) -> StagedCandidate:
    return StagedCandidate(
        cve_id=CVE_ID,
        last_modified_us=last_modified_us,
        feed_format=feed_format,
        state=CandidateState.REJECTED,
        semantic_sha256=REJECTED_SEMANTIC,
        input_position=0,
        entry_index=1,
        retrieved_at_us=RETRIEVED_US,
        source_uri=SOURCE_URI_LARGE,
        content_sha256=None,
        raw_entry=None,
    )


def build_malformed(
    last_modified_us: int | None = LATEST_US, feed_format: NvdFeedFormat = NvdFeedFormat.V2_0
) -> StagedCandidate:
    return StagedCandidate(
        cve_id=CVE_ID,
        last_modified_us=last_modified_us,
        feed_format=feed_format,
        state=CandidateState.MALFORMED,
        semantic_sha256=None,
        input_position=0,
        entry_index=2,
        retrieved_at_us=RETRIEVED_US,
        source_uri=SOURCE_URI_LARGE,
        content_sha256=None,
        raw_entry=None,
    )


V2_ACTIVE_A = build_active(SEMANTIC_A)
V2_ACTIVE_B = build_active(SEMANTIC_B)
V1_ACTIVE_A = build_active(SEMANTIC_A, feed_format=NvdFeedFormat.V1_1)
V1_ACTIVE_B = build_active(SEMANTIC_B, feed_format=NvdFeedFormat.V1_1)
OLDER_ACTIVE_B = build_active(SEMANTIC_B, last_modified_us=OLDER_US)


@pytest.fixture
def staging_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "staging"
    directory.mkdir()
    return directory


@pytest.fixture
def staging(staging_dir: Path) -> Iterator[CandidateStaging]:
    candidate_staging = CandidateStaging(staging_dir, MigrationLimits())
    yield candidate_staging
    candidate_staging.close()


@pytest.fixture
def limited_staging(
    staging_dir: Path, request: pytest.FixtureRequest
) -> Iterator[CandidateStaging]:
    """Staging under the ``MigrationLimits`` the test passes indirectly."""
    candidate_staging = CandidateStaging(staging_dir, request.param)
    yield candidate_staging
    candidate_staging.close()


# --- resolve_cve: a single candidate -------------------------------------------------


@pytest.mark.parametrize(
    ("candidate", "expected_outcome", "expected_winner", "expected_candidate_outcome"),
    [
        (V2_ACTIVE_A, CveOutcome.IMPORTED, V2_ACTIVE_A, CHOSEN),
        (build_rejected(), CveOutcome.WITHDRAWN_BY_SOURCE, None, CHOSEN),
        (build_malformed(), CveOutcome.MALFORMED_WINNING_CANDIDATE, None, EXCLUDED),
        (
            build_active(last_modified_us=None),
            CveOutcome.IMPORTED,
            build_active(last_modified_us=None),
            CHOSEN,
        ),
        (build_rejected(last_modified_us=None), CveOutcome.WITHDRAWN_BY_SOURCE, None, CHOSEN),
        (
            build_malformed(last_modified_us=None),
            CveOutcome.MALFORMED_WINNING_CANDIDATE,
            None,
            EXCLUDED,
        ),
    ],
    ids=[
        "active_is_imported",
        "rejected_is_withdrawn",
        "malformed_is_excluded",
        "active_without_time_is_imported",
        "rejected_without_time_is_withdrawn",
        "malformed_without_time_is_excluded",
    ],
)
def test_resolve_cve_with_single_candidate_returns_its_state_outcome(
    candidate: StagedCandidate,
    expected_outcome: CveOutcome,
    expected_winner: StagedCandidate | None,
    expected_candidate_outcome: CandidateOutcome,
) -> None:
    # Act
    resolution = resolve_cve([candidate], SOURCE_VERSIONS)

    # Assert
    assert resolution == CveResolution(
        CVE_ID, expected_outcome, expected_winner, (expected_candidate_outcome,)
    )


# --- resolve_cve: the latest modification time decides -------------------------------


@pytest.mark.parametrize(
    ("group", "expected_outcomes"),
    [
        ([OLDER_ACTIVE_B, V2_ACTIVE_A], (SUPERSEDED, CHOSEN)),
        ([V2_ACTIVE_A, OLDER_ACTIVE_B], (CHOSEN, SUPERSEDED)),
    ],
    ids=["older_first", "newer_first"],
)
def test_resolve_cve_with_newer_candidate_imports_it_and_supersedes_older(
    group: list[StagedCandidate], expected_outcomes: tuple[CandidateOutcome, ...]
) -> None:
    # Act
    resolution = resolve_cve(group, SOURCE_VERSIONS)

    # Assert
    assert resolution == CveResolution(CVE_ID, CveOutcome.IMPORTED, V2_ACTIVE_A, expected_outcomes)


def test_resolve_cve_with_newer_active_from_older_format_imports_newer() -> None:
    # Arrange
    newer_v1 = build_active(SEMANTIC_A, feed_format=NvdFeedFormat.V1_1)
    older_v2 = build_active(SEMANTIC_B, last_modified_us=OLDER_US)

    # Act
    resolution = resolve_cve([older_v2, newer_v1], SOURCE_VERSIONS)

    # Assert
    assert resolution == CveResolution(CVE_ID, CveOutcome.IMPORTED, newer_v1, (SUPERSEDED, CHOSEN))


def test_resolve_cve_with_identical_latest_candidates_chooses_one_and_marks_rest_identical() -> (
    None
):
    # Arrange
    preferred = replace(V2_ACTIVE_A, retrieved_at_us=LATER_RETRIEVED_US, entry_index=7)
    group = [V2_ACTIVE_A, preferred, replace(V2_ACTIVE_A, entry_index=8), OLDER_ACTIVE_B]

    # Act
    resolution = resolve_cve(group, SOURCE_VERSIONS)

    # Assert
    assert resolution == CveResolution(
        CVE_ID, CveOutcome.IMPORTED, preferred, (IDENTICAL, CHOSEN, IDENTICAL, SUPERSEDED)
    )


# --- resolve_cve: the tie-break among equal candidates -------------------------------

TIE_BREAK_BASE = replace(V2_ACTIVE_A, content_sha256=CONTENT_LARGE)


@pytest.mark.parametrize(
    ("preferred", "other"),
    [
        (TIE_BREAK_BASE, replace(TIE_BREAK_BASE, feed_format=NvdFeedFormat.V1_1)),
        (replace(TIE_BREAK_BASE, retrieved_at_us=LATER_RETRIEVED_US), TIE_BREAK_BASE),
        (replace(TIE_BREAK_BASE, source_uri=SOURCE_URI_SMALL), TIE_BREAK_BASE),
        (replace(TIE_BREAK_BASE, input_position=1), TIE_BREAK_BASE),
        (replace(TIE_BREAK_BASE, content_sha256=CONTENT_SMALL), TIE_BREAK_BASE),
        (
            TIE_BREAK_BASE,
            replace(
                TIE_BREAK_BASE,
                feed_format=NvdFeedFormat.V1_1,
                retrieved_at_us=LATER_RETRIEVED_US,
                source_uri=SOURCE_URI_SMALL,
                input_position=1,
                content_sha256=CONTENT_SMALL,
            ),
        ),
        (
            replace(TIE_BREAK_BASE, retrieved_at_us=LATER_RETRIEVED_US),
            replace(
                TIE_BREAK_BASE,
                source_uri=SOURCE_URI_SMALL,
                input_position=1,
                content_sha256=CONTENT_SMALL,
            ),
        ),
        (
            replace(TIE_BREAK_BASE, source_uri=SOURCE_URI_SMALL),
            replace(TIE_BREAK_BASE, input_position=1, content_sha256=CONTENT_SMALL),
        ),
        (
            replace(TIE_BREAK_BASE, input_position=1),
            replace(TIE_BREAK_BASE, content_sha256=CONTENT_SMALL),
        ),
    ],
    ids=[
        "v2_over_v1",
        "later_retrieval",
        "smaller_source_uri",
        "smaller_source_version",
        "smaller_content_sha256",
        "format_before_every_other_key",
        "retrieval_before_uri_version_content",
        "uri_before_version_content",
        "version_before_content",
    ],
)
@pytest.mark.parametrize(
    ("is_preferred_first", "expected_outcomes"),
    [(True, (CHOSEN, IDENTICAL)), (False, (IDENTICAL, CHOSEN))],
    ids=["preferred_first", "preferred_last"],
)
def test_resolve_cve_with_equal_candidates_chooses_by_tie_break_order(
    preferred: StagedCandidate,
    other: StagedCandidate,
    is_preferred_first: bool,
    expected_outcomes: tuple[CandidateOutcome, ...],
) -> None:
    # Arrange
    group = [preferred, other] if is_preferred_first else [other, preferred]

    # Act
    resolution = resolve_cve(group, SOURCE_VERSIONS)

    # Assert
    assert resolution == CveResolution(CVE_ID, CveOutcome.IMPORTED, preferred, expected_outcomes)


# --- resolve_cve: disagreeing latest candidates ---------------------------------------


@pytest.mark.parametrize(
    ("group", "expected_outcomes"),
    [
        ([V2_ACTIVE_A, V2_ACTIVE_B], (EXCLUDED, EXCLUDED)),
        ([V1_ACTIVE_A, V1_ACTIVE_B], (EXCLUDED, EXCLUDED)),
        ([V2_ACTIVE_A, V2_ACTIVE_B, V2_ACTIVE_A], (EXCLUDED, EXCLUDED, EXCLUDED)),
        ([V2_ACTIVE_A, build_rejected()], (EXCLUDED, EXCLUDED)),
        ([build_rejected(feed_format=NvdFeedFormat.V1_1), V1_ACTIVE_A], (EXCLUDED, EXCLUDED)),
    ],
    ids=[
        "two_v2_differ",
        "two_v1_differ",
        "two_v2_agree_one_v2_differs",
        "v2_active_and_rejected",
        "v1_rejected_and_active",
    ],
)
def test_resolve_cve_with_differing_latest_of_one_format_is_conflicting_duplicate(
    group: list[StagedCandidate], expected_outcomes: tuple[CandidateOutcome, ...]
) -> None:
    # Act
    resolution = resolve_cve(group, SOURCE_VERSIONS)

    # Assert
    assert resolution == CveResolution(
        CVE_ID, CveOutcome.CONFLICTING_DUPLICATE, None, expected_outcomes
    )


@pytest.mark.parametrize(
    ("group", "expected_outcomes"),
    [
        ([V1_ACTIVE_B, V2_ACTIVE_A], (DROPPED, CHOSEN)),
        ([V2_ACTIVE_A, V1_ACTIVE_B, V1_ACTIVE_A], (CHOSEN, DROPPED, DROPPED)),
        (
            [V2_ACTIVE_A, V1_ACTIVE_B, replace(V2_ACTIVE_A, entry_index=5)],
            (CHOSEN, DROPPED, IDENTICAL),
        ),
    ],
    ids=["one_v2_one_v1", "v1_dropped_even_when_equal_to_v2", "two_equal_v2_one_v1"],
)
def test_resolve_cve_with_differing_formats_drops_v1_and_imports_agreeing_v2(
    group: list[StagedCandidate], expected_outcomes: tuple[CandidateOutcome, ...]
) -> None:
    # Act
    resolution = resolve_cve(group, SOURCE_VERSIONS)

    # Assert
    assert resolution == CveResolution(CVE_ID, CveOutcome.IMPORTED, V2_ACTIVE_A, expected_outcomes)


def test_resolve_cve_with_two_conflicting_v2_and_v1_equal_to_one_is_conflicting() -> None:
    # Arrange
    group = [V2_ACTIVE_A, V2_ACTIVE_B, V1_ACTIVE_A]

    # Act
    resolution = resolve_cve(group, SOURCE_VERSIONS)

    # Assert
    assert resolution == CveResolution(
        CVE_ID, CveOutcome.CONFLICTING_DUPLICATE, None, (EXCLUDED, EXCLUDED, EXCLUDED)
    )


def test_resolve_cve_with_v1_only_candidates_disagreeing_is_conflicting() -> None:
    # Arrange
    group = [V1_ACTIVE_A, V1_ACTIVE_B, build_rejected(feed_format=NvdFeedFormat.V1_1)]

    # Act
    resolution = resolve_cve(group, SOURCE_VERSIONS)

    # Assert
    assert resolution == CveResolution(
        CVE_ID, CveOutcome.CONFLICTING_DUPLICATE, None, (EXCLUDED, EXCLUDED, EXCLUDED)
    )


@pytest.mark.parametrize(
    ("group", "expected_resolution"),
    [
        (
            [build_rejected(feed_format=NvdFeedFormat.V1_1), V2_ACTIVE_A],
            CveResolution(CVE_ID, CveOutcome.IMPORTED, V2_ACTIVE_A, (DROPPED, CHOSEN)),
        ),
        (
            [V1_ACTIVE_A, build_rejected()],
            CveResolution(CVE_ID, CveOutcome.WITHDRAWN_BY_SOURCE, None, (DROPPED, CHOSEN)),
        ),
    ],
    ids=["v2_active_over_v1_rejected", "v2_rejected_over_v1_active"],
)
def test_resolve_cve_with_active_and_rejected_across_formats_follows_v2(
    group: list[StagedCandidate], expected_resolution: CveResolution
) -> None:
    # Act
    resolution = resolve_cve(group, SOURCE_VERSIONS)

    # Assert
    assert resolution == expected_resolution


# --- resolve_cve: withdrawal ----------------------------------------------------------


def test_resolve_cve_with_rejection_newer_than_actives_withdraws_and_never_revives() -> None:
    # Arrange
    group = [
        OLDER_ACTIVE_B,
        build_rejected(),
        build_active(SEMANTIC_A, last_modified_us=OLDER_US - 1),
    ]

    # Act
    resolution = resolve_cve(group, SOURCE_VERSIONS)

    # Assert
    assert resolution == CveResolution(
        CVE_ID, CveOutcome.WITHDRAWN_BY_SOURCE, None, (SUPERSEDED, CHOSEN, SUPERSEDED)
    )


def test_resolve_cve_with_identical_latest_rejections_withdraws_once() -> None:
    # Arrange
    group = [build_rejected(), build_rejected(feed_format=NvdFeedFormat.V1_1), OLDER_ACTIVE_B]

    # Act
    resolution = resolve_cve(group, SOURCE_VERSIONS)

    # Assert
    assert resolution == CveResolution(
        CVE_ID, CveOutcome.WITHDRAWN_BY_SOURCE, None, (CHOSEN, IDENTICAL, SUPERSEDED)
    )


# --- resolve_cve: failing closed ------------------------------------------------------


@pytest.mark.parametrize(
    ("group", "expected_outcomes"),
    [
        ([OLDER_ACTIVE_B, build_malformed()], (EXCLUDED, EXCLUDED)),
        ([V2_ACTIVE_A, build_malformed()], (EXCLUDED, EXCLUDED)),
        (
            [build_malformed(feed_format=NvdFeedFormat.V1_1), V2_ACTIVE_A, V2_ACTIVE_A],
            (EXCLUDED, EXCLUDED, EXCLUDED),
        ),
    ],
    ids=["malformed_newest", "malformed_tied_with_active", "malformed_v1_tied_with_v2"],
)
def test_resolve_cve_with_malformed_latest_candidate_is_malformed_winning_candidate(
    group: list[StagedCandidate], expected_outcomes: tuple[CandidateOutcome, ...]
) -> None:
    # Act
    resolution = resolve_cve(group, SOURCE_VERSIONS)

    # Assert
    assert resolution == CveResolution(
        CVE_ID, CveOutcome.MALFORMED_WINNING_CANDIDATE, None, expected_outcomes
    )


def test_resolve_cve_with_malformed_older_candidate_imports_winner_and_counts_malformed() -> None:
    # Arrange
    group = [build_malformed(last_modified_us=OLDER_US), V2_ACTIVE_A]

    # Act
    resolution = resolve_cve(group, SOURCE_VERSIONS)

    # Assert
    assert resolution == CveResolution(
        CVE_ID, CveOutcome.IMPORTED, V2_ACTIVE_A, (MALFORMED, CHOSEN)
    )


@pytest.mark.parametrize(
    "group",
    [
        [V2_ACTIVE_A, build_active(SEMANTIC_A, last_modified_us=None)],
        [build_active(SEMANTIC_B, last_modified_us=None), V2_ACTIVE_A],
        [build_malformed(last_modified_us=None), V2_ACTIVE_A],
        [build_rejected(last_modified_us=None), V2_ACTIVE_A],
        [build_active(last_modified_us=None), build_active(last_modified_us=None)],
    ],
    ids=[
        "equal_active_without_time",
        "differing_active_without_time",
        "malformed_without_time",
        "rejected_without_time",
        "every_candidate_without_time",
    ],
)
def test_resolve_cve_with_candidate_missing_time_in_group_is_unorderable(
    group: list[StagedCandidate],
) -> None:
    # Act
    resolution = resolve_cve(group, SOURCE_VERSIONS)

    # Assert
    assert resolution == CveResolution(
        CVE_ID, CveOutcome.UNORDERABLE_CANDIDATE, None, (EXCLUDED, EXCLUDED)
    )


def test_resolve_cve_candidate_outcomes_align_with_group_order() -> None:
    # Arrange
    group = [
        OLDER_ACTIVE_B,
        build_malformed(last_modified_us=OLDER_US),
        V1_ACTIVE_B,
        V2_ACTIVE_A,
        replace(V2_ACTIVE_A, entry_index=9),
    ]

    # Act
    resolution = resolve_cve(group, SOURCE_VERSIONS)

    # Assert
    assert resolution.candidate_outcomes == (SUPERSEDED, MALFORMED, DROPPED, CHOSEN, IDENTICAL)


# --- CandidateStaging -----------------------------------------------------------------


def list_group_cve_ids(staging: CandidateStaging) -> list[list[str]]:
    group_cve_ids: list[list[str]] = []
    for group in staging.list_candidate_groups():
        cve_ids: list[str] = []
        for candidate in group:
            cve_ids.append(candidate.cve_id)
        group_cve_ids.append(cve_ids)
    return group_cve_ids


def test_list_candidate_groups_returns_groups_in_lexical_cve_order_whatever_insert_order(
    staging: CandidateStaging,
) -> None:
    # Arrange
    for cve_id in ["CVE-9999-0003", "CVE-9999-0001", "CVE-9999-0002", "CVE-9999-0001"]:
        staging.add_candidate(build_active(cve_id=cve_id))

    # Act
    group_cve_ids = list_group_cve_ids(staging)

    # Assert
    assert group_cve_ids == [
        ["CVE-9999-0001", "CVE-9999-0001"],
        ["CVE-9999-0002"],
        ["CVE-9999-0003"],
    ]


def test_list_candidate_groups_orders_cve_ids_lexically_not_numerically(
    staging: CandidateStaging,
) -> None:
    # Arrange
    staging.add_candidate(build_active(cve_id="CVE-9999-2000"))
    staging.add_candidate(build_active(cve_id="CVE-9999-10000"))

    # Act
    group_cve_ids = list_group_cve_ids(staging)

    # Assert
    assert group_cve_ids == [["CVE-9999-10000"], ["CVE-9999-2000"]]


def test_list_candidate_groups_on_empty_staging_yields_nothing(
    staging: CandidateStaging,
) -> None:
    # Act
    group_cve_ids = list_group_cve_ids(staging)

    # Assert
    assert group_cve_ids == []


@pytest.mark.parametrize(
    "candidate",
    [
        replace(V2_ACTIVE_A, input_position=3, entry_index=41),
        build_rejected(feed_format=NvdFeedFormat.V1_1),
        build_malformed(last_modified_us=None),
    ],
    ids=["active", "rejected_v1", "malformed_without_time"],
)
def test_list_candidate_groups_returns_staged_candidate_unchanged(
    staging: CandidateStaging, candidate: StagedCandidate
) -> None:
    # Arrange
    staging.add_candidate(candidate)

    # Act
    groups = list(staging.list_candidate_groups())

    # Assert
    assert groups == [[candidate]]


def test_list_anchor_lines_returns_anchors_in_evidence_id_order_once_each(
    staging: CandidateStaging,
) -> None:
    # Arrange
    staging.add_anchor("ev:cccccccccccccccccccccccc", '{"anchor":"c"}')
    staging.add_anchor("ev:aaaaaaaaaaaaaaaaaaaaaaaa", '{"anchor":"a"}')
    staging.add_anchor("ev:bbbbbbbbbbbbbbbbbbbbbbbb", '{"anchor":"b"}')
    staging.add_anchor("ev:aaaaaaaaaaaaaaaaaaaaaaaa", '{"anchor":"a"}')

    # Act
    anchor_lines = list(staging.list_anchor_lines())

    # Assert
    assert anchor_lines == ['{"anchor":"a"}', '{"anchor":"b"}', '{"anchor":"c"}']


CANDIDATE_CAP_OF_TWO = MigrationLimits(max_nvd_candidates=2)
STAGING_CAP_OF_ONE_BYTE = MigrationLimits(max_staging_bytes=1)


@pytest.mark.parametrize(
    "limited_staging", [CANDIDATE_CAP_OF_TWO], indirect=True, ids=["cap_of_two"]
)
def test_add_candidate_up_to_candidate_cap_stages_every_candidate(
    limited_staging: CandidateStaging,
) -> None:
    # Act
    limited_staging.add_candidate(build_active(cve_id="CVE-9999-0001"))
    limited_staging.add_candidate(build_active(cve_id="CVE-9999-0002"))

    # Assert
    assert list_group_cve_ids(limited_staging) == [["CVE-9999-0001"], ["CVE-9999-0002"]]


@pytest.mark.parametrize(
    "limited_staging", [CANDIDATE_CAP_OF_TWO], indirect=True, ids=["cap_of_two"]
)
def test_add_candidate_past_candidate_cap_fails_with_too_many_candidates(
    limited_staging: CandidateStaging,
) -> None:
    # Arrange
    limited_staging.add_candidate(build_active(cve_id="CVE-9999-0001"))
    limited_staging.add_candidate(build_active(cve_id="CVE-9999-0002"))

    # Act
    with pytest.raises(MigrationFailed) as raised:
        limited_staging.add_candidate(build_active(cve_id="CVE-9999-0003"))

    # Assert
    assert raised.value.code is MigrationFailureCode.TOO_MANY_CANDIDATES


@pytest.mark.parametrize(
    "limited_staging", [STAGING_CAP_OF_ONE_BYTE], indirect=True, ids=["cap_of_one_byte"]
)
def test_check_size_past_staging_cap_fails_with_staging_too_large(
    limited_staging: CandidateStaging,
) -> None:
    # Arrange
    limited_staging.add_candidate(V2_ACTIVE_A)

    # Act
    with pytest.raises(MigrationFailed) as raised:
        limited_staging.check_size()

    # Assert
    assert raised.value.code is MigrationFailureCode.STAGING_TOO_LARGE


def test_check_size_within_staging_cap_accepts_staging(staging: CandidateStaging) -> None:
    # Arrange
    staging.add_candidate(V2_ACTIVE_A)

    # Act
    staging.check_size()

    # Assert
    assert list_group_cve_ids(staging) == [[CVE_ID]]


def stage_candidate_rows(staging: CandidateStaging, row_count: int) -> None:
    for number in range(row_count):
        staging.add_candidate(build_active(cve_id=f"CVE-9999-{number:04d}"))


def stage_anchor_rows(staging: CandidateStaging, row_count: int) -> None:
    for number in range(row_count):
        staging.add_anchor(f"ev:{number:024x}", '{"anchor":"' + str(number) + '"}')


@pytest.mark.parametrize(
    "limited_staging", [STAGING_CAP_OF_ONE_BYTE], indirect=True, ids=["cap_of_one_byte"]
)
@pytest.mark.parametrize(
    "stage_rows", [stage_candidate_rows, stage_anchor_rows], ids=["candidates", "anchors"]
)
def test_adding_rows_past_staging_cap_fails_with_staging_too_large_without_explicit_check(
    limited_staging: CandidateStaging, stage_rows: Callable[[CandidateStaging, int], None]
) -> None:
    # Act
    with pytest.raises(MigrationFailed) as raised:
        stage_rows(limited_staging, 2 * SIZE_CHECK_INTERVAL_ROWS)

    # Assert
    assert raised.value.code is MigrationFailureCode.STAGING_TOO_LARGE


def test_candidate_staging_in_a_missing_directory_fails_with_staging_failed(
    tmp_path: Path,
) -> None:
    # Arrange
    missing_dir = tmp_path / "missing"

    # Act
    with pytest.raises(MigrationFailed) as raised:
        CandidateStaging(missing_dir, MigrationLimits())

    # Assert
    assert raised.value.code is MigrationFailureCode.STAGING_FAILED


def add_one_candidate(staging: CandidateStaging) -> None:
    staging.add_candidate(V2_ACTIVE_A)


def add_one_anchor(staging: CandidateStaging) -> None:
    staging.add_anchor("ev:aaaaaaaaaaaaaaaaaaaaaaaa", '{"anchor":"a"}')


def read_candidate_groups(staging: CandidateStaging) -> None:
    list(staging.list_candidate_groups())


def read_anchor_lines(staging: CandidateStaging) -> None:
    list(staging.list_anchor_lines())


@pytest.mark.parametrize(
    "use_staging",
    [add_one_candidate, add_one_anchor, read_candidate_groups, read_anchor_lines],
    ids=["add_candidate", "add_anchor", "list_candidate_groups", "list_anchor_lines"],
)
def test_staging_used_after_its_database_is_closed_fails_with_staging_failed(
    staging: CandidateStaging, use_staging: Callable[[CandidateStaging], None]
) -> None:
    # Arrange
    staging.close()

    # Act
    with pytest.raises(MigrationFailed) as raised:
        use_staging(staging)

    # Assert
    assert raised.value.code is MigrationFailureCode.STAGING_FAILED


def test_check_size_on_a_removed_staging_directory_fails_with_staging_failed(
    staging: CandidateStaging, staging_dir: Path
) -> None:
    # Arrange
    staging.add_candidate(V2_ACTIVE_A)
    shutil.rmtree(staging_dir)

    # Act
    with pytest.raises(MigrationFailed) as raised:
        staging.check_size()

    # Assert
    assert raised.value.code is MigrationFailureCode.STAGING_FAILED
