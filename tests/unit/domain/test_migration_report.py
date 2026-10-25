"""The migration report's contract (ADR 0008 §1, §6, §7, §9, §10): a failed run, and only
one, carries its failure, whose message is the fixed sentence of its code; a run that
wrote or found a store names it by its import identity and manifest hash and states the
server's fixed rollback kind, scope and instruction; a run that published no store names
none; KEV rows without an NVD record bring the fixed advice; legacy root findings cite the
legacy formats' commit; skipped entries are located, bounded, and never quoted."""

from typing import Any

import pytest
from pydantic import ValidationError

from cve_kgrag.domain.corpus_store_manifest import (
    ROLLBACK_INSTRUCTION,
    ROLLBACK_KIND,
    ROLLBACK_SCOPE,
)
from cve_kgrag.domain.migration_report import (
    KEV_WITHOUT_NVD_RECORD_ADVICE,
    LEGACY_FORMATS_COMMIT,
    MAX_REPORTED_LOCATORS,
    MIGRATION_FAILURE_MESSAGES,
    MigrationFailed,
    MigrationFailure,
    MigrationFailureCode,
    MigrationOutcome,
    MigrationReport,
    build_migration_failure,
)

IMPORT_IDENTITY_SHA256 = "a" * 64
STORE_ROLLBACK = {
    "rollback_kind": ROLLBACK_KIND,
    "rollback_scope": ROLLBACK_SCOPE,
    "rollback_instruction": ROLLBACK_INSTRUCTION,
}
NO_ROLLBACK = {"rollback_kind": None, "rollback_scope": None, "rollback_instruction": None}
STORE_MANIFEST_SHA256 = "b" * 64
KEV_FAILURE_CODES = [
    MigrationFailureCode.KEV_INVALID_ENCODING,
    MigrationFailureCode.KEV_INVALID_HEADER,
    MigrationFailureCode.KEV_INVALID_ROW,
    MigrationFailureCode.KEV_CONFLICTING_ROWS,
    MigrationFailureCode.KEV_TOO_LARGE,
]


def build_report_fields(outcome: str, **overrides: Any) -> dict[str, Any]:
    """A report's fields for ``outcome``, consistent by default: a failed run carries a
    failure, an imported or already imported run names its store and rollback."""
    fields: dict[str, Any] = {
        "outcome": outcome,
        "failure": None,
        "import_identity_sha256": IMPORT_IDENTITY_SHA256,
        "store_manifest_sha256": None,
        "cve_outcomes": {"imported": 1},
        "candidate_outcomes": {"chosen": 1},
        "normalization_failures": {},
        "kev_outcomes": {},
        "kev_advice": None,
        "skipped_entries": [],
        "legacy_root_findings": None,
        "legacy_formats_commit": None,
        "rollback_kind": None,
        "rollback_scope": None,
        "rollback_instruction": None,
    }
    if outcome == "failed":
        fields["failure"] = build_migration_failure(MigrationFailureCode.NO_IMPORTABLE_RECORDS)
    if outcome in ("imported", "already_imported"):
        fields["store_manifest_sha256"] = STORE_MANIFEST_SHA256
        fields.update(STORE_ROLLBACK)
    fields.update(overrides)
    return fields


def build_skipped_entries(count: int) -> list[dict[str, Any]]:
    skipped_entries: list[dict[str, Any]] = []
    for entry_index in range(count):
        skipped_entries.append(
            {"input_position": 0, "entry_index": entry_index, "code": "missing_field"}
        )
    return skipped_entries


@pytest.mark.parametrize(
    "outcome",
    ["imported", "already_imported", "dry_run", "failed"],
    ids=["imported", "already_imported", "dry_run", "failed"],
)
def test_consistent_report_is_accepted(outcome: str) -> None:
    report = MigrationReport.model_validate(build_report_fields(outcome))

    assert report.outcome is MigrationOutcome(outcome)


def test_failed_report_without_its_failure_is_refused() -> None:
    report_fields = build_report_fields("failed", failure=None)

    with pytest.raises(ValidationError, match="a failed run, and only one, carries its failure"):
        MigrationReport.model_validate(report_fields)


@pytest.mark.parametrize(
    "outcome",
    ["imported", "already_imported", "dry_run"],
    ids=["imported", "already_imported", "dry_run"],
)
def test_report_that_did_not_fail_carrying_a_failure_is_refused(outcome: str) -> None:
    report_fields = build_report_fields(
        outcome, failure=build_migration_failure(MigrationFailureCode.TARGET_EXISTS)
    )

    with pytest.raises(ValidationError, match="a failed run, and only one, carries its failure"):
        MigrationReport.model_validate(report_fields)


@pytest.mark.parametrize(
    "report_fields",
    [
        build_report_fields("imported", **NO_ROLLBACK),
        build_report_fields("imported", rollback_kind=None),
        build_report_fields("imported", rollback_scope=None),
        build_report_fields("imported", rollback_instruction=None),
        build_report_fields("dry_run", **STORE_ROLLBACK),
        build_report_fields("dry_run", rollback_kind=ROLLBACK_KIND),
        build_report_fields("failed", rollback_scope=ROLLBACK_SCOPE),
        build_report_fields("dry_run", rollback_instruction=ROLLBACK_INSTRUCTION),
    ],
    ids=[
        "store_without_rollback",
        "store_without_kind",
        "store_without_scope",
        "store_without_instruction",
        "rollback_without_store",
        "kind_without_store",
        "scope_without_store",
        "instruction_without_store",
    ],
)
def test_report_naming_a_store_without_its_rollback_or_the_reverse_is_refused(
    report_fields: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError, match="states the fixed rollback"):
        MigrationReport.model_validate(report_fields)


@pytest.mark.parametrize(
    "rollback_instruction",
    ["Delete the target directory.", ROLLBACK_INSTRUCTION.lower(), ROLLBACK_INSTRUCTION + "\n"],
    ids=["other_sentence", "lower_case", "trailing_newline"],
)
def test_report_with_another_rollback_instruction_is_refused(rollback_instruction: str) -> None:
    report_fields = build_report_fields("imported", rollback_instruction=rollback_instruction)

    with pytest.raises(ValidationError, match="states the fixed rollback"):
        MigrationReport.model_validate(report_fields)


@pytest.mark.parametrize(
    "outcome", ["imported", "already_imported"], ids=["imported", "already_imported"]
)
def test_report_of_a_written_or_found_store_that_names_no_store_is_refused(outcome: str) -> None:
    report_fields = build_report_fields(outcome, store_manifest_sha256=None, **NO_ROLLBACK)

    with pytest.raises(ValidationError):
        MigrationReport.model_validate(report_fields)


def test_dry_run_report_naming_a_store_is_refused() -> None:
    report_fields = build_report_fields(
        "dry_run", store_manifest_sha256=STORE_MANIFEST_SHA256, **STORE_ROLLBACK
    )

    with pytest.raises(ValidationError):
        MigrationReport.model_validate(report_fields)


@pytest.mark.parametrize(
    ("kev_without_nvd_record", "kev_advice"),
    [(0, None), (3, KEV_WITHOUT_NVD_RECORD_ADVICE)],
    ids=["no_kev_row_without_nvd", "kev_rows_without_nvd"],
)
def test_report_with_kev_advice_exactly_when_kev_rows_lack_nvd_records_is_accepted(
    kev_without_nvd_record: int, kev_advice: str | None
) -> None:
    report = MigrationReport.model_validate(
        build_report_fields(
            "dry_run",
            kev_outcomes={"kev_without_nvd_record": kev_without_nvd_record},
            kev_advice=kev_advice,
        )
    )

    assert report.kev_advice == kev_advice


@pytest.mark.parametrize(
    ("kev_without_nvd_record", "kev_advice"),
    [(0, KEV_WITHOUT_NVD_RECORD_ADVICE), (3, None), (3, "Add a feed.")],
    ids=["advice_without_need", "need_without_advice", "other_sentence"],
)
def test_report_with_kev_advice_out_of_step_with_its_counts_is_refused(
    kev_without_nvd_record: int, kev_advice: str | None
) -> None:
    report_fields = build_report_fields(
        "dry_run",
        kev_outcomes={"kev_without_nvd_record": kev_without_nvd_record},
        kev_advice=kev_advice,
    )

    with pytest.raises(ValidationError, match="KEV advice"):
        MigrationReport.model_validate(report_fields)


@pytest.mark.parametrize(
    "overrides",
    [
        {"legacy_root_findings": {"pickle": 1}, "legacy_formats_commit": None},
        {"legacy_root_findings": None, "legacy_formats_commit": LEGACY_FORMATS_COMMIT},
    ],
    ids=["findings_without_commit", "commit_without_findings"],
)
def test_report_with_legacy_findings_and_commit_out_of_step_is_refused(
    overrides: dict[str, Any],
) -> None:
    report_fields = build_report_fields("dry_run", **overrides)

    with pytest.raises(ValidationError, match="legacy formats' commit"):
        MigrationReport.model_validate(report_fields)


def test_report_with_legacy_findings_citing_the_commit_is_accepted() -> None:
    report = MigrationReport.model_validate(
        build_report_fields(
            "dry_run",
            legacy_root_findings={"pickle": 1},
            legacy_formats_commit=LEGACY_FORMATS_COMMIT,
        )
    )

    assert report.legacy_formats_commit == "b64eef3"


def test_report_naming_a_store_without_its_import_identity_is_refused() -> None:
    report_fields = build_report_fields("imported", import_identity_sha256=None)

    with pytest.raises(ValidationError):
        MigrationReport.model_validate(report_fields)


def test_report_holds_at_most_the_capped_number_of_skipped_entries() -> None:
    report = MigrationReport.model_validate(
        build_report_fields("dry_run", skipped_entries=build_skipped_entries(MAX_REPORTED_LOCATORS))
    )

    assert len(report.skipped_entries) == MAX_REPORTED_LOCATORS


def test_report_with_more_skipped_entries_than_the_cap_is_refused() -> None:
    report_fields = build_report_fields(
        "dry_run", skipped_entries=build_skipped_entries(MAX_REPORTED_LOCATORS + 1)
    )

    with pytest.raises(ValidationError):
        MigrationReport.model_validate(report_fields)


@pytest.mark.parametrize(
    "skipped_entry",
    [
        {"input_position": 0, "entry_index": 0, "code": "missing_field", "cve_id": "CVE-9999-0001"},
        {"input_position": -1, "entry_index": 0, "code": "missing_field"},
        {"input_position": 0, "entry_index": -1, "code": "missing_field"},
        {"input_position": 0, "entry_index": 0, "code": "Value error, bad entry"},
    ],
    ids=["entry_content", "negative_input_position", "negative_entry_index", "free_text_code"],
)
def test_skipped_entry_beyond_a_locator_and_its_code_is_refused(
    skipped_entry: dict[str, Any],
) -> None:
    report_fields = build_report_fields("dry_run", skipped_entries=[skipped_entry])

    with pytest.raises(ValidationError):
        MigrationReport.model_validate(report_fields)


@pytest.mark.parametrize(
    "report_fields",
    [
        build_report_fields("imported", store_manifest_sha256="B" * 64),
        build_report_fields("imported", import_identity_sha256="a" * 63),
        build_report_fields("rolled_back"),
        build_report_fields("dry_run", cve_outcomes={"skipped": 1}),
        build_report_fields("dry_run", legacy_root_findings={"chroma_store": 1}),
        build_report_fields("dry_run", input_text="CVE-9999-0001"),
    ],
    ids=[
        "store_hash_upper_case",
        "identity_hash_too_short",
        "unknown_outcome",
        "unknown_cve_outcome",
        "unknown_legacy_file_kind",
        "unknown_field",
    ],
)
def test_report_with_a_malformed_field_is_refused(report_fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        MigrationReport.model_validate(report_fields)


@pytest.mark.parametrize("code", list(MigrationFailureCode), ids=str)
def test_every_failure_code_builds_a_failure_with_its_fixed_message(
    code: MigrationFailureCode,
) -> None:
    failure = build_migration_failure(code, input_position=3)

    assert (failure.code, failure.message, failure.input_position) == (
        code,
        MIGRATION_FAILURE_MESSAGES[code],
        3,
    )


def test_every_failure_code_has_its_own_message() -> None:
    distinct_messages = set(MIGRATION_FAILURE_MESSAGES.values())

    assert len(distinct_messages) == len(MigrationFailureCode)


@pytest.mark.parametrize("code", KEV_FAILURE_CODES, ids=str)
def test_kev_failure_message_offers_both_ways_on(code: MigrationFailureCode) -> None:
    message = build_migration_failure(code).message

    assert "Fix the file" in message
    assert "remove the cisa-kev input from the manifest" in message


@pytest.mark.parametrize(
    "failure_fields",
    [
        {"code": "target_exists", "message": "The target exists.", "input_position": None},
        {
            "code": "target_exists",
            "message": MIGRATION_FAILURE_MESSAGES[MigrationFailureCode.INPUT_UNREADABLE],
            "input_position": None,
        },
        {
            "code": "input_unreadable",
            "message": MIGRATION_FAILURE_MESSAGES[MigrationFailureCode.INPUT_UNREADABLE],
            "input_position": -1,
        },
        {"code": "disk_full", "message": "The disk is full.", "input_position": None},
    ],
    ids=["free_message", "another_codes_message", "negative_input_position", "unknown_code"],
)
def test_failure_without_its_codes_fixed_message_is_refused(
    failure_fields: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        MigrationFailure.model_validate(failure_fields)


def test_migration_failed_carries_its_code_and_input_position() -> None:
    failure = MigrationFailed(MigrationFailureCode.BAD_COMPRESSION, input_position=2)

    assert (failure.code, failure.input_position, str(failure)) == (
        MigrationFailureCode.BAD_COMPRESSION,
        2,
        "bad_compression",
    )
