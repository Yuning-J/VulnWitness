"""What an import reports: its outcome, why it failed when it did, and what became of every
entry, in the server's words and counts only (ADR 0008 §7, §10).

The report never quotes an input: an entry is located by the position of its input in
the sorted input list and its index in that input, and every message is the fixed
sentence of its code.
"""

from enum import StrEnum
from typing import Literal, Self

from pydantic import ConfigDict, Field, model_validator

from vulnwitness.domain.contract_model import ContractModel, describe_fixed_messages
from vulnwitness.domain.corpus_store_manifest import (
    ROLLBACK_INSTRUCTION,
    ROLLBACK_KIND,
    ROLLBACK_SCOPE,
    RollbackKind,
    RollbackScope,
)
from vulnwitness.domain.evidence import SHA256_PATTERN
from vulnwitness.domain.normalization import NormalizationFailureCode
from vulnwitness.domain.search import SCHEMA_VERSION, SchemaVersion

MAX_REPORTED_LOCATORS = 100
KEV_REMEDY = (
    " Fix the file, or remove the cisa-kev input from the manifest and run again without KEV."
)
KEV_WITHOUT_NVD_RECORD_ADVICE = (
    "Some KEV rows name a CVE no NVD input holds. Add the NVD year feed that covers each; "
    "a recent or modified feed covers a CVE only while it is inside that feed's window."
)
# The CVE-KGRAG commit whose writers define the legacy derived formats the walk recognises.
LegacyFormatsCommit = Literal["b64eef3"]
LEGACY_FORMATS_COMMIT: LegacyFormatsCommit = "b64eef3"


class MigrationOutcome(StrEnum):
    IMPORTED = "imported"
    ALREADY_IMPORTED = "already_imported"
    DRY_RUN = "dry_run"
    FAILED = "failed"


# The outcomes of a run that wrote a store or found it already written.
STORE_OUTCOMES = frozenset({MigrationOutcome.IMPORTED, MigrationOutcome.ALREADY_IMPORTED})


class MigrationFailureCode(StrEnum):
    """Why a run failed as a whole; no store is published."""

    INPUT_NOT_A_REGULAR_FILE = "input_not_a_regular_file"
    INPUT_UNREADABLE = "input_unreadable"
    INPUT_REPEATED = "input_repeated"
    INPUT_BYTES_REPEATED = "input_bytes_repeated"
    INPUT_CHANGED = "input_changed"
    ARTIFACT_UNDECLARED = "artifact_undeclared"
    ARTIFACT_CONFLICT = "artifact_conflict"
    FORMAT_MISMATCH = "format_mismatch"
    INCOMPLETE_FEED = "incomplete_feed"
    UNRECOGNISED_FORMAT = "unrecognised_format"
    DERIVED_FILE_DECLARED_AS_SOURCE = "derived_file_declared_as_source"
    BAD_COMPRESSION = "bad_compression"
    INVALID_JSON = "invalid_json"
    DUPLICATE_JSON_KEY = "duplicate_json_key"
    ENTRY_TOO_DEEP = "entry_too_deep"
    ENTRY_TOO_LARGE = "entry_too_large"
    GENERATED_AT_INVALID = "generated_at_invalid"
    RETRIEVED_BEFORE_GENERATED = "retrieved_before_generated"
    RETRIEVED_IN_FUTURE = "retrieved_in_future"
    COMPRESSED_FILE_TOO_LARGE = "compressed_file_too_large"
    DECOMPRESSED_FILE_TOO_LARGE = "decompressed_file_too_large"
    TOTAL_TOO_LARGE = "total_too_large"
    TOO_MANY_CANDIDATES = "too_many_candidates"
    STAGING_TOO_LARGE = "staging_too_large"
    STAGING_FAILED = "staging_failed"
    KEV_INVALID_ENCODING = "kev_invalid_encoding"
    KEV_INVALID_HEADER = "kev_invalid_header"
    KEV_INVALID_ROW = "kev_invalid_row"
    KEV_CONFLICTING_ROWS = "kev_conflicting_rows"
    KEV_TOO_LARGE = "kev_too_large"
    CNVD_UNCATALOGUED_FILE = "cnvd_uncatalogued_file"
    CNVD_INCOMPLETE_SNAPSHOT = "cnvd_incomplete_snapshot"
    CNVD_INVALID_PARQUET = "cnvd_invalid_parquet"
    CNVD_MIXED_SOURCES = "cnvd_mixed_sources"
    CNVD_EQUAL_RETRIEVED_AT = "cnvd_equal_retrieved_at"
    CNVD_INVALID_NDJSON = "cnvd_invalid_ndjson"
    CNVD_INVALID_RECORD = "cnvd_invalid_record"
    CNVD_MISSING_COLUMN = "cnvd_missing_column"
    CNVD_EXTRA_COLUMN = "cnvd_extra_column"
    CNVD_MISTYPED_COLUMN = "cnvd_mistyped_column"
    CNVD_NULL_VALUE = "cnvd_null_value"
    CNVD_INVALID_ID = "cnvd_invalid_id"
    CNVD_REPEATED_ID = "cnvd_repeated_id"
    CNVD_EMPTY_TITLE = "cnvd_empty_title"
    CNVD_EMPTY_DESCRIPTION = "cnvd_empty_description"
    CNVD_INVALID_SEVERITY = "cnvd_invalid_severity"
    CNVD_INVALID_SOURCE = "cnvd_invalid_source"
    CNVD_FILE_TOO_LARGE = "cnvd_file_too_large"
    CNVD_TOO_MANY_ROWS = "cnvd_too_many_rows"
    CNVD_ROW_COUNT_MISMATCH = "cnvd_row_count_mismatch"
    LEGACY_ROOT_UNREADABLE = "legacy_root_unreadable"
    LEGACY_ROOT_CHANGED = "legacy_root_changed"
    LEGACY_ROOT_TOO_DEEP = "legacy_root_too_deep"
    LEGACY_ROOT_TOO_MANY_ENTRIES = "legacy_root_too_many_entries"
    LEGACY_ROOT_READ_BUDGET = "legacy_root_read_budget"
    TARGET_EXISTS = "target_exists"
    TARGET_UNUSABLE = "target_unusable"
    TARGET_OVERLAPS_INPUT = "target_overlaps_input"
    TARGET_PARENT_HOLDS_INPUT = "target_parent_holds_input"
    TARGET_IN_STORE_ROOT = "target_in_store_root"
    STORE_ROOT_UNUSABLE = "store_root_unusable"
    EXISTING_STORE_INVALID = "existing_store_invalid"
    NO_IMPORTABLE_RECORDS = "no_importable_records"
    STORE_WRITE_FAILED = "store_write_failed"


MIGRATION_FAILURE_MESSAGES: dict[MigrationFailureCode, str] = {
    MigrationFailureCode.INPUT_NOT_A_REGULAR_FILE: "An input is not a regular file.",
    MigrationFailureCode.INPUT_UNREADABLE: "An input cannot be read.",
    MigrationFailureCode.INPUT_REPEATED: "Two inputs name the same file.",
    MigrationFailureCode.INPUT_BYTES_REPEATED: "Two inputs hold the same bytes.",
    MigrationFailureCode.INPUT_CHANGED: "An input changed while the import read it.",
    MigrationFailureCode.ARTIFACT_UNDECLARED: (
        "An NVD input has no standard feed name and declares no artifact."
    ),
    MigrationFailureCode.ARTIFACT_CONFLICT: (
        "An NVD input's file name and declared artifact disagree."
    ),
    MigrationFailureCode.FORMAT_MISMATCH: (
        "An NVD input's content declares another format than its artifact."
    ),
    MigrationFailureCode.INCOMPLETE_FEED: (
        "An NVD input is not a whole feed: it does not declare its entry count, holds "
        "another number of entries, or is one page of a larger result."
    ),
    MigrationFailureCode.UNRECOGNISED_FORMAT: "An input is not in a format the importer reads.",
    MigrationFailureCode.DERIVED_FILE_DECLARED_AS_SOURCE: (
        "An input is a legacy derived file, which is never imported as a source."
    ),
    MigrationFailureCode.BAD_COMPRESSION: "An input's compression cannot be read.",
    MigrationFailureCode.INVALID_JSON: "An NVD input is not valid JSON.",
    MigrationFailureCode.DUPLICATE_JSON_KEY: "An NVD input repeats a key within one object.",
    MigrationFailureCode.ENTRY_TOO_DEEP: "An NVD entry nests deeper than the importer reads.",
    MigrationFailureCode.ENTRY_TOO_LARGE: (
        "An NVD entry or top-level value is larger than the importer reads."
    ),
    MigrationFailureCode.GENERATED_AT_INVALID: (
        "An NVD input's generation time is not a valid timestamp."
    ),
    MigrationFailureCode.RETRIEVED_BEFORE_GENERATED: (
        "An input is declared retrieved before its source generated it."
    ),
    MigrationFailureCode.RETRIEVED_IN_FUTURE: "An input is declared retrieved in the future.",
    MigrationFailureCode.COMPRESSED_FILE_TOO_LARGE: "An input file is larger than the cap.",
    MigrationFailureCode.DECOMPRESSED_FILE_TOO_LARGE: (
        "An input decompresses to more than the cap."
    ),
    MigrationFailureCode.TOTAL_TOO_LARGE: "The inputs decompress to more than the total cap.",
    MigrationFailureCode.TOO_MANY_CANDIDATES: "The inputs hold more NVD entries than the cap.",
    MigrationFailureCode.STAGING_TOO_LARGE: "The staging directory grew past its cap.",
    MigrationFailureCode.STAGING_FAILED: "The staging directory could not be written.",
    MigrationFailureCode.KEV_INVALID_ENCODING: ("The KEV input is not UTF-8 CSV." + KEV_REMEDY),
    MigrationFailureCode.KEV_INVALID_HEADER: (
        "The KEV input's header is not the KEV column set." + KEV_REMEDY
    ),
    MigrationFailureCode.KEV_INVALID_ROW: (
        "A KEV row is malformed or lacks a required value." + KEV_REMEDY
    ),
    MigrationFailureCode.KEV_CONFLICTING_ROWS: (
        "The KEV input lists one CVE in rows that disagree." + KEV_REMEDY
    ),
    MigrationFailureCode.KEV_TOO_LARGE: (
        "The KEV input is larger or longer than the cap." + KEV_REMEDY
    ),
    MigrationFailureCode.CNVD_UNCATALOGUED_FILE: (
        "A CNVD input is not a file in the reviewed snapshot catalog."
    ),
    MigrationFailureCode.CNVD_INCOMPLETE_SNAPSHOT: (
        "The CNVD inputs are not exactly one reviewed revision's complete file set."
    ),
    MigrationFailureCode.CNVD_MIXED_SOURCES: "An import accepts only one CNVD source.",
    MigrationFailureCode.CNVD_EQUAL_RETRIEVED_AT: (
        "Raw CNVD inputs must have distinct retrieved_at instants."
    ),
    MigrationFailureCode.CNVD_INVALID_NDJSON: (
        "A raw CNVD input must be a plain .ndjson file with one JSON object per line."
    ),
    MigrationFailureCode.CNVD_INVALID_RECORD: "A raw CNVD record has malformed retained fields.",
    MigrationFailureCode.CNVD_INVALID_PARQUET: (
        "A CNVD input is not readable Parquet with Parquet magic."
    ),
    MigrationFailureCode.CNVD_MISSING_COLUMN: "A CNVD input lacks a required column.",
    MigrationFailureCode.CNVD_EXTRA_COLUMN: "A CNVD input has an extra or repeated column.",
    MigrationFailureCode.CNVD_MISTYPED_COLUMN: (
        "A CNVD input has a column whose type is not string."
    ),
    MigrationFailureCode.CNVD_NULL_VALUE: "A CNVD row holds a null value.",
    MigrationFailureCode.CNVD_INVALID_ID: "A CNVD row has an invalid CNVD ID.",
    MigrationFailureCode.CNVD_REPEATED_ID: "A CNVD ID repeats within or across the inputs.",
    MigrationFailureCode.CNVD_EMPTY_TITLE: "A CNVD row has an empty title.",
    MigrationFailureCode.CNVD_EMPTY_DESCRIPTION: "A CNVD row has an empty description.",
    MigrationFailureCode.CNVD_INVALID_SEVERITY: (
        "A CNVD row has a severity other than 高, 中 or 低."
    ),
    MigrationFailureCode.CNVD_INVALID_SOURCE: "A CNVD row has a source other than cnvd.",
    MigrationFailureCode.CNVD_FILE_TOO_LARGE: (
        "A CNVD input is larger than the per-file byte cap."
    ),
    MigrationFailureCode.CNVD_TOO_MANY_ROWS: (
        "The CNVD inputs hold more rows than the total row cap."
    ),
    MigrationFailureCode.CNVD_ROW_COUNT_MISMATCH: (
        "A CNVD input has another row count than its reviewed catalog entry."
    ),
    MigrationFailureCode.LEGACY_ROOT_UNREADABLE: "Part of the legacy root cannot be read.",
    MigrationFailureCode.LEGACY_ROOT_CHANGED: "The legacy root changed while it was walked.",
    MigrationFailureCode.LEGACY_ROOT_TOO_DEEP: "The legacy root nests deeper than the walk goes.",
    MigrationFailureCode.LEGACY_ROOT_TOO_MANY_ENTRIES: (
        "The legacy root holds more entries than the walk examines."
    ),
    MigrationFailureCode.LEGACY_ROOT_READ_BUDGET: (
        "Recognising the legacy root's files needs more reading than the walk allows."
    ),
    MigrationFailureCode.TARGET_EXISTS: (
        "The target exists and holds another import; it is never overwritten."
    ),
    MigrationFailureCode.TARGET_UNUSABLE: (
        "The target cannot be resolved, or its parent is not a writable directory."
    ),
    MigrationFailureCode.TARGET_OVERLAPS_INPUT: (
        "The target is, holds or lies inside the manifest, an input or the legacy root."
    ),
    MigrationFailureCode.TARGET_PARENT_HOLDS_INPUT: (
        "The target's parent directory holds an input."
    ),
    MigrationFailureCode.TARGET_IN_STORE_ROOT: (
        "The target lies in the store root but is not a store directly under it with a valid "
        "store name."
    ),
    MigrationFailureCode.STORE_ROOT_UNUSABLE: (
        "The target lies in the store root, which is missing, not a directory, a symbolic "
        "link or unreadable."
    ),
    MigrationFailureCode.EXISTING_STORE_INVALID: (
        "The target holds this import, but the store fails verification; it is never repaired."
    ),
    MigrationFailureCode.NO_IMPORTABLE_RECORDS: "The inputs yield no importable record.",
    MigrationFailureCode.STORE_WRITE_FAILED: "The store could not be written.",
}


class MigrationFailed(Exception):
    """A run fails as a whole for ``code``. A failure while the inputs are resolved names
    the input by ``manifest_index``, its index in the manifest; a later one by
    ``input_position``, its place in the sorted input list. Raised by the importer's
    readers and caught by the run."""

    def __init__(
        self,
        code: MigrationFailureCode,
        input_position: int | None = None,
        manifest_index: int | None = None,
        input_line: int | None = None,
    ) -> None:
        super().__init__(code.value)
        self.code = code
        self.input_position = input_position
        self.manifest_index = manifest_index
        self.input_line = input_line


class CveOutcome(StrEnum):
    """What became of each CVE the NVD inputs name (ADR 0008 §5)."""

    IMPORTED = "imported"
    WITHDRAWN_BY_SOURCE = "withdrawn_by_source"
    CONFLICTING_DUPLICATE = "conflicting_duplicate"
    MALFORMED_WINNING_CANDIDATE = "malformed_winning_candidate"
    UNORDERABLE_CANDIDATE = "unorderable_candidate"


class CandidateOutcome(StrEnum):
    """What became of each NVD entry."""

    CHOSEN = "chosen"
    SUPERSEDED = "superseded"
    IDENTICAL_DUPLICATE = "identical_duplicate"
    DROPPED_FOR_FORMAT = "dropped_for_format"
    MALFORMED = "malformed"
    IN_EXCLUDED_CVE = "in_excluded_cve"


class KevOutcome(StrEnum):
    """What became of each KEV row (ADR 0008 §6)."""

    MERGED = "merged"
    IDENTICAL_DUPLICATE = "identical_duplicate"
    WITHOUT_NVD_RECORD = "kev_without_nvd_record"
    FOR_REJECTED_NVD_RECORD = "kev_for_rejected_nvd_record"
    FOR_EXCLUDED_NVD_RECORD = "kev_for_excluded_nvd_record"


class CnvdOutcome(StrEnum):
    """What became of each CNVD row after NVD resolution (ADR 0015 §3)."""

    MERGED = "merged"
    WITHOUT_NVD_RECORD = "cnvd_without_nvd_record"
    FOR_REJECTED_NVD_RECORD = "cnvd_for_rejected_nvd_record"
    FOR_EXCLUDED_NVD_RECORD = "cnvd_for_excluded_nvd_record"
    WITHOUT_CVE_ID = "cnvd_without_cve_id"
    UNRECOGNISED_CVE_ID = "cnvd_unrecognised_cve_id"


class LegacyFileKind(StrEnum):
    """What a file found under the legacy root is, by structure or magic bytes."""

    ENHANCED_DOCUMENTS = "enhanced_documents"
    RAG_EXPORT = "rag_export"
    CPE_PARSING_RESULTS = "cpe_parsing_results"
    GRAPH_EXPORT = "graph_export"
    MAPPING = "mapping"
    ANALYTICS = "analytics"
    PICKLE = "pickle"
    NUMPY_ARRAY = "numpy_array"
    MODEL_ARCHIVE = "model_archive"


class MigrationFailure(ContractModel):
    model_config = ConfigDict(json_schema_extra=describe_fixed_messages(MIGRATION_FAILURE_MESSAGES))

    code: MigrationFailureCode
    message: str = Field(min_length=1, max_length=200)
    manifest_index: int | None = Field(
        ge=0,
        description="The failing input's index in the manifest, when it failed while the "
        "inputs were resolved.",
    )
    input_position: int | None = Field(
        ge=0,
        description="The failing input's position in the sorted input list, when it failed later.",
    )

    input_line: int | None = Field(
        default=None, ge=1, description="One-based line number of a malformed NDJSON record."
    )

    @model_validator(mode="after")
    def check_message(self) -> Self:
        if self.message != MIGRATION_FAILURE_MESSAGES[self.code]:
            raise ValueError("message must be the fixed sentence of the failure's code")
        if self.manifest_index is not None and self.input_position is not None:
            raise ValueError("a failure names its input one way")
        return self


def build_migration_failure(
    code: MigrationFailureCode,
    input_position: int | None = None,
    manifest_index: int | None = None,
    input_line: int | None = None,
) -> MigrationFailure:
    return MigrationFailure(
        code=code,
        message=MIGRATION_FAILURE_MESSAGES[code],
        manifest_index=manifest_index,
        input_position=input_position,
        input_line=input_line,
    )


class EntryLocator(ContractModel):
    """Where a skipped NVD entry sits: never its content."""

    input_position: int = Field(ge=0)
    entry_index: int = Field(ge=0)
    code: NormalizationFailureCode


class MigrationReport(ContractModel):
    """A run's report. A failed run has its ``failure``; a run that wrote or found a store
    names it and states how to roll it back."""

    schema_version: SchemaVersion = SCHEMA_VERSION
    outcome: MigrationOutcome
    failure: MigrationFailure | None
    import_identity_sha256: str | None = Field(pattern=SHA256_PATTERN)
    store_manifest_sha256: str | None = Field(pattern=SHA256_PATTERN)
    corpus_content_sha256: str | None = Field(
        pattern=SHA256_PATTERN,
        description="The dataset the named store holds, as a server serving it names it; "
        "set exactly when a store is named.",
    )
    cve_outcomes: dict[CveOutcome, int]
    candidate_outcomes: dict[CandidateOutcome, int]
    normalization_failures: dict[NormalizationFailureCode, int]
    kev_outcomes: dict[KevOutcome, int]
    cnvd_outcomes: dict[CnvdOutcome, int]
    skipped_entries: tuple[EntryLocator, ...] = Field(
        max_length=MAX_REPORTED_LOCATORS,
        description=f"The first {MAX_REPORTED_LOCATORS} skipped malformed entries.",
    )
    kev_advice: str | None = Field(
        description="What to add when a KEV row names a CVE no NVD input holds; set exactly "
        "when kev_without_nvd_record is above zero."
    )
    legacy_root_findings: dict[LegacyFileKind, int] | None = Field(
        description="Files found by kind under --legacy-root; null without one."
    )
    legacy_formats_commit: LegacyFormatsCommit | None = Field(
        description="The CVE-KGRAG commit whose writers define the derived formats counted "
        "in legacy_root_findings; set exactly with them."
    )
    rollback_kind: RollbackKind | None = Field(
        description="How the import is undone; set exactly when a store is named."
    )
    rollback_scope: RollbackScope | None = Field(
        description="When that undoing applies; set exactly when a store is named."
    )
    rollback_instruction: str | None = Field(
        description="How to undo the import; set exactly when a store is named."
    )

    @model_validator(mode="after")
    def check_outcome_fields(self) -> Self:
        """A failed run, and only one, carries its failure; a run that wrote or found a
        store, and only one, names it by both hashes and states its rollback; the KEV
        advice and the legacy formats' commit come exactly with what they explain."""
        has_failed = self.outcome is MigrationOutcome.FAILED
        if has_failed != (self.failure is not None):
            raise ValueError("a failed run, and only one, carries its failure")
        names_store = self.outcome in STORE_OUTCOMES
        if names_store != (self.store_manifest_sha256 is not None):
            raise ValueError("a run that wrote or found a store, and only one, names it")
        if names_store and self.import_identity_sha256 is None:
            raise ValueError("a run names its store by its import identity too")
        if names_store != (self.corpus_content_sha256 is not None):
            raise ValueError("a run that names a store, and only one, names its dataset")
        rollback = (self.rollback_kind, self.rollback_scope, self.rollback_instruction)
        expected_rollback = (ROLLBACK_KIND, ROLLBACK_SCOPE, ROLLBACK_INSTRUCTION)
        if rollback != (expected_rollback if names_store else (None, None, None)):
            raise ValueError("a run that names its store states the fixed rollback")
        has_kev_without_nvd = self.kev_outcomes.get(KevOutcome.WITHOUT_NVD_RECORD, 0) > 0
        if self.kev_advice != (KEV_WITHOUT_NVD_RECORD_ADVICE if has_kev_without_nvd else None):
            raise ValueError("the KEV advice is the fixed sentence, given exactly when needed")
        has_findings = self.legacy_root_findings is not None
        if self.legacy_formats_commit != (LEGACY_FORMATS_COMMIT if has_findings else None):
            raise ValueError("legacy root findings cite the legacy formats' commit")
        return self
