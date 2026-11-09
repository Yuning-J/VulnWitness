"""The counts an import gathers as it runs, and the report built from them (ADR 0008 §7,
§10)."""

from vulnwitness.adapters.store.corpus_store import VerifiedStore
from vulnwitness.domain.corpus_store_manifest import (
    ROLLBACK_INSTRUCTION,
    ROLLBACK_KIND,
    ROLLBACK_SCOPE,
)
from vulnwitness.domain.migration_report import (
    KEV_WITHOUT_NVD_RECORD_ADVICE,
    LEGACY_FORMATS_COMMIT,
    MAX_REPORTED_LOCATORS,
    CandidateOutcome,
    CnvdOutcome,
    CveOutcome,
    EntryLocator,
    KevOutcome,
    LegacyFileKind,
    MigrationFailed,
    MigrationOutcome,
    MigrationReport,
    build_migration_failure,
)
from vulnwitness.domain.normalization import NormalizationFailureCode


class ReportTally:
    """The counts a run gathers for its report; every outcome and code is listed."""

    def __init__(self) -> None:
        self.cve_outcomes: dict[CveOutcome, int] = dict.fromkeys(CveOutcome, 0)
        self.candidate_outcomes: dict[CandidateOutcome, int] = dict.fromkeys(CandidateOutcome, 0)
        self.normalization_failures: dict[NormalizationFailureCode, int] = dict.fromkeys(
            NormalizationFailureCode, 0
        )
        self.cnvd_outcomes: dict[CnvdOutcome, int] = dict.fromkeys(CnvdOutcome, 0)
        self.kev_outcomes: dict[KevOutcome, int] = dict.fromkeys(KevOutcome, 0)
        self.skipped_entries: list[EntryLocator] = []
        self.legacy_root_findings: dict[LegacyFileKind, int] | None = None
        self.import_identity_sha256: str | None = None

    def add_malformed_entry(
        self, input_position: int, entry_index: int, code: NormalizationFailureCode
    ) -> None:
        self.normalization_failures[code] += 1
        if len(self.skipped_entries) < MAX_REPORTED_LOCATORS:
            self.skipped_entries.append(
                EntryLocator(input_position=input_position, entry_index=entry_index, code=code)
            )

    def build_report(
        self,
        outcome: MigrationOutcome,
        failure: MigrationFailed | None = None,
        named_store: VerifiedStore | None = None,
    ) -> MigrationReport:
        """The report of a run ending in ``outcome``; ``named_store`` is the verification
        of the store it wrote or found, which names that store and its dataset."""
        names_store = named_store is not None
        has_kev_without_nvd = self.kev_outcomes[KevOutcome.WITHOUT_NVD_RECORD] > 0
        return MigrationReport(
            outcome=outcome,
            failure=None
            if failure is None
            else build_migration_failure(
                failure.code, failure.input_position, failure.manifest_index, failure.input_line
            ),
            import_identity_sha256=self.import_identity_sha256,
            store_manifest_sha256=None
            if named_store is None
            else named_store.store_manifest_sha256,
            corpus_content_sha256=None
            if named_store is None
            else named_store.corpus_content_sha256,
            cve_outcomes=self.cve_outcomes,
            candidate_outcomes=self.candidate_outcomes,
            normalization_failures=self.normalization_failures,
            kev_outcomes=self.kev_outcomes,
            cnvd_outcomes=self.cnvd_outcomes,
            kev_advice=KEV_WITHOUT_NVD_RECORD_ADVICE if has_kev_without_nvd else None,
            skipped_entries=tuple(self.skipped_entries),
            legacy_root_findings=self.legacy_root_findings,
            legacy_formats_commit=None
            if self.legacy_root_findings is None
            else LEGACY_FORMATS_COMMIT,
            rollback_kind=ROLLBACK_KIND if names_store else None,
            rollback_scope=ROLLBACK_SCOPE if names_store else None,
            rollback_instruction=ROLLBACK_INSTRUCTION if names_store else None,
        )
