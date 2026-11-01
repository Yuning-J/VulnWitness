"""Stage an NVD input's entries as its feed is read (ADR 0008 §5, §7).

Every entry is normalized once with a draft snapshot to learn its state and semantic
hash; an entry whose CVE ID can be read is staged as a candidate, and one that cannot be
normalized is counted with its locator.
"""

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from vulnwitness.adapters.migration.candidate_staging import (
    CandidateStaging,
    CandidateState,
    StagedCandidate,
    describe_semantic_state,
)
from vulnwitness.adapters.migration.input_resolution import ResolvedInput
from vulnwitness.adapters.migration.report_tally import ReportTally
from vulnwitness.adapters.nvd.normalizer import (
    KevSource,
    NormalizedCve,
    NvdNormalizationError,
    NvdNormalizer,
    RejectedCveError,
    SourceSnapshot,
)
from vulnwitness.domain.corpus_store_manifest import NvdFeedFormat
from vulnwitness.domain.cve import CVE_ID_PATTERN
from vulnwitness.domain.hashing import canonical_json_bytes, canonical_sha256, sha256_hex
from vulnwitness.domain.migration_report import MigrationFailed, MigrationFailureCode
from vulnwitness.domain.normalization import NormalizationFailureCode

# An NVD time as feeds write it: minutes or seconds, any fraction, an offset or none.
NVD_TIME_PATTERN = re.compile(
    r"^(?P<date_time>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(?::[0-9]{2})?)"
    r"(?:\.(?P<fraction>[0-9]+))?(?P<offset>Z|[+-][0-9]{2}:[0-9]{2})?$"
)
MICROSECOND_DIGITS = 6
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
ONE_MICROSECOND = timedelta(microseconds=1)


def parse_nvd_time(text: object) -> datetime | None:
    """An NVD time as an aware UTC datetime, truncated to microseconds; ``None`` for
    anything else, a time UTC cannot express included. A time without an offset is UTC,
    as NVD writes them."""
    if not isinstance(text, str):
        return None
    time_match = NVD_TIME_PATTERN.fullmatch(text)
    if time_match is None:
        return None
    fraction = (time_match["fraction"] or "")[:MICROSECOND_DIGITS]
    offset = time_match["offset"] or "+00:00"
    normalized_text = time_match["date_time"]
    if fraction:
        normalized_text += f".{fraction.ljust(MICROSECOND_DIGITS, '0')}"
    normalized_text += "+00:00" if offset == "Z" else offset
    try:
        return datetime.fromisoformat(normalized_text).astimezone(UTC)
    except (ValueError, OverflowError):
        return None


def to_microseconds(moment: datetime) -> int:
    """Exact microseconds since the Unix epoch, negative before it."""
    return (moment - UNIX_EPOCH) // ONE_MICROSECOND


def is_cve_id(cve_id: object) -> bool:
    return isinstance(cve_id, str) and re.fullmatch(CVE_ID_PATTERN, cve_id) is not None


def read_entry_identity(
    feed_format: NvdFeedFormat, entry: dict[str, Any]
) -> tuple[dict[str, Any], object, object]:
    """The object the normalizer reads, the CVE ID and the modification time as the
    entry writes them, each possibly absent or of any type."""
    if feed_format is NvdFeedFormat.V2_0:
        cve_object = entry.get("cve")
        if not isinstance(cve_object, dict):
            return entry, None, None
        return cve_object, cve_object.get("id"), cve_object.get("lastModified")
    cve_section = entry.get("cve")
    metadata = cve_section.get("CVE_data_meta") if isinstance(cve_section, dict) else None
    cve_id = metadata.get("ID") if isinstance(metadata, dict) else None
    return entry, cve_id, entry.get("lastModifiedDate")


def normalize(
    normalizer: NvdNormalizer,
    feed_format: NvdFeedFormat,
    cve_object: dict[str, Any],
    snapshot: SourceSnapshot,
    kev: KevSource | None = None,
) -> NormalizedCve:
    if feed_format is NvdFeedFormat.V2_0:
        return normalizer.normalize_v2(cve_object, snapshot, kev)
    return normalizer.normalize_v1(cve_object, snapshot, kev)


@dataclass
class NvdEntryStager:
    """Stages one NVD input's entries as the feed is read."""

    resolved_input: ResolvedInput
    staging: CandidateStaging
    normalizer: NvdNormalizer
    tally: ReportTally

    def stage_entry(
        self, feed_format: NvdFeedFormat, entry_index: int, entry: dict[str, Any]
    ) -> None:
        artifact = self.resolved_input.artifact
        if artifact is None or feed_format is not artifact.format:
            raise MigrationFailed(MigrationFailureCode.FORMAT_MISMATCH)
        position = self.resolved_input.position
        cve_object, cve_id, modified_text = read_entry_identity(feed_format, entry)
        # The source version is the payload's hash, known once the feed is read whole;
        # staging needs only the semantic and content hashes, which do not depend on it.
        draft_snapshot = SourceSnapshot(
            source_uri=self.resolved_input.source_uri,
            retrieved_at=self.resolved_input.retrieved_at,
        )
        state = CandidateState.ACTIVE
        semantic_sha256: str | None = None
        content_sha256: str | None = None
        raw_entry: str | None = None
        try:
            normalized = normalize(self.normalizer, feed_format, cve_object, draft_snapshot)
        except RejectedCveError:
            # The normalizer stops at the rejection before it checks the ID's form, which
            # a withdrawn entry still needs to be staged under.
            if not is_cve_id(cve_id):
                self.tally.add_malformed_entry(
                    position, entry_index, NormalizationFailureCode.CONTRACT_VIOLATION
                )
                return
            state = CandidateState.REJECTED
            semantic_sha256 = sha256_hex(describe_semantic_state(str(cve_id)).encode())
        except NvdNormalizationError as error:
            self.tally.add_malformed_entry(position, entry_index, error.code)
            if not is_cve_id(cve_id):
                # Counted above; with no CVE ID there is no CVE to stage it under.
                return
            state = CandidateState.MALFORMED
        else:
            semantic_sha256 = canonical_sha256(
                normalized.record.model_dump(mode="json", exclude={"evidence_ids"})
            )
            content_sha256 = normalized.evidence[0].content_sha256
            raw_entry = canonical_json_bytes(cve_object).decode()
        modified_at = parse_nvd_time(modified_text)
        self.staging.add_candidate(
            StagedCandidate(
                cve_id=str(cve_id),
                last_modified_us=None if modified_at is None else to_microseconds(modified_at),
                feed_format=feed_format,
                state=state,
                semantic_sha256=semantic_sha256,
                input_position=position,
                entry_index=entry_index,
                retrieved_at_us=to_microseconds(self.resolved_input.retrieved_at),
                source_uri=self.resolved_input.source_uri,
                content_sha256=content_sha256,
                raw_entry=raw_entry,
            )
        )
