"""The corpus store the legacy-data importer writes: its manifest and the inputs it names
(ADR 0008).

A store is a directory of canonical JSON files pinned by SHA-256 in ``manifest.json``. It
holds imported, not synthetic, data, and is never modified once written: rolling a
migration back before activation is deleting the directory.
"""

import re
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, model_validator

from cve_kgrag.domain.contract_model import ContractModel
from cve_kgrag.domain.evidence import SHA256_PATTERN
from cve_kgrag.domain.hashing import canonical_sha256
from cve_kgrag.domain.search import SCHEMA_VERSION, SchemaVersion
from cve_kgrag.domain.timestamps import Timestamp

STORE_FORMAT_VERSION: Literal[1] = 1
# NVD's first year feed; it also holds the CVE IDs of 1999 to 2001.
FIRST_FEED_YEAR = 2002
STORE_FILE_NAME_PATTERN = r"^[a-z_]+\.jsonl$"
SOURCE_VERSION_PATTERN = r"^sha256:[0-9a-f]{64}$"
# The version of the corpus content identity, named in a store's ``cve_search`` version.
CORPUS_CONTENT_IDENTITY_VERSION = 1
ROLLBACK_INSTRUCTION = (
    "Before activation, remove the newly created target directory. After activation, use "
    "the WP10 store rollback operation."
)
RollbackKind = Literal["delete_unactivated_target"]
RollbackScope = Literal["before_activation_only"]
ROLLBACK_KIND: RollbackKind = "delete_unactivated_target"
ROLLBACK_SCOPE: RollbackScope = "before_activation_only"


class StoreSource(StrEnum):
    """The sources an import reads, by their source-registry names."""

    NVD = "nvd"
    CISA_KEV = "cisa-kev"


class NvdFeedFormat(StrEnum):
    V1_1 = "1.1"
    V2_0 = "2.0"


class NvdFeedSeries(StrEnum):
    YEAR = "year"
    RECENT = "recent"
    MODIFIED = "modified"


class InputContainer(StrEnum):
    PLAIN = "plain"
    GZIP = "gzip"
    ZIP = "zip"


class NvdArtifact(ContractModel):
    """One published NVD feed: its format, its series and, for the year series, its year."""

    format: NvdFeedFormat
    series: NvdFeedSeries
    year: int | None = Field(default=None, ge=FIRST_FEED_YEAR, le=9999)

    @model_validator(mode="after")
    def check_year_matches_series(self) -> Self:
        if (self.series is NvdFeedSeries.YEAR) != (self.year is not None):
            raise ValueError("a year feed names its year, and only a year feed does")
        return self

    def name_feed(self) -> str:
        """The feed's name in NVD's file names and URLs: its year, or its series."""
        if self.year is not None:
            return str(self.year)
        return self.series.value


# A standard NVD feed file name, as NVD publishes it or as unpacked.
NVD_FEED_FILE_PATTERN = re.compile(
    r"^nvdcve-(?P<format>1\.1|2\.0)-(?P<name>[0-9]{4}|recent|modified)\.json(?:\.gz|\.zip)?$"
)


def read_standard_artifact(file_name: str) -> NvdArtifact | None:
    """The artifact a standard NVD feed file name gives, or ``None`` for any other name,
    a year NVD never published a feed for included."""
    name_match = NVD_FEED_FILE_PATTERN.fullmatch(file_name)
    if name_match is None:
        return None
    feed_name = name_match["name"]
    if feed_name.isdigit():
        if int(feed_name) < FIRST_FEED_YEAR:
            return None
        return NvdArtifact.model_validate(
            {"format": name_match["format"], "series": "year", "year": int(feed_name)}
        )
    return NvdArtifact.model_validate({"format": name_match["format"], "series": feed_name})


class StoreInput(ContractModel):
    """One input as the store records it, in the sorted order of the import identity."""

    source: StoreSource
    artifact: NvdArtifact | None = Field(description="Every NVD input's; null for KEV.")
    container: InputContainer
    source_uri: str = Field(min_length=1, max_length=2048)
    source_version: str = Field(pattern=SOURCE_VERSION_PATTERN)
    input_file_sha256: str = Field(
        pattern=SHA256_PATTERN, description="SHA-256 of the file's bytes as supplied."
    )
    payload_sha256: str | None = Field(
        pattern=SHA256_PATTERN,
        description="SHA-256 of an NVD feed's decompressed JSON payload; null for KEV.",
    )
    retrieved_at: Timestamp = Field(description="When the operator obtained the file.")
    source_generated_at: Timestamp | None = Field(
        description="When the source generated the feed, as it states; null for KEV and "
        "for a feed that states no generation time."
    )
    input_bytes: int = Field(ge=0)

    @model_validator(mode="after")
    def check_source_fields(self) -> Self:
        """An NVD input names its artifact and payload, and its version is the payload's
        hash; a KEV input is a plain file with no generation time, and its version is the
        file's hash (ADR 0008 §3)."""
        if self.source is StoreSource.NVD:
            if self.artifact is None or self.payload_sha256 is None:
                raise ValueError("an NVD input names its artifact and payload")
            version_sha256 = self.payload_sha256
        else:
            has_nvd_fields = self.artifact is not None or self.payload_sha256 is not None
            if has_nvd_fields or self.source_generated_at is not None:
                raise ValueError("a KEV input names no artifact, payload or generation time")
            if self.container is not InputContainer.PLAIN:
                raise ValueError("a KEV input is a plain file")
            version_sha256 = self.input_file_sha256
        if self.source_version != f"sha256:{version_sha256}":
            raise ValueError("source_version is the hash the input's source is versioned by")
        return self


class StoreFile(ContractModel):
    path: str = Field(pattern=STORE_FILE_NAME_PATTERN)
    sha256: str = Field(pattern=SHA256_PATTERN)
    size_bytes: int = Field(ge=0)


class CorpusStoreManifest(ContractModel):
    """What a store holds and where it came from; every file it lists is pinned by
    SHA-256, and a reader refuses any other file."""

    schema_version: SchemaVersion = SCHEMA_VERSION
    store_format_version: Literal[1] = STORE_FORMAT_VERSION
    synthetic: Literal[False] = False
    created_at: Timestamp
    importer_version: str = Field(
        min_length=1, max_length=64, description="The cve-kgrag distribution version."
    )
    import_identity_sha256: str = Field(
        pattern=SHA256_PATTERN,
        description="Names the import: equal identities build equal records and anchors.",
    )
    inputs_manifest_sha256: str = Field(
        pattern=SHA256_PATTERN, description="SHA-256 of the input manifest's bytes; audit only."
    )
    inputs: tuple[StoreInput, ...] = Field(min_length=1)
    files: tuple[StoreFile, ...] = Field(min_length=1)
    record_count: int = Field(ge=1)
    anchor_count: int = Field(ge=1)
    rollback_kind: RollbackKind = ROLLBACK_KIND
    rollback_scope: RollbackScope = ROLLBACK_SCOPE
    rollback_instruction: str = ROLLBACK_INSTRUCTION

    @model_validator(mode="after")
    def check_rollback_instruction(self) -> Self:
        if self.rollback_instruction != ROLLBACK_INSTRUCTION:
            raise ValueError("the rollback instruction is the server's fixed sentence")
        return self

    @model_validator(mode="after")
    def check_files_pinned_once(self) -> Self:
        pinned_paths: set[str] = set()
        for store_file in self.files:
            if store_file.path in pinned_paths:
                raise ValueError("each store file is pinned once")
            pinned_paths.add(store_file.path)
        return self


def derive_corpus_content_sha256(records_file: StoreFile, anchors_file: StoreFile) -> str:
    """The SHA-256 naming the dataset a store's records and anchors hold, from their pins
    alone: no manifest field other than the two files' hashes and sizes enters it, so
    stores with byte-for-byte equal records and anchors serve one dataset (ADR 0009 §2).
    Taken only once both files have been checked against their pins."""
    return canonical_sha256(
        {
            "identity_version": CORPUS_CONTENT_IDENTITY_VERSION,
            "files": [
                {
                    "role": "records",
                    "sha256": records_file.sha256,
                    "size_bytes": records_file.size_bytes,
                },
                {
                    "role": "anchors",
                    "sha256": anchors_file.sha256,
                    "size_bytes": anchors_file.size_bytes,
                },
            ],
        }
    )


def name_corpus_store_version(corpus_content_sha256: str) -> str:
    """A store's ``cve_search`` capability version: its content identity's version and
    digest."""
    return f"corpus-store-v{CORPUS_CONTENT_IDENTITY_VERSION}@sha256:{corpus_content_sha256}"
