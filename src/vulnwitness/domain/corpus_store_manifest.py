"""The corpus store the legacy-data importer writes: its manifest and the inputs it names
(ADR 0008).

A store is a directory of canonical JSON files pinned by SHA-256 in ``manifest.json``. It
holds imported, not synthetic, data, and is never modified once written: rolling a
migration back before activation is deleting the directory.
"""

import re
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.evidence import SHA256_PATTERN
from vulnwitness.domain.hashing import canonical_sha256
from vulnwitness.domain.search import HIDDEN_REQUEST_CHARACTERS
from vulnwitness.domain.timestamps import Timestamp

STORE_FORMAT_VERSION: Literal[3] = 3
# Format 3 persists raw CNVD products, calendar dates and handling advice. This digest guards
# the published schemas of the manifest, CVE record, evidence anchor and pending entry;
# changes require judging the persisted shape and reader rules against ADR 0008 §9.
STORE_FORMAT_SCHEMA_SHA256 = "60e4deb10d7eaa0301f04b1feda8cec8d71e5dcc2d42374081218ae77cc17ab9"
# NVD's first year feed; it also holds the CVE IDs of 1999 to 2001.
FIRST_FEED_YEAR = 2002
STORE_FILE_NAME_PATTERN = r"^[a-z_]+\.jsonl$"
SOURCE_VERSION_PATTERN = r"^sha256:[0-9a-f]{64}$"
# The version of the corpus content identity, named in a store's ``cve_search`` version.
CORPUS_CONTENT_IDENTITY_VERSION = 1
ROLLBACK_INSTRUCTION = (
    "Before activation, remove the newly created target directory. After activation, use "
    "vulnwitness store rollback."
)
MAX_ROLLBACK_INSTRUCTION_CHARS = 512
# A contract version's shape, as the store records the one it was created under.
STORE_SCHEMA_VERSION_PATTERN = r"^[0-9]+\.[0-9]+\.[0-9]+(-dev\.[0-9]+)?$"
StoreSchemaVersion = Annotated[str, Field(pattern=STORE_SCHEMA_VERSION_PATTERN, max_length=32)]
RollbackKind = Literal["delete_unactivated_target"]
RollbackScope = Literal["before_activation_only"]
ROLLBACK_KIND: RollbackKind = "delete_unactivated_target"
ROLLBACK_SCOPE: RollbackScope = "before_activation_only"


class StoreSource(StrEnum):
    """The sources an import reads, by their source-registry names."""

    NVD = "nvd"
    CISA_KEV = "cisa-kev"
    CIRCL_CNVD = "circl-cnvd"
    VULNERABILITY_LOOKUP_CNVD = "vulnerability-lookup-cnvd"


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
    artifact: NvdArtifact | None = Field(description="Every NVD input's; null for KEV and CNVD.")
    container: InputContainer
    source_uri: str = Field(min_length=1, max_length=2048)
    source_version: str = Field(pattern=SOURCE_VERSION_PATTERN)
    input_file_sha256: str = Field(
        pattern=SHA256_PATTERN, description="SHA-256 of the file's bytes as supplied."
    )
    payload_sha256: str | None = Field(
        pattern=SHA256_PATTERN,
        description="SHA-256 of an NVD feed's decompressed JSON payload; null for KEV and CNVD.",
    )
    retrieved_at: Timestamp = Field(description="When the operator obtained the file.")
    source_generated_at: Timestamp | None = Field(
        description="When the source generated the feed, as it states; null for KEV, CNVD and "
        "for a feed that states no generation time."
    )
    input_bytes: int = Field(ge=0)

    @model_validator(mode="after")
    def check_source_fields(self) -> Self:
        """An NVD input names its artifact and payload, and its version is the payload's
        hash; a KEV or CNVD input is a plain file with no generation time, and its version
        is the file's hash (ADR 0008 §3)."""
        if self.source is StoreSource.NVD:
            if self.artifact is None or self.payload_sha256 is None:
                raise ValueError("an NVD input names its artifact and payload")
            version_sha256 = self.payload_sha256
        else:
            has_nvd_fields = self.artifact is not None or self.payload_sha256 is not None
            if has_nvd_fields or self.source_generated_at is not None:
                raise ValueError(
                    "a KEV or CNVD input names no artifact, payload or generation time"
                )
            if self.container is not InputContainer.PLAIN:
                raise ValueError("a KEV or CNVD input is a plain file")
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

    schema_version: StoreSchemaVersion = Field(
        description="The contract version the store was created under; provenance only, "
        "never compared with the version a reader serves."
    )
    store_format_version: Literal[1, 2, 3] = Field(
        default=STORE_FORMAT_VERSION,
        description="What decides whether a reader can read the store; a reader refuses "
        "integers other than 1, 2 and 3.",
    )
    synthetic: Literal[False] = False
    created_at: Timestamp
    importer_version: str = Field(
        min_length=1, max_length=64, description="The vulnwitness distribution version."
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
    rollback_instruction: str = Field(
        min_length=1,
        max_length=MAX_ROLLBACK_INSTRUCTION_CHARS,
        pattern=rf"^[^{HIDDEN_REQUEST_CHARACTERS}]+$",
        description="The instruction the importer that wrote the store gave; a record of "
        "the store's creation, never current guidance.",
    )

    @model_validator(mode="after")
    def check_files_pinned_once(self) -> Self:
        pinned_paths: set[str] = set()
        for store_file in self.files:
            if store_file.path in pinned_paths:
                raise ValueError("each store file is pinned once")
            pinned_paths.add(store_file.path)
        return self


def derive_corpus_content_sha256(
    records_file: StoreFile, anchors_file: StoreFile, pending_file: StoreFile | None = None
) -> str:
    """Name the verified dataset from its logical file roles, hashes and sizes alone.

    Format 1 has records and anchors; format 2 also has pending CNVD entries. Manifest
    provenance and physical file names never enter the content identity (ADR 0009 §2).
    """
    content_files: list[dict[str, str | int]] = []
    role_files = [("records", records_file), ("anchors", anchors_file)]
    if pending_file is not None:
        role_files.append(("pending_cnvd", pending_file))
    for role, store_file in role_files:
        content_files.append(
            {"role": role, "sha256": store_file.sha256, "size_bytes": store_file.size_bytes}
        )
    return canonical_sha256(
        {"identity_version": CORPUS_CONTENT_IDENTITY_VERSION, "files": content_files}
    )


def name_corpus_store_version(corpus_content_sha256: str) -> str:
    """A store's ``cve_search`` capability version: its content identity's version and
    digest."""
    return f"corpus-store-v{CORPUS_CONTENT_IDENTITY_VERSION}@sha256:{corpus_content_sha256}"
