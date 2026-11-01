"""The input manifest an operator writes for an import: every input file, where it came
from and when it was obtained (ADR 0008 §2)."""

import re
from datetime import UTC, datetime
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.corpus_store_manifest import NvdArtifact, StoreSource
from vulnwitness.domain.timestamps import RFC3339_TIMESTAMP_PATTERN, Timestamp

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_MANIFEST_INPUTS = 128
MAX_MANIFEST_PATH_CHARS = 1024


class InputDeclaration(ContractModel):
    """One input: its source, its path relative to the manifest, when the operator obtained
    it and, for an NVD file whose name is not a standard feed name, which feed it is."""

    source: StoreSource
    path: str = Field(min_length=1, max_length=MAX_MANIFEST_PATH_CHARS)
    retrieved_at: Timestamp
    artifact: NvdArtifact | None = None

    @field_validator("path")
    @classmethod
    def refuse_nul(cls, value: str) -> str:
        """A NUL ends a path at the operating system, so no file has one in its name."""
        if "\x00" in value:
            raise ValueError("a path holds no NUL character")
        return value

    @field_validator("retrieved_at", mode="before")
    @classmethod
    def require_rfc3339_text(cls, value: object) -> object:
        """Only RFC 3339 text with an offset and at most six fractional digits: a parsed
        datetime, a naive time, a space separator or more digits would each lose or guess
        part of the time the operator meant."""
        if not isinstance(value, str) or re.fullmatch(RFC3339_TIMESTAMP_PATTERN, value) is None:
            raise ValueError("not an RFC 3339 timestamp with an offset")
        return value

    @field_validator("retrieved_at")
    @classmethod
    def require_utc_range(cls, value: datetime) -> datetime:
        """An instant UTC can express: year 1 with an eastern offset, or year 9999 with a
        western one, lies outside it."""
        try:
            value.astimezone(UTC)
        except OverflowError:
            raise ValueError("the time lies outside the years UTC can express") from None
        return value

    @model_validator(mode="after")
    def check_artifact_source(self) -> Self:
        if self.artifact is not None and self.source is not StoreSource.NVD:
            raise ValueError("only an NVD input declares an artifact")
        return self


class InputsManifest(ContractModel):
    format_version: Literal[1]
    inputs: tuple[InputDeclaration, ...] = Field(
        description=f"One to {MAX_MANIFEST_INPUTS} inputs.",
        json_schema_extra={"minItems": 1, "maxItems": MAX_MANIFEST_INPUTS},
    )

    @model_validator(mode="after")
    def check_input_count(self) -> Self:
        # Checked here rather than as tuple bounds: pydantic counts a tuple's valid items
        # only, so one bad input would also be reported as an empty list.
        if not 1 <= len(self.inputs) <= MAX_MANIFEST_INPUTS:
            raise ValueError(f"inputs holds one to {MAX_MANIFEST_INPUTS} entries")
        return self

    @model_validator(mode="after")
    def check_one_kev_input(self) -> Self:
        kev_inputs = 0
        for declaration in self.inputs:
            if declaration.source is StoreSource.CISA_KEV:
                kev_inputs += 1
        if kev_inputs > 1:
            raise ValueError("at most one cisa-kev input")
        return self
