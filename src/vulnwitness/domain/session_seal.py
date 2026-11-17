"""The closed on-disk contract for a session's HMAC seal."""

from typing import Annotated, Literal

from pydantic import Field

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.evidence import SHA256_PATTERN

SealDigest = Annotated[str, Field(pattern=SHA256_PATTERN)]


class SessionSeal(ContractModel):
    format_version: Literal[1]
    algorithm: Literal["hmac-sha256"]
    key_id: str = Field(pattern=r"^[0-9a-f]{16}$")
    files: dict[str, SealDigest]
    mac: SealDigest
