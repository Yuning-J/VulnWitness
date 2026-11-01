"""Bounded readiness waits carry no investigation or recording context."""

from typing import Annotated, Literal

from pydantic import ConfigDict, Field, RootModel

from vulnwitness.domain.contract_model import ContractModel

DEFAULT_WAIT_SECONDS = 20
MAX_WAIT_SECONDS = 60


class WaitForDataRequest(ContractModel):
    timeout_seconds: int = Field(
        default=DEFAULT_WAIT_SECONDS, ge=1, le=MAX_WAIT_SECONDS, strict=True
    )


class WaitForDataReady(ContractModel):
    status: Literal["ready"] = "ready"


class WaitForDataLoading(ContractModel):
    status: Literal["loading"] = "loading"
    waited_seconds: int = Field(ge=1, le=MAX_WAIT_SECONDS)


class WaitForDataResponse(
    RootModel[Annotated[WaitForDataReady | WaitForDataLoading, Field(discriminator="status")]]
):
    model_config = ConfigDict(frozen=True, json_schema_extra={"type": "object"})
