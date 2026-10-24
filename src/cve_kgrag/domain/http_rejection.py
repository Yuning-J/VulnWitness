"""The answer an HTTP server gives in place of a route's: to a request it refuses before
any route runs, to one whose deadline passes while its route still runs, and to one
whose route fails (ADR 0007, decision 7)."""

from enum import StrEnum
from typing import Self

from pydantic import ConfigDict, Field, model_validator

from cve_kgrag.domain.contract_model import ContractModel, describe_fixed_messages
from cve_kgrag.domain.search import SCHEMA_VERSION, SchemaVersion


class HttpRejectionCode(StrEnum):
    INVALID_REQUEST = "invalid_request"
    UNAUTHORIZED = "unauthorized"
    ORIGIN_NOT_ALLOWED = "origin_not_allowed"
    NOT_FOUND = "not_found"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    BODY_TOO_LARGE = "body_too_large"
    HOST_NOT_ALLOWED = "host_not_allowed"
    INTERNAL_ERROR = "internal_error"
    NOT_READY = "not_ready"
    DEADLINE_EXCEEDED = "deadline_exceeded"


# The one sentence a rejection of each code carries; it never quotes the request.
HTTP_REJECTION_MESSAGES: dict[HttpRejectionCode, str] = {
    HttpRejectionCode.INVALID_REQUEST: "The request is not one this server accepts.",
    HttpRejectionCode.UNAUTHORIZED: "The request lacks the server's bearer token.",
    HttpRejectionCode.ORIGIN_NOT_ALLOWED: "The request comes from an origin this server refuses.",
    HttpRejectionCode.NOT_FOUND: "This server has no such route.",
    HttpRejectionCode.METHOD_NOT_ALLOWED: "The route does not accept this method.",
    HttpRejectionCode.BODY_TOO_LARGE: "The request body exceeds the route's size limit.",
    HttpRejectionCode.HOST_NOT_ALLOWED: "The request names a host this server does not serve.",
    HttpRejectionCode.INTERNAL_ERROR: "The request failed with an internal error.",
    HttpRejectionCode.NOT_READY: "Every worker holds a call; retry later.",
    HttpRejectionCode.DEADLINE_EXCEEDED: "The request did not finish within its deadline.",
}


class HttpRejection(ContractModel):
    """Why an HTTP server answered in place of a route: a refusal before the route ran,
    the request deadline passing while it ran, or the route failing. It carries its code
    and that code's fixed sentence, never text the request carried; the HTTP status
    tells the code apart as well."""

    model_config = ConfigDict(json_schema_extra=describe_fixed_messages(HTTP_REJECTION_MESSAGES))

    schema_version: SchemaVersion = SCHEMA_VERSION
    code: HttpRejectionCode
    message: str = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def check_message(self) -> Self:
        """The message is the fixed sentence of the code (``HTTP_REJECTION_MESSAGES``)."""
        if self.message != HTTP_REJECTION_MESSAGES[self.code]:
            raise ValueError("message must be the fixed sentence of the rejection's code")
        return self


def build_http_rejection(code: HttpRejectionCode) -> HttpRejection:
    return HttpRejection(code=code, message=HTTP_REJECTION_MESSAGES[code])
