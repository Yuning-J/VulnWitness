"""Identifiers a finding's statement names, checked against what the session recorded.

Free narrative stays unchecked as a claim, but the CVE, CWE and CNVD IDs it names are
exact tokens: either some successful recorded response of the session contains the ID, or
none does. An ID no recorded response contains is the signature of an invented or
misremembered identifier, which models produce for CVEs past their training data. The
check is deterministic, reads no store and calls no service, and it never changes the
verdict of the record, citation or claim checks; it reports.
"""

import re
from collections.abc import Iterable
from typing import Final, Literal

from pydantic import Field

from vulnwitness.domain.contract_model import ContractModel

# ASCII digits only, and bounded on both sides so CVE-2026-12345 never matches inside
# CVE-2026-123456 or a longer token.
IDENTIFIER_PATTERN: Final = re.compile(
    r"(?<![A-Za-z0-9-])(CVE-[0-9]{4}-[0-9]{4,}|CWE-[0-9]+|CNVD-[0-9]{4}-[0-9]{4,6})(?![0-9])",
    re.IGNORECASE,
)
MAX_LISTED_UNRECORDED = 200
IdentifierKind = Literal["cve", "cwe", "cnvd"]
NARRATIVE_ID_STATEMENT: Final = (
    "Identifiers named in finding statements are matched exactly against the session's "
    "successful recorded responses. A recorded identifier is not thereby supported by the "
    "statement's claim; an unrecorded one was not returned by any call in this session."
)


class UnrecordedIdentifier(ContractModel):
    finding_id: str
    identifier: str
    kind: IdentifierKind


class NarrativeIdentifierCheck(ContractModel):
    identifiers_checked: int = Field(ge=0)
    recorded: int = Field(ge=0)
    unrecorded: tuple[UnrecordedIdentifier, ...] = Field(max_length=MAX_LISTED_UNRECORDED)
    unrecorded_count: int = Field(ge=0)
    statement: Literal[
        "Identifiers named in finding statements are matched exactly against the session's "
        "successful recorded responses. A recorded identifier is not thereby supported by "
        "the statement's claim; an unrecorded one was not returned by any call in this "
        "session."
    ] = NARRATIVE_ID_STATEMENT


def extract_identifiers(text: str) -> tuple[str, ...]:
    """Distinct identifiers in order of first mention, upper-cased."""
    identifiers: list[str] = []
    for match in IDENTIFIER_PATTERN.finditer(text):
        identifier = match.group(1).upper()
        if identifier not in identifiers:
            identifiers.append(identifier)
    return tuple(identifiers)


def classify_identifier(identifier: str) -> IdentifierKind:
    if identifier.startswith("CVE-"):
        return "cve"
    if identifier.startswith("CWE-"):
        return "cwe"
    return "cnvd"


def collect_recorded_identifiers(response_texts: Iterable[str]) -> frozenset[str]:
    recorded: set[str] = set()
    for text in response_texts:
        recorded.update(extract_identifiers(text))
    return frozenset(recorded)


def check_narrative_identifiers(
    statements: Iterable[tuple[str, str]], recorded: frozenset[str]
) -> NarrativeIdentifierCheck:
    """``statements`` are (finding ID, statement) pairs in finding order."""
    checked = 0
    recorded_count = 0
    unrecorded: list[UnrecordedIdentifier] = []
    for finding_id, statement in statements:
        for identifier in extract_identifiers(statement):
            checked += 1
            if identifier in recorded:
                recorded_count += 1
            else:
                unrecorded.append(
                    UnrecordedIdentifier(
                        finding_id=finding_id,
                        identifier=identifier,
                        kind=classify_identifier(identifier),
                    )
                )
    return NarrativeIdentifierCheck(
        identifiers_checked=checked,
        recorded=recorded_count,
        unrecorded=tuple(unrecorded[:MAX_LISTED_UNRECORDED]),
        unrecorded_count=len(unrecorded),
    )
