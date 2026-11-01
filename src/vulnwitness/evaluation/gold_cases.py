"""The cases of an investigation gold file, read for the planner evaluation.

A gold file is untrusted input: a problem in it is reported in the server's words,
never by quoting the file.
"""

from dataclasses import dataclass
from typing import Literal

from pydantic import ValidationError

from vulnwitness.domain.contract_model import list_validation_problems
from vulnwitness.domain.evidence_set_verification_report import bound_violations
from vulnwitness.domain.hashing import canonical_sha256
from vulnwitness.domain.investigation import InvestigationRequest

MAX_GOLD_FILE_BYTES = 1024 * 1024
MAX_GOLD_CASES = 100

# The FiGHT source a case runs on: the packaged excerpt or none (an M7a case's choice), or
# the operator snapshot an M7b evaluation serves.
FightChoice = Literal["packaged", "unavailable", "operator"]


class GoldFileError(ValueError):
    """The gold file is not an investigation gold file; the message never quotes it."""


@dataclass(frozen=True)
class GoldCase:
    """One gold row: the request and the FiGHT source its deployment serves.
    ``case_sha256`` names it in the report in place of its query."""

    case_sha256: str
    request: InvestigationRequest
    fight: FightChoice


def compute_case_sha256(request: InvestigationRequest, fight: FightChoice) -> str:
    return canonical_sha256({"request": request.model_dump(mode="json"), "fight": fight})


def read_gold_case(row: object, position: int) -> GoldCase:
    if not isinstance(row, dict):
        raise GoldFileError(f"case {position} is not a mapping")
    sources = row.get("sources")
    fight_name = sources.get("mitre_fight") if isinstance(sources, dict) else None
    fight: FightChoice
    if fight_name == "packaged":
        fight = "packaged"
    elif fight_name == "unavailable":
        fight = "unavailable"
    else:
        raise GoldFileError(f"case {position}: sources.mitre_fight is not packaged or unavailable")
    try:
        request = InvestigationRequest.model_validate(row.get("request"))
    except ValidationError as error:
        problems = "; ".join(bound_violations(list_validation_problems(error)))
        raise GoldFileError(f"case {position}: request: {problems}") from None
    return GoldCase(case_sha256=compute_case_sha256(request, fight), request=request, fight=fight)


def read_gold_cases(gold_document: object) -> tuple[GoldCase, ...]:
    """The cases of an investigation gold file, as ``read_gold_document`` parsed it: a
    ``trajectories`` list whose rows each hold a ``request`` and ``sources.mitre_fight``;
    every other key is the labels, which the evaluation does not read. Raises
    ``GoldFileError`` for any other document, more than ``MAX_GOLD_CASES`` rows or a row
    repeating an earlier one."""
    rows = gold_document.get("trajectories") if isinstance(gold_document, dict) else None
    if not isinstance(rows, list) or not rows:
        raise GoldFileError("the gold file holds no trajectories list")
    if len(rows) > MAX_GOLD_CASES:
        raise GoldFileError(f"the gold file holds more than {MAX_GOLD_CASES} cases")
    cases: list[GoldCase] = []
    case_hashes: set[str] = set()
    for position, row in enumerate(rows, start=1):
        case = read_gold_case(row, position)
        if case.case_sha256 in case_hashes:
            raise GoldFileError(f"case {position} repeats an earlier case")
        case_hashes.add(case.case_sha256)
        cases.append(case)
    return tuple(cases)
