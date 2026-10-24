"""The cases of an investigation gold file, read for the planner evaluation.

A gold file is untrusted input: a problem in it is reported in the server's words,
never by quoting the file.
"""

from dataclasses import dataclass
from typing import Literal

import yaml
from pydantic import ValidationError

from cve_kgrag.adapters.strict_yaml import load_strict_yaml
from cve_kgrag.domain.contract_model import list_validation_problems
from cve_kgrag.domain.evidence_set_verification_report import bound_violations
from cve_kgrag.domain.hashing import canonical_sha256
from cve_kgrag.domain.investigation import InvestigationRequest

MAX_GOLD_FILE_BYTES = 1024 * 1024
MAX_GOLD_CASES = 100

FightChoice = Literal["packaged", "unavailable"]


class GoldFileError(ValueError):
    """The gold file is not an investigation gold file; the message never quotes it."""


@dataclass(frozen=True)
class GoldCase:
    """One gold row: the request and the FiGHT source its deployment serves.
    ``case_sha256`` names it in the report in place of its query."""

    case_sha256: str
    request: InvestigationRequest
    fight: FightChoice


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
    case_sha256 = canonical_sha256({"request": request.model_dump(mode="json"), "fight": fight})
    return GoldCase(case_sha256=case_sha256, request=request, fight=fight)


def load_gold_cases(gold_bytes: bytes) -> tuple[GoldCase, ...]:
    """The cases of an investigation gold file: a ``trajectories`` list whose rows each
    hold a ``request`` and ``sources.mitre_fight``; every other key is the labels, which the
    evaluation does not read. Raises ``GoldFileError`` for any other file, more than
    ``MAX_GOLD_CASES`` rows or a row repeating an earlier one."""
    if len(gold_bytes) > MAX_GOLD_FILE_BYTES:
        raise GoldFileError(f"the gold file is larger than {MAX_GOLD_FILE_BYTES} bytes")
    try:
        gold_document = load_strict_yaml(gold_bytes.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        raise GoldFileError("the gold file is not UTF-8 YAML a strict loader accepts") from None
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
