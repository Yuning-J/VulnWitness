"""The report of a whole-set verification: what checking a knowledge evidence set handed
back found (ADR 0003 §10)."""

from collections.abc import Iterable
from enum import StrEnum
from typing import Annotated, Self

from pydantic import BeforeValidator, ConfigDict, Field, JsonValue, model_validator
from pydantic.config import JsonDict

from cve_kgrag.domain.contract_model import ContractModel
from cve_kgrag.domain.search import require_json_number

# A report carries at most this many violations, each of at most this many characters: a
# set can break far more rules than a reader needs listed, and the longest sentence a
# contract can give (one listing every allowed value) stays well under the length.
MAX_REPORTED_VIOLATIONS = 100
MAX_VIOLATION_CHARS = 1024
TRUNCATION_MARK = "..."

# A violation is the server's own sentence; none repeats text the checked set chose.
ViolationText = Annotated[str, Field(min_length=1, max_length=MAX_VIOLATION_CHARS)]


class VerificationVerdict(StrEnum):
    """What the verification found: the set parsed (``malformed`` when not); passed the
    validator and the decision-path audit, and its replay passed the checks the controller
    runs at seal (``invalid`` when not); and replayed to the recorded set
    (``replay_differs`` or ``replay_timed_out`` when not)."""

    VERIFIED = "verified"
    MALFORMED = "malformed"
    INVALID = "invalid"
    REPLAY_DIFFERS = "replay_differs"
    REPLAY_TIMED_OUT = "replay_timed_out"


# The verdicts a report gives with violations, and the one it gives with differences.
VERDICTS_WITH_VIOLATIONS = frozenset({VerificationVerdict.MALFORMED, VerificationVerdict.INVALID})
VERDICT_WITH_DIFFERENCES = VerificationVerdict.REPLAY_DIFFERS


def describe_verification_report_shape() -> JsonDict:
    """``VerificationReport.check_findings_match_verdict`` as JSON Schema."""
    verdicts_with_violations: list[JsonValue] = []
    for verdict in VerificationVerdict:
        if verdict in VERDICTS_WITH_VIOLATIONS:
            verdicts_with_violations.append(verdict.value)
    return {
        "allOf": [
            {
                "if": {"properties": {"verdict": {"enum": verdicts_with_violations}}},
                "then": {"properties": {"violations": {"minItems": 1}}},
                "else": {"properties": {"violations": {"maxItems": 0}}},
            },
            {
                "if": {"properties": {"verdict": {"const": VERDICT_WITH_DIFFERENCES.value}}},
                "then": {"properties": {"differences": {"minItems": 1}}},
                "else": {"properties": {"differences": {"maxItems": 0}}},
            },
        ]
    }


def bound_violations(violations: Iterable[str]) -> tuple[str, ...]:
    """The first ``MAX_REPORTED_VIOLATIONS`` violations, each longer than
    ``MAX_VIOLATION_CHARS`` cut to that length and ending in ``TRUNCATION_MARK``."""
    bounded_violations: list[str] = []
    for violation in violations:
        if len(bounded_violations) == MAX_REPORTED_VIOLATIONS:
            break
        if len(violation) > MAX_VIOLATION_CHARS:
            violation = violation[: MAX_VIOLATION_CHARS - len(TRUNCATION_MARK)] + TRUNCATION_MARK
        bounded_violations.append(violation)
    return tuple(bounded_violations)


class ReportedDifference(ContractModel):
    """A recorded part the replayed run gives differently: the field ``part`` of step
    ``step_index`` (``step`` when the step exists in only one of the two runs), or, when
    ``step_index`` is null, the set-level ``part``, a dotted path such as
    ``coverage.source_outcomes``. It never carries a response's or reply's text."""

    # Steps are numbered from 1, as in the trajectory. The bound comes before the
    # validator so that the published schema states it.
    step_index: Annotated[int, Field(ge=1), BeforeValidator(require_json_number)] | None
    part: str = Field(min_length=1, max_length=128)


class VerificationReport(ContractModel):
    """The verdict, the violations behind a ``malformed`` or ``invalid`` verdict, and the
    differences behind ``replay_differs``; each other verdict carries neither."""

    model_config = ConfigDict(json_schema_extra=describe_verification_report_shape())

    # Declared in the order `cve-kgrag verify` prints the keys.
    verdict: VerificationVerdict
    violations: tuple[ViolationText, ...] = Field(default=(), max_length=MAX_REPORTED_VIOLATIONS)
    differences: tuple[ReportedDifference, ...] = ()

    @model_validator(mode="after")
    def check_findings_match_verdict(self) -> Self:
        violations_expected = self.verdict in VERDICTS_WITH_VIOLATIONS
        differences_expected = self.verdict is VERDICT_WITH_DIFFERENCES
        if bool(self.violations) is not violations_expected:
            raise ValueError(f"a {self.verdict.value} report has the wrong violations")
        if bool(self.differences) is not differences_expected:
            raise ValueError(f"a {self.verdict.value} report has the wrong differences")
        return self
