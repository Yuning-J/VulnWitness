"""The budget ledger charges before calls, admits only timely results within the byte cap,
and reports the first breach."""

import pytest

from tests.support.clocks import SteppingClock
from vulnwitness.application.budget_ledger import BudgetLedger
from vulnwitness.domain.budget import BudgetBreach, InvestigationBudget
from vulnwitness.domain.investigation import StepAdmission
from vulnwitness.domain.topic_context import KnowledgeSource


def build_ledger(clock: SteppingClock, **budget_fields: int) -> BudgetLedger:
    budget = InvestigationBudget.model_validate(budget_fields)
    return BudgetLedger(budget, clock.read, started_at_seconds=clock.read())


def test_charges_accumulate_and_sources_keep_first_consulted_order() -> None:
    ledger = build_ledger(SteppingClock())

    ledger.charge(1, [KnowledgeSource.CVE_SEARCH])
    ledger.charge(5, [KnowledgeSource.MITRE_FIGHT, KnowledgeSource.CVE_SEARCH])

    usage = ledger.summarize_usage()
    assert usage.tool_calls == 6
    assert usage.sources == (KnowledgeSource.CVE_SEARCH, KnowledgeSource.MITRE_FIGHT)
    assert ledger.remaining_tool_calls() == 2


def test_charge_stands_when_the_result_is_discarded() -> None:
    ledger = build_ledger(SteppingClock(), max_context_bytes=10)
    ledger.charge(1, [KnowledgeSource.CVE_SEARCH])

    admission = ledger.decide_admission(context_bytes=11, finished_seconds=0.0)

    assert admission is StepAdmission.DISCARDED_OVER_CONTEXT_BUDGET
    assert ledger.summarize_usage().tool_calls == 1
    assert ledger.summarize_usage().context_bytes == 0


@pytest.mark.parametrize(
    ("finished_seconds", "expected_admission"),
    [
        (29.999, StepAdmission.ADMITTED),
        (30.0, StepAdmission.DISCARDED_AFTER_DEADLINE),
        (31.0, StepAdmission.DISCARDED_AFTER_DEADLINE),
    ],
    ids=["just_in_time", "exactly_at_deadline", "late"],
)
def test_result_finishing_at_or_after_the_deadline_is_discarded(
    finished_seconds: float, expected_admission: StepAdmission
) -> None:
    ledger = build_ledger(SteppingClock())

    admission = ledger.decide_admission(context_bytes=100, finished_seconds=finished_seconds)

    assert admission is expected_admission


def test_late_result_records_a_wall_time_breach() -> None:
    ledger = build_ledger(SteppingClock(), max_wall_time_seconds=5)

    ledger.decide_admission(context_bytes=100, finished_seconds=5.5)

    assert ledger.summarize_usage().breach is BudgetBreach.WALL_TIME


def test_remaining_time_follows_the_injected_clock() -> None:
    clock = SteppingClock(now_seconds=100.0)
    ledger = build_ledger(clock, max_wall_time_seconds=10)

    clock.advance(4.0)

    assert ledger.remaining_seconds() == 6.0
    assert ledger.is_out_of_time() is False


def test_run_is_out_of_time_once_the_deadline_is_reached() -> None:
    clock = SteppingClock()
    ledger = build_ledger(clock, max_wall_time_seconds=10)

    clock.advance(10.0)

    assert ledger.is_out_of_time() is True
    assert ledger.remaining_seconds() == 0.0


def test_admitted_bytes_accumulate_until_the_next_result_would_cross_the_cap() -> None:
    ledger = build_ledger(SteppingClock(), max_context_bytes=1000)

    first_admission = ledger.decide_admission(context_bytes=600, finished_seconds=0.0)
    second_admission = ledger.decide_admission(context_bytes=400, finished_seconds=0.0)
    third_admission = ledger.decide_admission(context_bytes=1, finished_seconds=0.0)

    assert (first_admission, second_admission, third_admission) == (
        StepAdmission.ADMITTED,
        StepAdmission.ADMITTED,
        StepAdmission.DISCARDED_OVER_CONTEXT_BUDGET,
    )
    assert ledger.summarize_usage().context_bytes == 1000
    assert ledger.summarize_usage().breach is BudgetBreach.CONTEXT_BYTES


def test_deadline_is_checked_before_the_byte_cap() -> None:
    ledger = build_ledger(SteppingClock(), max_wall_time_seconds=1, max_context_bytes=1)

    admission = ledger.decide_admission(context_bytes=2, finished_seconds=2.0)

    assert admission is StepAdmission.DISCARDED_AFTER_DEADLINE


def test_first_breach_is_the_one_reported() -> None:
    ledger = build_ledger(SteppingClock())

    ledger.record_breach(BudgetBreach.TOOL_CALLS)
    ledger.record_breach(BudgetBreach.WALL_TIME)

    assert ledger.summarize_usage().breach is BudgetBreach.TOOL_CALLS
