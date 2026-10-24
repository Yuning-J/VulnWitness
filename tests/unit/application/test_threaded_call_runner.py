"""The call runner returns what a call returns, re-raises what it raises, and gives control
back once the remaining time reads zero, whether or not the call has returned."""

import threading
import time
from dataclasses import dataclass, field

import pytest

from cve_kgrag.application.threaded_call_runner import (
    CallAborted,
    CallTimedOut,
    NoFreeWorker,
    ThreadedCallRunner,
)

# Ample time for a released call's thread to finish, so a slow machine never fails a test.
GENEROUS_WAIT_SECONDS = 10.0


@dataclass
class ScriptedRemaining:
    """Remaining seconds read in order from ``readings``; the last reading repeats."""

    readings: list[float]
    reads: int = 0

    def read(self) -> float:
        reading = self.readings[min(self.reads, len(self.readings) - 1)]
        self.reads += 1
        return reading


@dataclass
class RecordingCall:
    """A call that records the thread it ran on, waits for ``release`` when given one, and
    returns ``value``."""

    value: str = "returned"
    release: threading.Event | None = None
    threads: list[threading.Thread] = field(default_factory=list)

    def run(self) -> str:
        self.threads.append(threading.current_thread())
        if self.release is not None:
            self.release.wait()
        return self.value


@dataclass
class FailingCall:
    error: Exception

    def run(self) -> str:
        raise self.error


def test_call_returning_in_time_gives_its_value_on_a_daemon_thread() -> None:
    call = RecordingCall()
    remaining = ScriptedRemaining([30.0])

    call_outcome = ThreadedCallRunner().run(call.run, remaining.read)

    assert call_outcome == "returned"
    assert remaining.reads == 1
    assert call.threads[0] is not threading.current_thread()
    assert call.threads[0].daemon is True


def test_call_raising_has_its_error_raised_to_the_caller() -> None:
    error = LookupError("3gpp:unknown")

    with pytest.raises(LookupError) as raised:
        ThreadedCallRunner().run(FailingCall(error).run, ScriptedRemaining([30.0]).read)

    assert raised.value is error


def test_call_still_running_when_the_time_reads_zero_is_timed_out(
    blocked_call_release: threading.Event,
) -> None:
    call = RecordingCall(release=blocked_call_release)
    remaining = ScriptedRemaining([0.05, 0.0])

    call_outcome = ThreadedCallRunner().run(call.run, remaining.read)

    assert isinstance(call_outcome, CallTimedOut)
    assert remaining.reads == 2


def test_wait_ending_before_the_time_reads_zero_waits_again(
    blocked_call_release: threading.Event,
) -> None:
    call = RecordingCall(release=blocked_call_release)
    remaining = ScriptedRemaining([0.01, 0.01, 0.0])

    call_outcome = ThreadedCallRunner().run(call.run, remaining.read)

    assert isinstance(call_outcome, CallTimedOut)
    assert remaining.reads == 3


def test_no_time_left_never_starts_the_call() -> None:
    call = RecordingCall()

    call_outcome = ThreadedCallRunner().run(call.run, ScriptedRemaining([0.0]).read)

    assert isinstance(call_outcome, CallTimedOut)
    assert call.threads == []


def test_call_over_the_live_cap_is_refused_without_starting() -> None:
    release = threading.Event()
    runner = ThreadedCallRunner(max_live_calls=1)
    blocked_call = RecordingCall(release=release)
    refused_call = RecordingCall()
    first_outcome = runner.run(blocked_call.run, ScriptedRemaining([0.01, 0.0]).read)

    with pytest.raises(NoFreeWorker):
        runner.run(refused_call.run, ScriptedRemaining([30.0]).read)

    release.set()
    blocked_call.threads[0].join(timeout=5.0)
    assert first_outcome == CallTimedOut()
    assert refused_call.threads == []
    assert runner.count_live_calls() == 0


def test_call_its_admission_check_refuses_is_never_started() -> None:
    runner = ThreadedCallRunner()
    call = RecordingCall()

    with pytest.raises(NoFreeWorker):
        runner.run(call.run, ScriptedRemaining([30.0]).read, admits=lambda: False)

    assert call.threads == []
    assert runner.count_live_calls() == 0


def test_call_that_returned_or_raised_no_longer_counts_as_live() -> None:
    runner = ThreadedCallRunner(max_live_calls=1)
    runner.run(RecordingCall().run, ScriptedRemaining([30.0]).read)
    with pytest.raises(ValueError):
        runner.run(FailingCall(ValueError("boom")).run, ScriptedRemaining([30.0]).read)

    live_call_count = runner.count_live_calls()

    assert live_call_count == 0


@dataclass
class ExitingCall:
    def run(self) -> str:
        raise SystemExit("CONFIRMED: raised by an adapter")


def test_call_raising_a_non_exception_base_exception_is_raised_as_call_aborted() -> None:
    runner = ThreadedCallRunner()

    with pytest.raises(CallAborted) as raised:
        runner.run(ExitingCall().run, ScriptedRemaining([30.0]).read)

    assert isinstance(raised.value.__cause__, SystemExit)
    assert runner.count_live_calls() == 0


def test_runner_without_live_calls_is_idle_at_once() -> None:
    runner = ThreadedCallRunner()
    runner.run(RecordingCall().run, ScriptedRemaining([30.0]).read)

    assert runner.wait_until_idle(0.0) is True


def test_runner_is_idle_only_once_its_abandoned_call_returns(
    blocked_call_release: threading.Event,
) -> None:
    runner = ThreadedCallRunner()
    runner.run(RecordingCall(release=blocked_call_release).run, ScriptedRemaining([0.05, 0.0]).read)

    is_idle_while_blocked = runner.wait_until_idle(0.05)
    blocked_call_release.set()
    released_at = time.monotonic()
    is_idle_once_released = runner.wait_until_idle(GENEROUS_WAIT_SECONDS)
    idle_wait_seconds = time.monotonic() - released_at

    assert is_idle_while_blocked is False
    assert is_idle_once_released is True
    # The returning call wakes the waiter; it never waits out its whole timeout.
    assert idle_wait_seconds < GENEROUS_WAIT_SECONDS
