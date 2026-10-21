"""Injected clocks: a fixed wall clock, a monotonic clock that tests step by hand, and the
real monotonic clock started late."""

import time
from dataclasses import dataclass
from datetime import UTC, datetime

FIXED_STARTED_AT = datetime(2026, 10, 15, 8, 30, tzinfo=UTC)
# Real seconds a run under a one-second wall-time cap may take, scheduling slack included.
ONE_SECOND_RUN_REAL_SECONDS = 3.0
# How late a one-second run's clock starts, so its first planner call has 0.2 s left,
# less than the planner's third of the run.
LATE_START_SECONDS = 0.8


def read_fixed_clock() -> datetime:
    return FIXED_STARTED_AT


@dataclass
class SteppingClock:
    """A monotonic clock in seconds: each read advances it by ``seconds_per_read``, and a
    fake collaborator can ``advance`` it to simulate a slow call."""

    now_seconds: float = 0.0
    seconds_per_read: float = 0.0

    def read(self) -> float:
        reading = self.now_seconds
        self.now_seconds += self.seconds_per_read
        return reading

    def advance(self, seconds: float) -> None:
        self.now_seconds += seconds


@dataclass
class LateStartClock:
    """The real monotonic clock, read as if ``head_start_seconds`` had already passed once
    the run began: its first read is the real time, every later read adds the head start.
    A one-second run then starts its first planner call with less time left than the
    planner's share of the run, so a planner that never replies runs into the run's own
    deadline."""

    head_start_seconds: float
    has_started: bool = False

    def read(self) -> float:
        if not self.has_started:
            self.has_started = True
            return time.monotonic()
        return time.monotonic() + self.head_start_seconds
