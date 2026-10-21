"""Runs one planner or tool call on its own daemon thread and waits for it no longer than
the run has left, so a blocking adapter cannot hold an investigation past its deadline.

Python cannot stop a running thread, so a call still running at the deadline is
abandoned, not killed: its thread runs until the call returns, and whatever it
returns then is dropped. The thread is a daemon, so an abandoned call never keeps
the interpreter from exiting. The calls run here are read-only searches and plan
proposals, so an abandoned call changes nothing the run reads afterwards. Network
adapters still have to honour the timeout they are given, or each abandoned call
keeps a thread and a connection until the remote side gives up.

A runner counts its live calls: those that have not returned, whether their caller is
still waiting or abandoned them. A runner built with ``max_live_calls`` starts no call
beyond it, so abandoned calls keep counting against the cap until they return.
"""

import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

ResultT = TypeVar("ResultT")
# Every call thread carries this name, so a thread dump shows which threads hold calls.
CALL_THREAD_NAME = "cve-kgrag-call"


@dataclass(frozen=True)
class CallTimedOut:
    """The deadline came before the call returned; the call was abandoned."""


@dataclass(frozen=True)
class CallReturned(Generic[ResultT]):
    value: ResultT


@dataclass(frozen=True)
class CallRaised:
    error: BaseException


class CallAborted(RuntimeError):
    """The call raised a ``BaseException`` that is not an ``Exception`` (``SystemExit``,
    ``KeyboardInterrupt`` or a custom one). It ended only the call's own thread, so the
    caller sees it as an ordinary error, chained to the original."""


class NoFreeWorker(RuntimeError):
    """The runner already has ``max_live_calls`` live calls, or the caller's admission
    check refused the call, so the call was not started."""


def admit_every_call() -> bool:
    return True


class ThreadedCallRunner:
    """Runs each call on a fresh daemon thread, bounded by the time the run has left, and
    never more than ``max_live_calls`` at once when it is set (``None``: no cap)."""

    def __init__(self, max_live_calls: int | None = None) -> None:
        self._max_live_calls = max_live_calls
        self._live_call_count = 0
        self._count_lock = threading.Lock()

    def count_live_calls(self) -> int:
        """The calls started that have not returned, abandoned or not."""
        with self._count_lock:
            return self._live_call_count

    def run(
        self,
        call: Callable[[], ResultT],
        remaining_seconds: Callable[[], float],
        admits: Callable[[], bool] = admit_every_call,
    ) -> ResultT | CallTimedOut:
        """What ``call`` returns, or ``CallTimedOut`` once ``remaining_seconds()`` reaches 0.

        ``remaining_seconds`` reads the run's injected clock. It is read once before the
        call starts and again only when a wait runs out, so a call that returns in time
        costs one read, and the call is reported timed out only when that clock says the
        deadline has come. A call whose deadline has come before it starts is never
        started. An exception the call raises is re-raised here; any other ``BaseException``
        it raises is raised as ``CallAborted``. Raises ``NoFreeWorker``,
        without starting the call, when the runner already has ``max_live_calls`` live
        calls or ``admits()`` answers ``False``. ``admits`` is asked under the runner's
        lock, just before the call is counted live, so no other call of this runner is
        admitted between the check and the start; it must not call back into this runner.
        """
        timeout_seconds = remaining_seconds()
        outcome_queue: queue.Queue[CallReturned[ResultT] | CallRaised] = queue.Queue(maxsize=1)
        if timeout_seconds > 0:
            self._start_worker(call, outcome_queue, admits)
        while timeout_seconds > 0:
            try:
                outcome = outcome_queue.get(timeout=timeout_seconds)
            except queue.Empty:
                timeout_seconds = remaining_seconds()
                continue
            if isinstance(outcome, CallRaised):
                if not isinstance(outcome.error, Exception):
                    raise CallAborted("the call raised a non-Exception BaseException") from (
                        outcome.error
                    )
                raise outcome.error
            return outcome.value
        return CallTimedOut()

    def _start_worker(
        self,
        call: Callable[[], ResultT],
        outcome_queue: "queue.Queue[CallReturned[ResultT] | CallRaised]",
        admits: Callable[[], bool],
    ) -> None:
        """Count the call live and start its thread, or raise ``NoFreeWorker`` at the cap
        or when ``admits`` refuses it."""
        with self._count_lock:
            if self._max_live_calls is not None and self._live_call_count >= self._max_live_calls:
                raise NoFreeWorker("every worker is busy")
            if not admits():
                raise NoFreeWorker("the call was not admitted")
            self._live_call_count += 1
        worker = threading.Thread(
            target=self._deliver_outcome,
            args=(call, outcome_queue),
            name=CALL_THREAD_NAME,
            daemon=True,
        )
        try:
            worker.start()
        except BaseException:
            self._finish_call()
            raise

    def _deliver_outcome(
        self,
        call: Callable[[], ResultT],
        outcome_queue: "queue.Queue[CallReturned[ResultT] | CallRaised]",
    ) -> None:
        """Thread target: run ``call``, stop counting it live, then hand what it returned
        or raised to the waiting caller, so a caller that has the outcome never finds
        its own call still counted."""
        outcome: CallReturned[ResultT] | CallRaised
        try:
            outcome = CallReturned(call())
        except BaseException as error:  # the waiting caller re-raises it on its own thread
            outcome = CallRaised(error)
        self._finish_call()
        outcome_queue.put(outcome)

    def _finish_call(self) -> None:
        with self._count_lock:
            self._live_call_count -= 1
