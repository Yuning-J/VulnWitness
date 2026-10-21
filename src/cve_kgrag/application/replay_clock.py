"""The clock a replay runs the controller on: the deployment's monotonic clock, moved past
the deadline at the checkpoint where the recorded run found it."""

from collections.abc import Callable

from cve_kgrag.application.deadline_checkpoint import DeadlineCheckpoint


class ReplayClock:
    """Reads the deployment's ``monotonic_clock``. When the controller reaches
    ``deadline_checkpoint``, the recorded run's deadline point, every later reading is
    moved on by ``max_wall_time_seconds``, the run's whole wall-time cap, so the controller's
    own check there finds the deadline as the recorded run did, and the replay's timings
    put that point at or past it.

    Until then the readings are real, so the call runner bounds every replayed call by the
    time the replay has left of the same cap: a replay that reaches the deadline anywhere
    else ran into its own deadline (``has_reached_recorded_deadline`` stays ``False``).
    Only the controller's thread reads and moves it.
    """

    def __init__(
        self,
        monotonic_clock: Callable[[], float],
        max_wall_time_seconds: float,
        deadline_checkpoint: DeadlineCheckpoint | None,
    ) -> None:
        self._monotonic_clock = monotonic_clock
        self._max_wall_time_seconds = max_wall_time_seconds
        self._deadline_checkpoint = deadline_checkpoint
        self._offset_seconds = 0.0
        self.has_reached_recorded_deadline = False

    def read(self) -> float:
        return self._monotonic_clock() + self._offset_seconds

    def reach(self, checkpoint: DeadlineCheckpoint) -> None:
        if checkpoint != self._deadline_checkpoint or self.has_reached_recorded_deadline:
            return
        self._offset_seconds = self._max_wall_time_seconds
        self.has_reached_recorded_deadline = True
