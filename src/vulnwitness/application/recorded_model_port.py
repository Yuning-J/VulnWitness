"""The model planner a replay runs the controller with: the recorded set's replies, round by
round, so planning and relevance assessments use exactly the replies the set records."""

from collections.abc import Sequence

from vulnwitness.domain.investigation import RoundRecord
from vulnwitness.domain.planning import ModelReply, ModelReplyFailureDetail, PlanningInput
from vulnwitness.domain.relevance import RelevanceInput
from vulnwitness.domain.taxonomy import BackendStatus

# What a replayed run asking for a round the record holds no reply for is told: the
# recorded port gives no valid reply there, so the round it records differs from the
# recorded one, and replay names ``trajectory.rounds`` with every other part that follows.
# The replayed set is only compared, never published.
NO_RECORDED_REPLY = ModelReply(
    status=BackendStatus.UNAVAILABLE, detail=ModelReplyFailureDetail.ADAPTER_FAILED
)


class RecordedModelPort:
    """A ``ModelPort`` that answers each round with the reply the recorded round holds, or
    ``NO_RECORDED_REPLY`` when it holds none. It never blocks and never reads its timeout.
    A recorded reply the replayed run never asks for leaves its round without that reply,
    which replay names the same way."""

    def __init__(self, rounds: Sequence[RoundRecord]) -> None:
        self._assessor_replies: list[ModelReply] = []
        self._assessment_position = 0
        self._replies_by_round: dict[int, ModelReply] = {}
        for round_record in rounds:
            assessment = round_record.relevance_assessment
            if assessment is not None and assessment.deadline != "before_start":
                self._assessor_replies.append(assessment.reply or NO_RECORDED_REPLY)
            if round_record.model_reply is not None:
                self._replies_by_round[round_record.round_number] = round_record.model_reply

    def propose_plan(self, planning_input: PlanningInput, timeout_seconds: float) -> ModelReply:
        return self._replies_by_round.get(planning_input.round_number, NO_RECORDED_REPLY)

    def assess_relevance(
        self, assessment_input: RelevanceInput, timeout_seconds: float
    ) -> ModelReply:
        position = self._assessment_position
        self._assessment_position += 1
        if position >= len(self._assessor_replies):
            return NO_RECORDED_REPLY
        return self._assessor_replies[position]
