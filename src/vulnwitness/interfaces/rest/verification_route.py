"""``POST /api/v2/verify``: a knowledge evidence set handed back, checked as
``vulnwitness verify`` checks one (ADR 0007, decision 9).

Every verdict is the answer, with 200: a verification answer is not a request failure.
The route checks one set at a time: a request arriving while a check runs, one abandoned
at its deadline included, is answered 503 ``route_busy`` without waiting.
"""

import threading
from collections.abc import Callable

import anyio.to_thread
from starlette.types import Receive, Scope, Send

from vulnwitness.domain.evidence_set_verification_report import VerificationReport
from vulnwitness.domain.http_rejection import HttpRejectionCode
from vulnwitness.interfaces.http.guard import read_route_body, send_json, send_rejection

EvidenceSetCheck = Callable[[bytes], VerificationReport]


class VerificationRoute:
    """Answers the ``VerificationReport`` ``check_evidence_set`` gives the body."""

    def __init__(self, check_evidence_set: EvidenceSetCheck) -> None:
        self._check_evidence_set = check_evidence_set
        self._running_check = threading.Lock()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        evidence_set_bytes = await read_route_body(receive)
        report = await anyio.to_thread.run_sync(
            self._check_unless_busy, evidence_set_bytes, abandon_on_cancel=True
        )
        if report is None:
            await send_rejection(send, HttpRejectionCode.ROUTE_BUSY)
            return
        await send_json(send, 200, report.model_dump_json().encode())

    def _check_unless_busy(self, evidence_set_bytes: bytes) -> VerificationReport | None:
        """The check's report, or ``None`` while another check runs. It holds the route
        on its worker thread, from the moment the check starts until it returns, so a
        request cancelled before its thread starts holds nothing, and a check abandoned at
        the request deadline keeps the route until it ends."""
        if not self._running_check.acquire(blocking=False):
            return None
        try:
            return self._check_evidence_set(evidence_set_bytes)
        finally:
            self._running_check.release()
