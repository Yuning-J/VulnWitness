"""EPSS scores from operator-supplied daily snapshots, and NIST's LEV lower bound over them.

EPSS (FIRST) estimates the probability that a CVE is exploited in the next 30 days. NIST
CSWP 41 ("Likely Exploited Vulnerabilities", 2025) combines a CVE's EPSS history into LEV,
the probability that it has already been exploited since EPSS first scored it:

    LEV = 1 - prod over windows w of (1 - epss(v, start(w)) * days(w) / 30)

with 30-day windows from the first scored date, the last one cut at the reference date;
LEV2 is the same product over 1-day windows. Here each supplied snapshot covers the days
from its score date up to the next snapshot or 30 days, whichever is first, never past
the reference date. Days no snapshot covers add nothing, so the result is a lower bound
on the LEV the full history would give, and ``covered_days`` says how much it rests on.

No EPSS data ships with VulnWitness: FIRST states no licence for it (THIRD_PARTY_DATA.md).
A score is a probability signal for ordering work. A low score is never evidence that a
CVE is not exploited.
"""

from collections.abc import Sequence
from datetime import date, timedelta

from pydantic import Field

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.timestamps import CalendarDate

EPSS_WINDOW_DAYS = 30
Probability = float


class EpssSnapshotIdentity(ContractModel):
    """One supplied daily EPSS file, identified by content."""

    file_name: str = Field(min_length=1, max_length=255)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    score_date: CalendarDate
    model_version: str = Field(min_length=1, max_length=64)
    rows: int = Field(ge=0)


class EpssObservation(ContractModel):
    score_date: CalendarDate
    epss: Probability = Field(ge=0, le=1)
    percentile: Probability = Field(ge=0, le=1)


class LevEstimate(ContractModel):
    lev: Probability = Field(ge=0, le=1)
    first_scored: CalendarDate = Field(
        description="The earliest supplied snapshot that scores the CVE; EPSS may have "
        "scored it earlier."
    )
    covered_days: int = Field(ge=0)
    span_days: int = Field(ge=1, description="Days from first_scored to the reference date.")


def compute_lev(observations: Sequence[EpssObservation], reference_date: date) -> LevEstimate:
    """LEV over the supplied observations dated on or before ``reference_date``."""
    usable = sorted(
        (o for o in observations if o.score_date <= reference_date), key=lambda o: o.score_date
    )
    if not usable:
        raise ValueError("no EPSS observation on or before the reference date")
    end = reference_date + timedelta(days=1)
    product = 1.0
    covered = 0
    for index, observation in enumerate(usable):
        window_end = observation.score_date + timedelta(days=EPSS_WINDOW_DAYS)
        if index + 1 < len(usable):
            window_end = min(window_end, usable[index + 1].score_date)
        days = (min(window_end, end) - observation.score_date).days
        covered += days
        product *= 1 - observation.epss * days / EPSS_WINDOW_DAYS
    first = usable[0].score_date
    return LevEstimate(
        lev=min(1.0, max(0.0, 1 - product)),
        first_scored=first,
        covered_days=covered,
        span_days=(end - first).days,
    )


def latest_observation(
    observations: Sequence[EpssObservation], reference_date: date
) -> EpssObservation | None:
    usable = [o for o in observations if o.score_date <= reference_date]
    return max(usable, key=lambda o: o.score_date, default=None)
