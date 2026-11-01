"""The CVE records and evidence a deployment serves, whichever dataset holds them."""

from typing import Protocol

from cve_kgrag.domain.cve import CveRecord
from cve_kgrag.domain.evidence import EvidenceAnchor
from cve_kgrag.domain.served_dataset import ServedDataset
from cve_kgrag.domain.session_record import SessionCorpusIdentity


class ServedCorpus(Protocol):
    @property
    def records(self) -> tuple[CveRecord, ...]:
        """Every record, ordered by CVE ID; each cites anchors of ``evidence``."""
        ...

    @property
    def evidence(self) -> tuple[EvidenceAnchor, ...]:
        """Every anchor the records cite."""
        ...

    def describe_served_dataset(self) -> ServedDataset:
        """Which dataset these are, and the ``cve_search`` version that names it."""
        ...

    def describe_session_corpus(self) -> SessionCorpusIdentity:
        """The verified physical store and corpus identities used for session binding."""
        ...
