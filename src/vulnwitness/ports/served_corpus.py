"""The CVE records and evidence a deployment serves, whichever dataset holds them."""

from typing import Protocol

from vulnwitness.domain.cnvd import CnvdIndex
from vulnwitness.domain.cve import CveRecord
from vulnwitness.domain.evidence import EvidenceAnchor
from vulnwitness.domain.served_dataset import ServedDataset
from vulnwitness.domain.session_record import SessionCorpusIdentity


class ServedCorpus(Protocol):
    @property
    def records(self) -> tuple[CveRecord, ...]:
        """Every record, ordered by CVE ID; each cites anchors of ``evidence``."""
        ...

    @property
    def evidence(self) -> tuple[EvidenceAnchor, ...]:
        """Every anchor the records and pending entries cite."""
        ...

    @property
    def cnvd_index(self) -> CnvdIndex:
        """CNVD entries by CVE and CNVD ID, including entries pending an NVD record."""
        ...

    def describe_served_dataset(self) -> ServedDataset:
        """Which dataset these are, and the ``cve_search`` version that names it."""
        ...

    def describe_session_corpus(self) -> SessionCorpusIdentity:
        """The verified physical store and corpus identities used for session binding."""
        ...
