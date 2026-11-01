"""The dataset a deployment serves: the packaged synthetic fixture or an activated corpus
store (ADR 0009 §1)."""

from enum import StrEnum

from pydantic import Field

from vulnwitness.domain.contract_model import ContractModel


class ServedDatasetKind(StrEnum):
    SYNTHETIC_FIXTURE = "synthetic_fixture"
    CORPUS_STORE = "corpus_store"


class ServedDataset(ContractModel):
    """What the deployment's CVE records and evidence are. ``cve_search_version`` is the
    ``cve_search`` capability's version: equal versions name byte-for-byte equal records
    and evidence, so a set sealed under one verifies under the other."""

    kind: ServedDatasetKind
    cve_search_version: str = Field(min_length=1)
