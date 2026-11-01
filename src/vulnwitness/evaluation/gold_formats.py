"""Which evaluation a gold file is for, decided once from its parsed top-level keys.

A gold file is untrusted input: it is read within ``MAX_GOLD_FILE_BYTES`` and parsed
once by the strict loader both formats' loaders use, and a problem is reported in the
server's words, never by quoting the file.
"""

from enum import StrEnum

import yaml

from vulnwitness.adapters.strict_yaml import load_strict_yaml
from vulnwitness.evaluation.gold_cases import MAX_GOLD_FILE_BYTES, GoldFileError

TRAJECTORIES_KEY = "trajectories"
LABELLED_KEYS = frozenset({"cases", "corpus_content_sha256", "fight_snapshot_sha256"})


class GoldFormat(StrEnum):
    """M7a's investigation trajectories over the fixture, or M7b's labelled cases over a
    store."""

    TRAJECTORIES = "trajectories"
    LABELLED_CASES = "labelled_cases"


def read_gold_document(gold_bytes: bytes) -> object:
    """The gold file parsed by the strict loader. Raises ``GoldFileError`` for a file
    over ``MAX_GOLD_FILE_BYTES`` or one the strict loader refuses."""
    if len(gold_bytes) > MAX_GOLD_FILE_BYTES:
        raise GoldFileError(f"the gold file is larger than {MAX_GOLD_FILE_BYTES} bytes")
    try:
        return load_strict_yaml(gold_bytes.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        raise GoldFileError("the gold file is not UTF-8 YAML a strict loader accepts") from None


def classify_gold_document(gold_document: object) -> GoldFormat:
    """The format the document's top-level key names state: ``trajectories`` alone, or
    all three labelled-case keys and no ``trajectories``. Raises ``GoldFileError`` for any
    other mapping, part of the labelled-case keys included, and for a document that is no
    mapping. Only key names are read; the format's loader validates the rest."""
    if not isinstance(gold_document, dict):
        raise GoldFileError("the gold file is not a mapping")
    keys = set(gold_document)
    has_trajectories = TRAJECTORIES_KEY in keys
    labelled_keys_present = LABELLED_KEYS & keys
    if has_trajectories and not labelled_keys_present:
        return GoldFormat.TRAJECTORIES
    if not has_trajectories and labelled_keys_present == LABELLED_KEYS:
        return GoldFormat.LABELLED_CASES
    raise GoldFileError(
        "the gold file names neither trajectories alone nor cases with both data digests"
    )
