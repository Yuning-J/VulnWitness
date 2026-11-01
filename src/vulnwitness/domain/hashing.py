"""Canonical JSON hashing used for content hashes, evidence IDs and result hashes."""

import hashlib
import json
from typing import Any

# Placeholder hash a response draft carries until its own content hash is computed.
UNSEALED_SHA256 = "0" * 64


def canonical_json_bytes(payload: Any) -> bytes:
    """Serialize JSON-compatible data with sorted keys and no insignificant whitespace."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def canonical_sha256(payload: Any) -> str:
    return sha256_hex(canonical_json_bytes(payload))
