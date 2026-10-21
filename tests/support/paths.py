"""Paths into the repository checkout that tests read."""

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
# The committed v2 contract schemas.
REPOSITORY_SCHEMA_DIR = REPOSITORY_ROOT / "schemas" / "v2"
# The hand-labelled gold files.
GOLD_DIR = REPOSITORY_ROOT / "eval" / "gold"
