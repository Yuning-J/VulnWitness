"""Every bound an import runs under (ADR 0008 §1, §6, §8). The defaults are the ADR's
constants; a run always uses them, and tests pass smaller ones to reach each bound."""

from dataclasses import dataclass

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB


@dataclass(frozen=True)
class MigrationLimits:
    max_compressed_file_bytes: int = 256 * MIB
    max_decompressed_file_bytes: int = 1 * GIB
    max_total_decompressed_bytes: int = 8 * GIB
    max_entry_bytes: int = 16 * MIB
    # The parser reads a feed this many bytes at a time, so it reads at most this far past
    # where an entry began before the entry's cap is checked.
    parser_buffer_bytes: int = 64 * KIB
    max_entry_depth: int = 64
    max_nvd_candidates: int = 1_000_000
    max_staging_bytes: int = 16 * GIB
    max_kev_bytes: int = 16 * MIB
    max_kev_rows: int = 50_000
    max_cnvd_bytes: int = 64 * MIB
    max_raw_cnvd_bytes: int = 256 * MIB
    max_cnvd_rows: int = 250_000
    max_walk_depth: int = 32
    max_walk_entries: int = 100_000
    magic_prefix_bytes: int = 8 * KIB
    max_fingerprint_file_bytes: int = 1 * MIB
    max_fingerprint_total_bytes: int = 256 * MIB
