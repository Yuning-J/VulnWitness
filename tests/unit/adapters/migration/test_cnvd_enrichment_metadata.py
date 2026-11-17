"""CNVD enrichment preserves normalization metadata alongside the record and anchors."""

from tests.support.builders import build_anchor, build_cve_record
from vulnwitness.adapters.migration.cnvd_enrichment import enrich_cnvd
from vulnwitness.adapters.nvd.normalizer import NormalizedCve
from vulnwitness.domain.normalization import DroppedMirroredBlocks


def test_cnvd_enrichment_preserves_dropped_mirrored_block_counts() -> None:
    dropped_block_counts = DroppedMirroredBlocks(source_affected=1, ssvc=2, cve_tags=3)
    normalized_cve = NormalizedCve(build_cve_record(), (build_anchor(),), dropped_block_counts)

    enriched_cve = enrich_cnvd(normalized_cve, [], "MIT")

    assert enriched_cve.dropped_mirrored_blocks == dropped_block_counts
