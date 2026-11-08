"""Load the reviewed CNVD catalog and require one complete revision's file set."""

from collections.abc import Sequence
from dataclasses import replace
from importlib.resources import files
from importlib.resources.abc import Traversable

from vulnwitness.adapters.migration.input_resolution import ResolvedInput
from vulnwitness.adapters.strict_yaml import load_strict_yaml
from vulnwitness.domain.cnvd_snapshot import CnvdSnapshotCatalog, CnvdSnapshotFile
from vulnwitness.domain.corpus_store_manifest import StoreSource
from vulnwitness.domain.migration_report import MigrationFailed, MigrationFailureCode

CNVD_RESOLVE_URL = "https://huggingface.co/datasets/CIRCL/Vulnerability-CNVD/resolve"


def default_cnvd_snapshot_catalog_file() -> Traversable:
    return files("vulnwitness").joinpath("knowledge", "cnvd_snapshots.yaml")


def load_cnvd_snapshot_catalog(catalog_file: Traversable) -> CnvdSnapshotCatalog:
    """Read a strictly typed catalog from YAML; raises validation errors for bad entries."""
    return CnvdSnapshotCatalog.model_validate(
        load_strict_yaml(catalog_file.read_text(encoding="utf-8"))
    )


def match_cnvd_inputs(
    inputs: Sequence[ResolvedInput], catalog: CnvdSnapshotCatalog
) -> tuple[tuple[ResolvedInput, ...], dict[int, CnvdSnapshotFile]]:
    """Require exactly one revision's files by byte hash, returning pinned URLs and files
    by input position. Raises ``MigrationFailed`` for uncatalogued or incomplete inputs.
    No CNVD declarations require no catalog match.
    """
    cnvd_hashes: set[str] = set()
    catalog_hashes: set[str] = set()
    for snapshot in catalog.snapshots:
        for snapshot_file in snapshot.files:
            catalog_hashes.add(snapshot_file.sha256)
    for resolved_input in inputs:
        if resolved_input.source is StoreSource.CIRCL_CNVD:
            file_hash = resolved_input.input_file.sha256
            if file_hash not in catalog_hashes:
                raise MigrationFailed(
                    MigrationFailureCode.CNVD_UNCATALOGUED_FILE, resolved_input.position
                )
            cnvd_hashes.add(file_hash)
    if not cnvd_hashes:
        return tuple(inputs), {}
    for snapshot in catalog.snapshots:
        snapshot_files: dict[str, CnvdSnapshotFile] = {}
        for snapshot_file in snapshot.files:
            snapshot_files[snapshot_file.sha256] = snapshot_file
        if cnvd_hashes != snapshot_files.keys():
            continue
        pinned_inputs: list[ResolvedInput] = []
        matched_files: dict[int, CnvdSnapshotFile] = {}
        for resolved_input in inputs:
            if resolved_input.source is StoreSource.CIRCL_CNVD:
                snapshot_file = snapshot_files[resolved_input.input_file.sha256]
                matched_files[resolved_input.position] = snapshot_file
                resolved_input = replace(
                    resolved_input,
                    source_uri=f"{CNVD_RESOLVE_URL}/{snapshot.revision}/{snapshot_file.upstream_path}",
                    cnvd_revision=snapshot.revision,
                )
            pinned_inputs.append(resolved_input)
        return tuple(pinned_inputs), matched_files
    raise MigrationFailed(MigrationFailureCode.CNVD_INCOMPLETE_SNAPSHOT)
