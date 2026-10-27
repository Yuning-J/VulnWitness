"""Turn the manifest's declarations into the import's inputs: resolved files, artifacts,
provenance, a stable order, the import identity and the target's safety (ADR 0008 §2-§4,
§9).
"""

import dataclasses
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cve_kgrag.adapters.migration.input_files import InputFile, inspect_input_file
from cve_kgrag.adapters.migration.migration_limits import MigrationLimits
from cve_kgrag.adapters.store.store_root import (
    StoreRootUnusableError,
    check_store_root,
    lies_in_store_root,
)
from cve_kgrag.domain.corpus_store_manifest import (
    STORE_FORMAT_VERSION,
    NvdArtifact,
    StoreSource,
    read_standard_artifact,
)
from cve_kgrag.domain.hashing import canonical_sha256
from cve_kgrag.domain.migration_inputs import InputDeclaration, InputsManifest
from cve_kgrag.domain.migration_report import MigrationFailed, MigrationFailureCode
from cve_kgrag.domain.provenance import SourceRegistry
from cve_kgrag.domain.search import SCHEMA_VERSION
from cve_kgrag.domain.store_status import is_store_name


@dataclass(frozen=True)
class ResolvedInput:
    """One declared input, found and identified. ``position`` is its place in the inputs
    sorted by source, artifact and file SHA-256, which locates it in reports."""

    position: int
    source: StoreSource
    input_file: InputFile
    artifact: NvdArtifact | None
    source_uri: str
    retrieved_at: datetime

    def sort_key(self) -> tuple[str, str, str, int, str]:
        artifact = self.artifact
        if artifact is None:
            return (self.source.value, "", "", 0, self.input_file.sha256)
        return (
            self.source.value,
            artifact.format.value,
            artifact.series.value,
            artifact.year or 0,
            self.input_file.sha256,
        )


def read_artifact(declaration: InputDeclaration, file_name: str) -> NvdArtifact:
    """The NVD artifact a standard file name gives or the manifest declares; both must
    agree when both exist."""
    standard_artifact = read_standard_artifact(file_name)
    if standard_artifact is None:
        if declaration.artifact is None:
            raise MigrationFailed(MigrationFailureCode.ARTIFACT_UNDECLARED)
        return declaration.artifact
    if declaration.artifact is not None and declaration.artifact != standard_artifact:
        raise MigrationFailed(MigrationFailureCode.ARTIFACT_CONFLICT)
    return standard_artifact


def build_source_uri(
    source: StoreSource, artifact: NvdArtifact | None, source_registry: SourceRegistry
) -> str:
    """The canonical upstream URL of the artifact, from the registry's template."""
    template = source_registry.find_source(source.value).artifact_uri_template
    if template is None:
        raise ValueError(f"the source registry has no artifact URI template for {source}")
    if artifact is None:
        return template
    return template.format(format=artifact.format.value, name=artifact.name_feed())


def resolve_path(path: Path, failure_code: MigrationFailureCode) -> Path:
    """``path`` made absolute with ``..`` and symbolic links resolved; raises
    ``MigrationFailed`` with ``failure_code`` when it cannot be, never naming the path."""
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        # Python before 3.13 raises RuntimeError for a symbolic link loop.
        raise MigrationFailed(failure_code) from None


def resolve_inputs(
    manifest: InputsManifest,
    manifest_dir: Path,
    source_registry: SourceRegistry,
    now: datetime,
    limits: MigrationLimits,
) -> tuple[ResolvedInput, ...]:
    """Every declared input, found, identified and sorted; raises ``MigrationFailed``
    naming the failing declaration by its ``manifest_index``."""
    unsorted_inputs: list[ResolvedInput] = []
    resolved_paths: set[Path] = set()
    file_hashes: set[str] = set()
    for declaration_index, declaration in enumerate(manifest.inputs):
        try:
            path = manifest_dir / declaration.path
            # Opened before it is resolved, so a symbolic link naming the input is refused.
            inspected_file = inspect_input_file(path, limits)
            resolved_path = resolve_path(path, MigrationFailureCode.INPUT_UNREADABLE)
            if resolved_path in resolved_paths:
                raise MigrationFailed(MigrationFailureCode.INPUT_REPEATED)
            if inspected_file.sha256 in file_hashes:
                raise MigrationFailed(MigrationFailureCode.INPUT_BYTES_REPEATED)
            resolved_paths.add(resolved_path)
            file_hashes.add(inspected_file.sha256)
            artifact = None
            if declaration.source is StoreSource.NVD:
                artifact = read_artifact(declaration, resolved_path.name)
            # The manifest refuses a time UTC cannot express.
            retrieved_at = declaration.retrieved_at.astimezone(UTC)
            if retrieved_at > now:
                raise MigrationFailed(MigrationFailureCode.RETRIEVED_IN_FUTURE)
        except MigrationFailed as failure:
            raise MigrationFailed(failure.code, manifest_index=declaration_index) from None
        unsorted_inputs.append(
            ResolvedInput(
                # Renumbered below once every input is known and sorted.
                position=declaration_index,
                source=declaration.source,
                input_file=dataclasses.replace(inspected_file, path=resolved_path),
                artifact=artifact,
                source_uri=build_source_uri(declaration.source, artifact, source_registry),
                retrieved_at=retrieved_at,
            )
        )
    sorted_inputs: list[ResolvedInput] = []
    for position, resolved_input in enumerate(sorted(unsorted_inputs, key=ResolvedInput.sort_key)):
        sorted_inputs.append(dataclasses.replace(resolved_input, position=position))
    return tuple(sorted_inputs)


def digest_registry_entries(source_registry: SourceRegistry) -> str:
    """SHA-256 of the registry entries an import cites: their terms and URL templates."""
    cited_entries: list[object] = []
    for source in StoreSource:
        registry_entry = source_registry.find_source(source.value)
        cited_entries.append(
            {
                "name": registry_entry.name,
                "terms_or_license_url": registry_entry.terms_or_license_url,
                "artifact_uri_template": registry_entry.artifact_uri_template,
            }
        )
    return canonical_sha256(cited_entries)


def compute_import_identity(
    inputs: Sequence[ResolvedInput],
    payload_hashes: Mapping[str, str | None],
    source_registry: SourceRegistry,
    importer_version: str,
) -> str:
    """``import_identity_sha256``: the sorted inputs (file and payload SHA-256, source,
    artifact, container, retrieval instant), the cited registry entries, the importer and
    store format versions and the contract version. No path and no manifest bytes.
    ``payload_hashes`` maps each input file's SHA-256 to its payload's."""
    identity_inputs: list[object] = []
    for resolved_input in inputs:
        identity_inputs.append(
            {
                "source": resolved_input.source.value,
                "artifact": None
                if resolved_input.artifact is None
                else resolved_input.artifact.model_dump(mode="json"),
                "container": resolved_input.input_file.container.value,
                "input_file_sha256": resolved_input.input_file.sha256,
                "payload_sha256": payload_hashes[resolved_input.input_file.sha256],
                "retrieved_at": resolved_input.retrieved_at.isoformat(),
            }
        )
    return canonical_sha256(
        {
            "inputs": identity_inputs,
            "registry": digest_registry_entries(source_registry),
            "importer_version": importer_version,
            "store_format_version": STORE_FORMAT_VERSION,
            "contract_version": SCHEMA_VERSION,
        }
    )


FileIdentity = tuple[int, int]


def read_file_identity(path: Path) -> FileIdentity | None:
    """The device and inode ``path`` names, ``None`` when nothing is there. Comparing
    identities, not spellings, makes two names of one directory match, such as two cases
    of a name on a case-insensitive file system."""
    try:
        path_status = os.stat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError:
        raise MigrationFailed(MigrationFailureCode.TARGET_UNUSABLE) from None
    return (path_status.st_dev, path_status.st_ino)


def lies_within(path: Path, directory: Path) -> bool:
    """Whether ``path`` is ``directory`` or lies under it, by file identity; a path that
    does not exist lies where its nearest existing ancestor does."""
    directory_identity = read_file_identity(directory)
    if directory_identity is None:
        return False
    for candidate in (path, *path.parents):
        if read_file_identity(candidate) == directory_identity:
            return True
    return False


def check_target_parent(target: Path) -> None:
    """The resolved target's parent is a directory the run can create entries in; raises
    ``MigrationFailed`` (``target_unusable``) otherwise, dry run included, so a dry run
    fails where a real run would."""
    parent = target.parent
    if not parent.is_dir() or not os.access(parent, os.W_OK | os.X_OK):
        raise MigrationFailed(MigrationFailureCode.TARGET_UNUSABLE)


def check_target_in_store_root(target: Path, store_root: Path | None) -> None:
    """A target the store root holds is a store directly under it with a valid name, so
    a migration never writes into an existing store, and a root that serving would
    refuse is refused here too, before anything is written (ADR 0009 §4). The resolved
    target is compared with the root by file identity, never by resolving the root's
    path, so a root that cannot be found, a symbolic-link loop included, holds no target;
    a target outside the root is not checked against it. Raises ``MigrationFailed``."""
    if store_root is None or not lies_in_store_root(target, store_root):
        return
    try:
        check_store_root(store_root)
    except StoreRootUnusableError:
        raise MigrationFailed(MigrationFailureCode.STORE_ROOT_UNUSABLE) from None
    is_root_child = read_file_identity(target.parent) == read_file_identity(store_root)
    if not is_root_child or not is_store_name(target.name):
        raise MigrationFailed(MigrationFailureCode.TARGET_IN_STORE_ROOT)


def check_target(
    target: Path,
    manifest_path: Path,
    inputs: Sequence[ResolvedInput],
    legacy_root: Path | None,
) -> None:
    """The target neither is, holds nor lies inside the manifest, an input or the legacy
    root, and its parent holds no input. Every path is resolved, ``..`` and symbolic links
    included, and compared by file identity. Raises ``MigrationFailed``."""
    protected_paths = [manifest_path]
    for resolved_input in inputs:
        protected_paths.append(resolved_input.input_file.path)
    if legacy_root is not None:
        protected_paths.append(legacy_root)
    for protected_path in protected_paths:
        if lies_within(target, protected_path) or lies_within(protected_path, target):
            raise MigrationFailed(MigrationFailureCode.TARGET_OVERLAPS_INPUT)
    target_parent_identity = read_file_identity(target.parent)
    for resolved_input in inputs:
        if read_file_identity(resolved_input.input_file.path.parent) == target_parent_identity:
            raise MigrationFailed(MigrationFailureCode.TARGET_PARENT_HOLDS_INPUT)
