"""Offline fixture feeds exercise the operator refresh and its activation boundary."""

import gzip
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.support.cnvd_inputs import (
    TEST_REVISION,
    build_cnvd_row,
    build_test_catalog,
    write_cnvd_file,
)
from tests.support.corpus_stores import import_store, read_active_bytes
from tests.support.legacy_inputs import (
    build_declaration,
    build_kev_row,
    build_v2_entry,
    build_v2_feed,
    write_gzip_feed,
    write_inputs_manifest,
    write_kev_csv,
)
from vulnwitness.adapters.store.active_store import load_active_store
from vulnwitness.cli import main
from vulnwitness.domain.hashing import sha256_hex

REFRESH_SCRIPT = Path(__file__).resolve().parents[2] / "scripts/operator/refresh_store.py"


@pytest.fixture
def store_root(tmp_path: Path) -> Path:
    store_root = tmp_path / "stores"
    store_root.mkdir()
    import_store(store_root, "previous")
    assert (
        main(
            ["store", "activate", "previous"],
            environment={"VULNWITNESS_STORE_ROOT": str(store_root)},
        )
        == 0
    )
    return store_root


@pytest.fixture
def input_manifest(tmp_path: Path) -> Path:
    inputs = tmp_path / "local-feeds"
    inputs.mkdir()
    write_gzip_feed(inputs / "nvdcve-2.0-2099.json.gz", build_v2_feed([build_v2_entry(3)]))
    write_kev_csv(inputs / "kev.csv", [build_kev_row(3)])
    return write_inputs_manifest(
        inputs,
        [
            build_declaration("nvdcve-2.0-2099.json.gz"),
            build_declaration("kev.csv", source="cisa-kev"),
        ],
    )


def run_refresh(
    store_root: Path,
    arguments: list[str],
    *,
    executable_dir: Path | None = None,
    refresh_script: Path = REFRESH_SCRIPT,
) -> subprocess.CompletedProcess[str]:
    uv = shutil.which("uv")
    assert uv is not None
    environment = {
        "PATH": f"{Path(uv).parent}:{os.defpath}",
        "PYTHONPATH": str(refresh_script.parents[2] / "src"),
        "UV_CACHE_DIR": str(store_root.parent / "uv-cache"),
        "UV_OFFLINE": "1",
        "VULNWITNESS_STORE_ROOT": str(store_root),
    }
    if executable_dir is not None:
        environment["PATH"] = f"{executable_dir}:{environment['PATH']}"
    return subprocess.run(
        [sys.executable, str(refresh_script), *arguments],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def read_active_cve_ids(store_root: Path) -> list[str]:
    cve_ids: list[str] = []
    for record in load_active_store(store_root).records:
        cve_ids.append(record.cve_id)
    return cve_ids


def test_local_manifest_refresh_activates_verified_store_and_preserves_rollback(
    store_root: Path, input_manifest: Path
) -> None:
    # Arrange
    environment = {"VULNWITNESS_STORE_ROOT": str(store_root)}

    # Act
    refresh = run_refresh(
        store_root, ["--inputs", str(input_manifest), "--store", "current", "--activate"]
    )
    active_cve_ids = read_active_cve_ids(store_root)
    rollback_exit = main(["store", "rollback"], environment=environment)
    restored_cve_ids = read_active_cve_ids(store_root)

    # Assert
    assert refresh.returncode == 0, refresh.stdout + refresh.stderr
    assert active_cve_ids == ["CVE-9999-0003"]
    assert "Restart API and MCP services" in refresh.stdout
    assert "store rollback" in refresh.stdout
    assert rollback_exit == 0
    assert restored_cve_ids == [
        "CVE-9999-0001",
        "CVE-9999-0002",
    ]


def test_import_without_activation_flag_keeps_active_record(
    store_root: Path, input_manifest: Path
) -> None:
    # Arrange
    active_before = read_active_bytes(store_root)

    # Act
    refresh = run_refresh(store_root, ["--inputs", str(input_manifest), "--store", "current"])

    # Assert
    assert refresh.returncode == 0, refresh.stdout + refresh.stderr
    assert (store_root / "current" / "manifest.json").is_file()
    assert read_active_bytes(store_root) == active_before
    assert "activation requires: vulnwitness store activate current" in refresh.stdout


def test_failed_import_keeps_active_record(store_root: Path, input_manifest: Path) -> None:
    # Arrange
    active_before = read_active_bytes(store_root)
    (input_manifest.parent / "nvdcve-2.0-2099.json.gz").write_bytes(b"invalid gzip")

    # Act
    refresh = run_refresh(
        store_root, ["--inputs", str(input_manifest), "--store", "current", "--activate"]
    )

    # Assert
    assert refresh.returncode != 0
    assert read_active_bytes(store_root) == active_before
    assert not (store_root / "current").exists()
    assert "Verifying and activating" not in refresh.stdout


@pytest.mark.parametrize("store_name", ["../outside", "ACTIVE", "previous"])
def test_invalid_or_existing_target_is_refused_before_fetch(
    store_root: Path, tmp_path: Path, store_name: str
) -> None:
    # Arrange
    active_before = read_active_bytes(store_root)
    feeds = tmp_path / "downloads"

    # Act
    refresh = run_refresh(
        store_root, ["--feeds-dir", str(feeds), "--store", store_name, "--activate"]
    )

    # Assert
    assert refresh.returncode == 2
    assert not feeds.exists()
    assert read_active_bytes(store_root) == active_before


def write_fixture_download_commands(executable_dir: Path, input_manifest: Path) -> Path:
    """Stub curl/sleep and copy the checkout with a synthetic catalog for fetch and import."""
    executable_dir.mkdir()
    feed_dir = input_manifest.parent
    cnvd_files = [
        write_cnvd_file(feed_dir, "part-0.parquet", [build_cnvd_row(3)]),
        write_cnvd_file(feed_dir, "part-1.parquet", [build_cnvd_row(4)]),
    ]
    catalog = build_test_catalog(cnvd_files, [1, 1])
    checkout = executable_dir.parent / "checkout"
    shutil.copytree(
        REFRESH_SCRIPT.parents[2] / "src",
        checkout / "src",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    shutil.copytree(REFRESH_SCRIPT.parent, checkout / "scripts" / "operator")
    (checkout / "pyproject.toml").symlink_to(REFRESH_SCRIPT.parents[2] / "pyproject.toml")
    (checkout / ".venv").symlink_to(Path(sys.executable).parent.parent)
    (checkout / "src/vulnwitness/knowledge/cnvd_snapshots.yaml").write_text(
        yaml.safe_dump(catalog.model_dump(mode="json"))
    )
    nvd_bytes = gzip.decompress((feed_dir / "nvdcve-2.0-2099.json.gz").read_bytes())
    feed_names = ["modified"]
    for year in range(2002, 2100):
        feed_names.append(str(year))
    for padding_size, feed_name in enumerate(feed_names):
        feed_bytes = nvd_bytes + b" " * padding_size
        file_stem = f"nvdcve-2.0-{feed_name}"
        (feed_dir / f"{file_stem}.json.gz").write_bytes(gzip.compress(feed_bytes, mtime=0))
        (feed_dir / f"{file_stem}.meta").write_text(f"sha256:{sha256_hex(feed_bytes)}\n")
    curl = executable_dir / "curl"
    curl.write_text(
        "#!/bin/bash\nset -eu\n"
        f"fixture_dir={shlex.quote(str(feed_dir))}\n"
        'url="${!#}"\n'
        'case "$url" in\n'
        "  https://nvd.nist.gov/feeds/json/cve/2.0/*.meta) "
        'cat "$fixture_dir/${url##*/}"; exit 0;;\n'
        '  https://nvd.nist.gov/feeds/json/cve/2.0/*.json.gz) source="${url##*/}";;\n'
        "  https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv) "
        "source=kev.csv;;\n"
        "  https://huggingface.co/datasets/CIRCL/Vulnerability-CNVD/"
        f"resolve/{TEST_REVISION}/data/part-*.parquet) "
        'source="${url##*/}";;\n'
        "  *) exit 77;;\n"
        'esac\nwhile [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = -o ]; then cp "$fixture_dir/$source" "$2"; exit 0; fi\n'
        "  shift\ndone\nexit 78\n"
    )
    curl.chmod(0o755)
    sleep = executable_dir / "sleep"
    sleep.write_text("#!/bin/sh\nexit 0\n")
    sleep.chmod(0o755)
    return checkout / "scripts/operator/refresh_store.py"


def test_fixture_downloads_are_checked_imported_and_activated(
    store_root: Path, input_manifest: Path, tmp_path: Path
) -> None:
    # Arrange
    commands = tmp_path / "commands"
    refresh_script = write_fixture_download_commands(commands, input_manifest)
    feeds = tmp_path / "downloads"

    # Act
    refresh = run_refresh(
        store_root,
        ["--feeds-dir", str(feeds), "--store", "current", "--activate"],
        executable_dir=commands,
        refresh_script=refresh_script,
    )

    # Assert
    assert refresh.returncode == 0, refresh.stdout + refresh.stderr
    assert (feeds / "inputs.yaml").is_file()
    assert (feeds / "provenance.tsv").is_file()
    assert read_active_cve_ids(store_root) == ["CVE-9999-0003"]
    active_store = load_active_store(store_root)
    assert active_store.records[0].cnvd[0].cnvd_id == "CNVD-9999-00003"
    manifest = yaml.safe_load((feeds / "inputs.yaml").read_text())
    cnvd_inputs = []
    for declaration in manifest["inputs"]:
        if declaration["source"] == "circl-cnvd":
            cnvd_inputs.append(declaration)
    assert len(cnvd_inputs) == 2
    provenance = (feeds / "provenance.tsv").read_text()
    for index, declaration in enumerate(cnvd_inputs):
        assert declaration["path"] == f"part-{index}.parquet"
        assert declaration["retrieved_at"].endswith("Z")
        assert (
            f"part-{index}.parquet\thttps://huggingface.co/datasets/CIRCL/Vulnerability-CNVD/"
            f"resolve/{TEST_REVISION}/data/part-{index}.parquet\t{declaration['retrieved_at']}\t"
        ) in provenance


def test_download_digest_mismatch_stops_before_import_and_activation(
    store_root: Path, input_manifest: Path, tmp_path: Path
) -> None:
    # Arrange
    commands = tmp_path / "commands"
    refresh_script = write_fixture_download_commands(commands, input_manifest)
    (input_manifest.parent / "nvdcve-2.0-2002.meta").write_text(f"sha256:{'0' * 64}\n")
    active_before = read_active_bytes(store_root)
    feeds = tmp_path / "downloads"

    # Act
    refresh = run_refresh(
        store_root,
        ["--feeds-dir", str(feeds), "--store", "current", "--activate"],
        executable_dir=commands,
        refresh_script=refresh_script,
    )

    # Assert
    assert refresh.returncode != 0
    assert "does not match the SHA-256" in refresh.stderr
    assert not (feeds / "inputs.yaml").exists()
    assert not (store_root / "current").exists()
    assert read_active_bytes(store_root) == active_before


@pytest.mark.parametrize("file_name", ["part-0.parquet", "part-1.parquet"])
def test_cnvd_digest_mismatch_publishes_no_manifest_and_keeps_active_store(
    store_root: Path, input_manifest: Path, tmp_path: Path, file_name: str
) -> None:
    # Arrange
    commands = tmp_path / "commands"
    refresh_script = write_fixture_download_commands(commands, input_manifest)
    (input_manifest.parent / file_name).write_bytes(b"SYNTHETIC: mismatched CNVD download")
    active_before = read_active_bytes(store_root)
    feeds = tmp_path / "downloads"

    # Act
    refresh = run_refresh(
        store_root,
        ["--feeds-dir", str(feeds), "--store", "current", "--activate"],
        executable_dir=commands,
        refresh_script=refresh_script,
    )

    # Assert
    assert refresh.returncode != 0
    assert f"{file_name} does not match the SHA-256 in the CNVD catalog" in refresh.stderr
    assert not (feeds / "inputs.yaml").exists()
    assert not (feeds / "provenance.tsv").exists()
    assert not (store_root / "current").exists()
    assert read_active_bytes(store_root) == active_before
