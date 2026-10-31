"""Fetch or reuse feeds, import a fresh store, and optionally activate it explicitly."""

import argparse
import os
import subprocess
from pathlib import Path

from pydantic import TypeAdapter, ValidationError

from cve_kgrag.adapters.store.store_root import StoreRootUnusableError, check_store_root
from cve_kgrag.cli import main as run_command
from cve_kgrag.domain.store_status import StoreName
from cve_kgrag.settings import SettingsError, load_settings


def main() -> int:
    """Reuse the importer and activation checks; stop at the first failed step."""
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument(
        "--feeds-dir", type=Path, help="fetch official feeds into a fresh directory"
    )
    inputs.add_argument("--inputs", type=Path, help="reuse an existing local input manifest")
    parser.add_argument(
        "--store", required=True, help="fresh store name under CVE_KGRAG_STORE_ROOT"
    )
    parser.add_argument("--activate", action="store_true", help="activate the imported store")
    arguments = parser.parse_args()
    environment = dict(os.environ)
    try:
        settings = load_settings(environment)
        store_name = TypeAdapter(StoreName).validate_python(arguments.store)
    except (SettingsError, ValidationError) as error:
        parser.error(str(error))
    if settings.store_root is None:
        parser.error("CVE_KGRAG_STORE_ROOT is required")
    try:
        check_store_root(settings.store_root)
    except StoreRootUnusableError:
        parser.error("store_root_unusable")
    target = settings.store_root / store_name
    if os.path.lexists(target):
        parser.error("target already exists; choose a fresh store name")
    manifest_path = arguments.inputs
    if arguments.feeds_dir is not None:
        print("Fetching feeds and checking NVD metadata digests.", flush=True)
        fetch_script = Path(__file__).with_name("fetch_feeds.sh")
        try:
            subprocess.run(["bash", str(fetch_script), str(arguments.feeds_dir)], check=True)
        except subprocess.CalledProcessError as error:
            return error.returncode
        manifest_path = arguments.feeds_dir / "inputs.yaml"
    print(f"Importing store {store_name}.", flush=True)
    import_exit = run_command(
        ["migrate", "legacy", "--inputs", str(manifest_path), "--target", str(target)],
        environment=environment,
    )
    if import_exit != 0:
        return import_exit
    if not arguments.activate:
        print(f"Imported {store_name}; activation requires: cve-kgrag store activate {store_name}")
        return 0
    print(f"Verifying and activating store {store_name}.", flush=True)
    activation_exit = run_command(["store", "activate", store_name], environment=environment)
    if activation_exit == 0:
        print(f"Activated {store_name}. Restart API and MCP services to serve it.")
        print("To reverse activation: cve-kgrag store rollback; then restart services.")
    return activation_exit


if __name__ == "__main__":
    raise SystemExit(main())
