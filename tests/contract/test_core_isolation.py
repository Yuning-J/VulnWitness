"""The core distribution stays light and its layers point inward."""

import ast
import json
import subprocess
import sys
from importlib.metadata import requires
from pathlib import Path

import pytest

import cve_kgrag

PACKAGE_DIR = Path(cve_kgrag.__file__).resolve().parent
HEAVY_OR_OPTIONAL_MODULES = (
    "anyio",
    "chromadb",
    "fastapi",
    "gradio",
    "httpx",
    "mcp",
    "mcp_types",
    "neo4j",
    "networkx",
    "numpy",
    "pandas",
    "requests",
    "sentence_transformers",
    "starlette",
    "torch",
    "transformers",
    "uvicorn",
)
# Modules that import an optional extra, loaded only through an entry point: the semantic
# adapter, and every module of the MCP server package (not the package itself, which stays
# empty).
OPTIONAL_MODULE_PREFIXES = (
    "cve_kgrag.adapters.semantic.chroma_retriever",
    "cve_kgrag.interfaces.mcp.",
)
IMPORT_EVERY_MODULE = f"""
import importlib, json, pkgutil, sys
import cve_kgrag
for module_info in pkgutil.walk_packages(cve_kgrag.__path__, "cve_kgrag."):
    if module_info.name.startswith({OPTIONAL_MODULE_PREFIXES!r}):
        continue
    importlib.import_module(module_info.name)
print(json.dumps(sorted(sys.modules)))
"""
# Modules each layer may not import: an inner layer imports no outer one, and the
# interfaces import neither the composition root, adapter discovery, adapters nor the CLI.
FORBIDDEN_IMPORTS_BY_LAYER = {
    "domain": (
        "cve_kgrag.ports",
        "cve_kgrag.application",
        "cve_kgrag.adapters",
        "cve_kgrag.cli",
        "cve_kgrag.composition",
        "cve_kgrag.interfaces",
    ),
    "ports": (
        "cve_kgrag.application",
        "cve_kgrag.adapters",
        "cve_kgrag.cli",
        "cve_kgrag.composition",
        "cve_kgrag.interfaces",
    ),
    "topics": (
        "cve_kgrag.application",
        "cve_kgrag.adapters",
        "cve_kgrag.cli",
        "cve_kgrag.composition",
        "cve_kgrag.interfaces",
    ),
    "application": (
        "cve_kgrag.adapters",
        "cve_kgrag.cli",
        "cve_kgrag.composition",
        "cve_kgrag.interfaces",
    ),
    "interfaces": (
        "cve_kgrag.adapters",
        "cve_kgrag.adapter_discovery",
        "cve_kgrag.cli",
        "cve_kgrag.composition",
    ),
}


def list_imported_modules(source_text: str) -> list[str]:
    """Every module an absolute import in ``source_text`` names. ``from package import
    name`` also counts as importing ``package.name``, since the name may be a submodule."""
    imported_modules: list[str] = []
    for node in ast.walk(ast.parse(source_text)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.append(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module is not None:
            imported_modules.append(node.module)
            for alias in node.names:
                imported_modules.append(f"{node.module}.{alias.name}")
    return imported_modules


def list_relative_imports(source_text: str) -> list[int]:
    """The line of every relative import in ``source_text``."""
    relative_import_lines: list[int] = []
    for node in ast.walk(ast.parse(source_text)):
        if isinstance(node, ast.ImportFrom) and node.level > 0:
            relative_import_lines.append(node.lineno)
    return relative_import_lines


def test_core_distribution_depends_only_on_pydantic_and_pyyaml() -> None:
    core_requirements: list[str] = []
    for requirement in requires("cve-kgrag") or []:
        if ";" not in requirement:
            core_requirements.append(requirement)
    assert core_requirements == ["pydantic<3,>=2.9", "pyyaml<7,>=6.0.2"]


def test_importing_every_core_module_loads_no_heavy_or_optional_dependency() -> None:
    completed = subprocess.run(
        [sys.executable, "-c", IMPORT_EVERY_MODULE], capture_output=True, text=True, check=True
    )

    loaded_top_level: set[str] = set()
    for module_name in json.loads(completed.stdout):
        loaded_top_level.add(module_name.split(".")[0])
    assert loaded_top_level.isdisjoint(HEAVY_OR_OPTIONAL_MODULES)


def test_inner_layers_never_import_outer_layers() -> None:
    violations: list[str] = []
    for layer, forbidden_prefixes in FORBIDDEN_IMPORTS_BY_LAYER.items():
        for source_file in sorted((PACKAGE_DIR / layer).rglob("*.py")):
            for imported_module in list_imported_modules(source_file.read_text()):
                if imported_module.startswith(forbidden_prefixes):
                    violations.append(
                        f"{source_file.relative_to(PACKAGE_DIR)} imports {imported_module}"
                    )
    assert violations == []


@pytest.mark.parametrize(
    ("source_text", "imported_module"),
    [
        ("import cve_kgrag.adapter_discovery", "cve_kgrag.adapter_discovery"),
        ("from cve_kgrag import adapter_discovery", "cve_kgrag.adapter_discovery"),
        ("from cve_kgrag.adapters import fixture", "cve_kgrag.adapters.fixture"),
    ],
    ids=["dotted_import", "from_package_import_module", "from_subpackage_import_module"],
)
def test_import_of_a_module_by_any_absolute_spelling_is_recorded(
    source_text: str, imported_module: str
) -> None:
    imported_modules = list_imported_modules(source_text)

    assert imported_module in imported_modules


def test_no_core_module_uses_a_relative_import() -> None:
    """A relative import would escape the layer check, which reads absolute names only."""
    relative_imports: list[str] = []
    for source_file in sorted(PACKAGE_DIR.rglob("*.py")):
        for line_number in list_relative_imports(source_file.read_text()):
            relative_imports.append(f"{source_file.relative_to(PACKAGE_DIR)}:{line_number}")

    assert relative_imports == []
