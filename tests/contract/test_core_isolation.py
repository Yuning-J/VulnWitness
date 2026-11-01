"""The core distribution stays light and its layers point inward."""

import ast
import json
import subprocess
import sys
from importlib.metadata import requires
from pathlib import Path

import pytest

import vulnwitness
from tests.support.module_walk import IMPORT_EVERY_MODULE

PACKAGE_DIR = Path(vulnwitness.__file__).resolve().parent
HEAVY_OR_OPTIONAL_MODULES = (
    "anyio",
    "chromadb",
    "fastapi",
    "gradio",
    "httpx",
    "httpx2",
    "mcp",
    "mcp_types",
    "neo4j",
    "networkx",
    "numpy",
    "pandas",
    "requests",
    "sentence_transformers",
    "sse_starlette",
    "starlette",
    "torch",
    "transformers",
    "uvicorn",
)
# Modules each layer may not import: an inner layer imports no outer one, and the
# interfaces import neither the composition root, adapter discovery, adapters nor the CLI.
FORBIDDEN_IMPORTS_BY_LAYER = {
    "domain": (
        "vulnwitness.ports",
        "vulnwitness.application",
        "vulnwitness.adapters",
        "vulnwitness.cli",
        "vulnwitness.composition",
        "vulnwitness.interfaces",
    ),
    "ports": (
        "vulnwitness.application",
        "vulnwitness.adapters",
        "vulnwitness.cli",
        "vulnwitness.composition",
        "vulnwitness.interfaces",
    ),
    "topics": (
        "vulnwitness.application",
        "vulnwitness.adapters",
        "vulnwitness.cli",
        "vulnwitness.composition",
        "vulnwitness.interfaces",
    ),
    "application": (
        "vulnwitness.adapters",
        "vulnwitness.cli",
        "vulnwitness.composition",
        "vulnwitness.interfaces",
    ),
    "interfaces": (
        "vulnwitness.adapters",
        "vulnwitness.adapter_discovery",
        "vulnwitness.cli",
        "vulnwitness.composition",
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
    for requirement in requires("vulnwitness") or []:
        if ";" not in requirement:
            core_requirements.append(requirement)
    assert core_requirements == ["pydantic<3,>=2.12", "pyyaml<7,>=6.0.2"]


def test_importing_every_core_module_loads_no_heavy_or_optional_dependency() -> None:
    import_script = (
        IMPORT_EVERY_MODULE + "import json, sys\nprint(json.dumps(sorted(sys.modules)))\n"
    )

    completed = subprocess.run(
        [sys.executable, "-c", import_script], capture_output=True, text=True, check=True
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
        ("import vulnwitness.adapter_discovery", "vulnwitness.adapter_discovery"),
        ("from vulnwitness import adapter_discovery", "vulnwitness.adapter_discovery"),
        ("from vulnwitness.adapters import fixture", "vulnwitness.adapters.fixture"),
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
