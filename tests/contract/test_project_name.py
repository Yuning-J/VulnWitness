"""Project names in tracked files, with explicit evidence and historical exceptions."""

import subprocess
from collections.abc import Sequence
from fnmatch import fnmatchcase
from pathlib import Path

import pytest

from tests.support.paths import REPOSITORY_ROOT

# Join name components so the guard can scan its own source without exempting itself.
FORBIDDEN_NAMES = (
    b"cve" + b"-kgrag",
    b"cve" + b"_kgrag",
    b"CVE" + b"_KGRAG",
    b"telecom-cve" + b"-kgrag",
)
PATH_EXCEPTIONS = {
    "eval/gold/m7b_cases.yaml": "Holdout cases; never read by the name guard.",
    "eval/gold/m7b_sets.json": "Holdout sets; never read by the name guard.",
    "docs/rebuild/m7b-work-packages.md": "Holdout work packages; never read by the name guard.",
    "docs/rebuild/m7b-results-*.md": "Holdout results; never read by the name guard.",
    "tests/contract/data/**": "Recorded compatibility and third-party data have pinned bytes.",
    "src/vulnwitness/fixtures/**": "Packaged data and notices are pinned by fixture manifests.",
    "plugins/vulnwitness/skills/vulnwitness-investigation/examples/findings.example.yaml": (
        "Recorded findings retain evidence IDs and their original reproduction commands."
    ),
    "docs/rebuild/m6-exit-audit.md": "Dated M6 exit audit records the commands verified then.",
    "docs/rebuild/provenance.md": "Split provenance records historical paths and commit subjects.",
}
PINNED_REFERENCES = {
    "src/vulnwitness/adapters/fixture/synthetic_fixture.py": (
        b"urn:cve" + b"-kgrag:fixture:",
        "The synthetic source URI binds the evidence IDs in recorded findings.",
    ),
}


def find_name_violations(repository_root: Path, relative_paths: Sequence[str]) -> list[str]:
    """Find names in paths and bytes without opening any exempted data or record."""
    violations: list[str] = []
    for relative_path in relative_paths:
        if any(fnmatchcase(relative_path, pattern) for pattern in PATH_EXCEPTIONS):
            continue
        path = repository_root / relative_path
        if not path.is_file():
            continue
        content = path.read_bytes()
        pinned_reference = PINNED_REFERENCES.get(relative_path)
        if pinned_reference is not None:
            content = content.replace(pinned_reference[0], b"", 1)
        if any(name in relative_path.encode() or name in content for name in FORBIDDEN_NAMES):
            violations.append(relative_path)
    return violations


def test_tracked_files_use_project_name_outside_documented_exceptions() -> None:
    # Include unstaged additions so the guard also covers a package move in a worktree.
    tracked_paths = (
        subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            check=True,
        )
        .stdout.decode()
        .split("\0")
    )

    violations = find_name_violations(REPOSITORY_ROOT, tracked_paths)

    assert violations == [], "Unexpected project names in: " + ", ".join(violations)


@pytest.mark.parametrize("name", FORBIDDEN_NAMES)
def test_guard_reports_each_forbidden_name_in_file_bytes(tmp_path: Path, name: bytes) -> None:
    source_path = tmp_path / "source.py"
    source_path.write_bytes(name)

    violations = find_name_violations(tmp_path, ["source.py"])

    assert violations == ["source.py"]


def test_pinned_reference_exempts_only_one_uri_in_its_named_file(tmp_path: Path) -> None:
    relative_path, (uri, _) = next(iter(PINNED_REFERENCES.items()))
    source_path = tmp_path / relative_path
    source_path.parent.mkdir(parents=True)
    source_path.write_bytes(uri + b"\n" + FORBIDDEN_NAMES[0])

    violations = find_name_violations(tmp_path, [relative_path])

    assert violations == [relative_path]
