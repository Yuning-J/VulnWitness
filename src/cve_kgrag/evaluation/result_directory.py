"""Where a planner evaluation writes its evidence sets and report."""

import os
import tempfile
from pathlib import Path


class ResultDirectory:
    """A new directory, readable by its owner only, whose files are each written once."""

    def __init__(self, path: Path) -> None:
        self.path = path

    @classmethod
    def create(cls, output_dir: Path) -> "ResultDirectory":
        """A new ``planner-*`` directory under ``output_dir``, which is created when missing
        but never its parents. Raises ``OSError`` when either cannot be made."""
        output_dir.mkdir(mode=0o700, exist_ok=True)
        return cls(Path(tempfile.mkdtemp(prefix="planner-", dir=output_dir)))

    def write(self, relative_path: str, content: bytes) -> None:
        """Write ``content`` to a file that must not exist yet, readable by its owner only."""
        file_path = self.path / relative_path
        file_path.parent.mkdir(mode=0o700, exist_ok=True)
        file_descriptor = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(file_descriptor, "wb") as result_file:
            result_file.write(content)
