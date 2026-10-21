"""An in-memory registry of installed entry points, standing in for importlib.metadata."""

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from cve_kgrag.adapter_discovery import AdapterEntryPoint


@dataclass(frozen=True)
class FakeDistribution:
    version: str = "1.0.0"


def load_nothing() -> object:
    """A loader for an entry point no test loads."""
    raise AssertionError("this entry point is never loaded")


@dataclass
class FakeEntryPoint:
    """An entry point named ``name`` whose ``load`` returns what ``loader`` returns."""

    name: str
    loader: Callable[[], object] = load_nothing
    value: str = "tests.support.entry_points:load_nothing"
    dist: FakeDistribution | None = field(default_factory=FakeDistribution)

    def load(self) -> object:
        return self.loader()


@dataclass
class FakeAdapterRegistry:
    """Lists ``entry_points`` and records that it was listed."""

    entry_points: list[FakeEntryPoint] = field(default_factory=list)
    is_listed: bool = False

    def list_adapters(self) -> Iterable[AdapterEntryPoint]:
        self.is_listed = True
        return self.entry_points


@dataclass(frozen=True)
class FailingRegistry:
    """A registry whose listing fails with ``message``, as unreadable metadata might."""

    message: str

    def list_adapters(self) -> Iterable[AdapterEntryPoint]:
        raise OSError(self.message)
