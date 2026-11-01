"""The installed distribution, which names the code that wrote a result."""

import importlib.metadata

DISTRIBUTION_NAME = "vulnwitness"


def read_installed_version() -> str:
    return importlib.metadata.version(DISTRIBUTION_NAME)
