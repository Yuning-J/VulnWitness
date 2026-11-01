# Stays empty: the core-only check imports every module through pkgutil.walk_packages,
# which imports this package, and a core install has no MCP SDK.
