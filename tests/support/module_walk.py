"""Scripts that import every core module of ``vulnwitness`` in a fresh interpreter."""

# Modules that import an optional extra, loaded only through an entry point: the semantic
# adapter, every module of the MCP server, HTTP, REST and UI packages (not the
# packages themselves, which stay empty), the shared anyio readiness signal, and
# the importer's JSON and Parquet parsers.
OPTIONAL_MODULE_PREFIXES = (
    "vulnwitness.adapters.semantic.chroma_retriever",
    "vulnwitness.interfaces.mcp.",
    "vulnwitness.interfaces.http.",
    "vulnwitness.interfaces.rest.",
    "vulnwitness.interfaces.ui.",
    "vulnwitness.interfaces.data_readiness",
    "vulnwitness.adapters.migration.ijson_events",
    "vulnwitness.adapters.migration.json_fingerprint",
    "vulnwitness.adapters.migration.nvd_feed_reader",
    "vulnwitness.adapters.migration.cnvd_parquet_reader",
)
# Imports each core module; a package that fails to import fails the script instead of
# being skipped, which is what walk_packages does without an onerror.
IMPORT_EVERY_MODULE = f"""
import importlib, pkgutil
import vulnwitness

def reraise_import_error(package_name):
    raise

for module_info in pkgutil.walk_packages(
    vulnwitness.__path__, "vulnwitness.", onerror=reraise_import_error
):
    if module_info.name.startswith({OPTIONAL_MODULE_PREFIXES!r}):
        continue
    importlib.import_module(module_info.name)
"""
# Records, through an audit hook installed before any import, every write to the file
# system, network use and process start; it prints them as JSON at the end.
RECORD_SIDE_EFFECTS = """
import json, os, sys

WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
WRITE_EVENTS = frozenset({
    "os.mkdir", "os.rename", "os.remove", "os.rmdir", "os.symlink", "os.link",
    "os.truncate", "os.chmod", "os.chown", "os.utime", "shutil.copyfile", "shutil.rmtree",
})
NETWORK_EVENTS = frozenset({
    "socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg", "socket.getaddrinfo",
    "socket.gethostbyname", "socket.gethostbyaddr", "socket.getnameinfo",
})
PROCESS_EVENTS = frozenset({
    "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.fork", "os.forkpty",
    "os.spawn",
})
side_effects = []

def record_side_effect(event, arguments):
    if event == "open":
        path, mode, flags = arguments
        if isinstance(mode, str):
            writes = any(character in mode for character in "wax+")
        else:
            writes = isinstance(flags, int) and bool(flags & WRITE_FLAGS)
        if writes:
            side_effects.append(f"open {path!r} for writing")
    elif event in WRITE_EVENTS or event in NETWORK_EVENTS or event in PROCESS_EVENTS:
        side_effects.append(event)

sys.addaudithook(record_side_effect)
"""
PRINT_SIDE_EFFECTS = """
print(json.dumps(side_effects))
"""
