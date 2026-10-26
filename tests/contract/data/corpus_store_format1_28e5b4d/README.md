# Format-1 compatibility store

`store/` is a corpus store of store format 1, written by the importer at commit `28e5b4d`
(contract version `2.0.0-dev.25`), the last release before stores were served. It guards
format 1 (ADR 0009 §15): `tests/contract/test_store_format_compatibility.py` pins the
SHA-256 of every file in it and requires the current reader to verify and load it whole,
so a reader change that stops reading what that importer wrote fails the test.

- Written by `build_store.py`, run once from a checkout of `28e5b4d` with
  `python build_store.py WORK_DIR`; its import report gave `outcome: imported` and
  `store_manifest_sha256` `c17f09856dc00eaf75a97dba788dc8154bb36714ada7e9a6a2fb56b8e798702f`.
- Never regenerate it with a later importer and never edit its bytes: a store a later
  importer wrote proves nothing about reading the stores already written. A store format
  change adds a new compatibility store beside this one.
- Every record is synthetic (`CVE-9999-*`, a fictional vendor). The inputs were authored
  with `tests/support/legacy_inputs.py` so that, for each field the store persists, it
  holds every value the importer at `28e5b4d` can write, a KEV entry included, and nothing
  it could not write. The source URIs are the canonical NVD and CISA artifact URLs the
  importer cites; no data was downloaded from them.
