"""Proves the store operations (ADR 0009 §4-§8): a store is recorded active only once it
verifies, under the manifest digest that verification read; the store active before it
becomes the one rollback lands on; rollback is one level and verifies its target again;
an unreadable ``ACTIVE`` is refused and left as it is; the root's lock keeps two
operations apart; and every failing point of the write either leaves ``ACTIVE`` as it was
(``active_write_failed``) or says the outcome is unknown (``active_write_unconfirmed``).
"""

import fcntl
import hashlib
import json
import os
import stat
from collections.abc import Callable
from pathlib import Path

import pytest

from cve_kgrag.adapters.store.active_record import (
    MAX_ACTIVE_BYTES,
    ActiveRecordUnreadableError,
    read_active_record,
)
from cve_kgrag.adapters.store.active_record_writer import OsActiveRecordFiles, hold_store_lock
from cve_kgrag.adapters.store.corpus_store import verify_corpus_store
from cve_kgrag.adapters.store.store_activation import StoreActivation
from cve_kgrag.domain.search import SCHEMA_VERSION
from cve_kgrag.domain.store_status import (
    ActiveRecordState,
    ActiveStoreCondition,
    StoreCondition,
    StoreOperationFailed,
    StoreOperationFailure,
)
from tests.support.corpus_stores import (
    ROOT_BREAKERS,
    FailingActiveRecordFiles,
    copy_compatibility_store,
    declare_later_format,
    import_store,
    list_hidden_entries,
    move_store,
    read_active_bytes,
    rewrite_manifest,
    tamper_with_records,
)


@pytest.fixture
def store_activation(store_root: Path) -> StoreActivation:
    return StoreActivation(store_root, OsActiveRecordFiles())


@pytest.fixture
def first_store(store_root: Path) -> Path:
    return import_store(store_root, "first", cve_numbers=(1, 2))


@pytest.fixture
def second_store(store_root: Path) -> Path:
    return import_store(store_root, "second", cve_numbers=(3, 4))


def hash_manifest(store_dir: Path) -> str:
    return hashlib.sha256((store_dir / "manifest.json").read_bytes()).hexdigest()


def read_record_fields(store_root: Path) -> dict[str, object]:
    active_bytes = read_active_bytes(store_root)
    assert active_bytes is not None
    record_fields: dict[str, object] = json.loads(active_bytes)
    return record_fields


def describe_pointer(store_dir: Path) -> dict[str, str]:
    return {"name": store_dir.name, "store_manifest_sha256": hash_manifest(store_dir)}


def expect_failure(operation: Callable[[], object], failure: StoreOperationFailure) -> None:
    with pytest.raises(StoreOperationFailed) as raised:
        operation()
    assert raised.value.failure is failure


# --- Activation -----------------------------------------------------------------------


def test_first_activation_records_the_store_with_no_previous_store(
    store_activation: StoreActivation, store_root: Path, first_store: Path
) -> None:
    store_status = store_activation.activate("first")

    assert read_record_fields(store_root) == {
        "active_format_version": 1,
        "active": describe_pointer(first_store),
        "previous": None,
    }
    assert store_status.active_store is not None
    assert store_status.active_store.condition is ActiveStoreCondition.OK
    assert store_status.previous_store is None


def test_activation_reports_the_identity_its_verification_found(
    store_activation: StoreActivation, first_store: Path
) -> None:
    verified_store = verify_corpus_store(first_store)

    store_status = store_activation.activate("first")

    assert store_status.active_store is not None
    identity = store_status.active_store.identity
    assert identity is not None
    assert identity.import_identity_sha256 == verified_store.manifest.import_identity_sha256
    assert identity.corpus_content_sha256 == verified_store.corpus_content_sha256
    assert identity.cve_search_version == (
        f"corpus-store-v1@sha256:{verified_store.corpus_content_sha256}"
    )
    assert identity.created_under_schema_version == SCHEMA_VERSION


def test_activating_another_store_keeps_the_active_one_as_previous(
    store_activation: StoreActivation, store_root: Path, first_store: Path, second_store: Path
) -> None:
    store_activation.activate("first")

    store_status = store_activation.activate("second")

    record_fields = read_record_fields(store_root)
    assert record_fields["active"] == describe_pointer(second_store)
    assert record_fields["previous"] == describe_pointer(first_store)
    assert store_status.previous_store is not None
    assert store_status.previous_store.condition is StoreCondition.OK


def test_activating_the_active_store_again_leaves_active_untouched(
    store_activation: StoreActivation, store_root: Path, first_store: Path, second_store: Path
) -> None:
    store_activation.activate("first")
    store_activation.activate("second")
    active_path = store_root / "ACTIVE"
    recorded_state = (active_path.read_bytes(), os.stat(active_path).st_ino)

    store_status = store_activation.activate("second")

    assert (active_path.read_bytes(), os.stat(active_path).st_ino) == recorded_state
    assert store_status.previous_store is not None
    assert store_status.previous_store.name == "first"


def test_activating_a_store_replaced_under_its_name_records_it_and_keeps_the_previous(
    store_activation: StoreActivation, store_root: Path, first_store: Path, second_store: Path
) -> None:
    store_activation.activate("first")
    store_activation.activate("second")
    rewrite_manifest(second_store)

    store_activation.activate("second")

    record_fields = read_record_fields(store_root)
    assert record_fields["active"] == describe_pointer(second_store)
    assert record_fields["previous"] == describe_pointer(first_store)


def test_activation_records_a_previous_store_whatever_state_it_is_in(
    store_activation: StoreActivation, store_root: Path, first_store: Path, second_store: Path
) -> None:
    store_activation.activate("first")
    recorded_first = describe_pointer(first_store)
    tamper_with_records(first_store)

    store_status = store_activation.activate("second")

    assert read_record_fields(store_root)["previous"] == recorded_first
    assert store_status.previous_store is not None
    assert store_status.previous_store.condition is StoreCondition.STORE_INVALID
    assert store_status.previous_store.identity is None


def test_compatibility_store_written_by_an_earlier_release_activates(
    store_activation: StoreActivation, store_root: Path
) -> None:
    copy_compatibility_store(store_root, "dev25")

    store_status = store_activation.activate("dev25")

    assert store_status.active_store is not None
    assert store_status.active_store.identity is not None
    assert store_status.active_store.identity.created_under_schema_version == "2.0.0-dev.25"


@pytest.mark.parametrize(
    ("break_store", "failure"),
    [
        (lambda store_dir: None, StoreOperationFailure.STORE_MISSING),
        (tamper_with_records, StoreOperationFailure.STORE_INVALID),
        (
            declare_later_format,
            StoreOperationFailure.STORE_FORMAT_UNSUPPORTED,
        ),
    ],
    ids=["missing", "tampered", "later_format"],
)
def test_activating_a_store_that_does_not_verify_changes_nothing(
    store_activation: StoreActivation,
    store_root: Path,
    first_store: Path,
    break_store: Callable[[Path], object],
    failure: StoreOperationFailure,
) -> None:
    store_activation.activate("first")
    recorded_bytes = read_active_bytes(store_root)
    candidate_dir = store_root / "candidate"
    if failure is not StoreOperationFailure.STORE_MISSING:
        import_store(store_root, "candidate", cve_numbers=(5,))
    break_store(candidate_dir)

    expect_failure(lambda: store_activation.activate("candidate"), failure)

    assert read_active_bytes(store_root) == recorded_bytes


def test_activating_a_symbolic_link_to_a_store_is_refused_as_invalid(
    store_activation: StoreActivation, store_root: Path, first_store: Path
) -> None:
    (store_root / "alias").symlink_to(first_store)

    expect_failure(lambda: store_activation.activate("alias"), StoreOperationFailure.STORE_INVALID)

    assert read_active_bytes(store_root) is None


def test_activate_writes_active_and_lock_readable_by_every_user_whatever_the_umask(
    store_activation: StoreActivation, store_root: Path, first_store: Path
) -> None:
    previous_umask = os.umask(0o077)
    try:
        store_activation.activate("first")
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(os.stat(store_root / "ACTIVE").st_mode) == 0o644
    assert stat.S_IMODE(os.stat(store_root / ".lock").st_mode) == 0o644


def test_activation_leaves_no_temporary_record_behind(
    store_activation: StoreActivation, store_root: Path, first_store: Path, second_store: Path
) -> None:
    store_activation.activate("first")
    store_activation.activate("second")

    assert list_hidden_entries(store_root) == []


# --- Rollback -------------------------------------------------------------------------


def test_rollback_makes_the_previous_store_active_with_no_previous_store(
    store_activation: StoreActivation, store_root: Path, first_store: Path, second_store: Path
) -> None:
    store_activation.activate("first")
    store_activation.activate("second")

    store_status = store_activation.roll_back()

    assert read_record_fields(store_root) == {
        "active_format_version": 1,
        "active": describe_pointer(first_store),
        "previous": None,
    }
    assert store_status.active_store is not None
    assert store_status.active_store.name == "first"
    assert store_status.previous_store is None


def test_rollback_is_one_level(
    store_activation: StoreActivation, first_store: Path, second_store: Path
) -> None:
    store_activation.activate("first")
    store_activation.activate("second")
    store_activation.roll_back()

    expect_failure(store_activation.roll_back, StoreOperationFailure.NO_PREVIOUS_STORE)


def test_rollback_without_active_has_no_previous_store(
    store_activation: StoreActivation, store_root: Path
) -> None:
    expect_failure(store_activation.roll_back, StoreOperationFailure.NO_PREVIOUS_STORE)

    assert read_active_bytes(store_root) is None


@pytest.mark.parametrize(
    ("break_previous", "failure"),
    [
        (
            move_store,
            StoreOperationFailure.STORE_MISSING,
        ),
        (rewrite_manifest, StoreOperationFailure.STORE_CHANGED),
        (tamper_with_records, StoreOperationFailure.STORE_INVALID),
    ],
    ids=["missing", "replaced", "tampered"],
)
def test_rollback_to_a_previous_store_that_no_longer_verifies_changes_nothing(
    store_activation: StoreActivation,
    store_root: Path,
    first_store: Path,
    second_store: Path,
    break_previous: Callable[[Path], object],
    failure: StoreOperationFailure,
) -> None:
    store_activation.activate("first")
    store_activation.activate("second")
    recorded_bytes = read_active_bytes(store_root)
    break_previous(first_store)

    expect_failure(store_activation.roll_back, failure)

    assert read_active_bytes(store_root) == recorded_bytes


def test_rollback_lands_on_a_previous_store_created_under_an_earlier_contract(
    store_activation: StoreActivation, store_root: Path, first_store: Path
) -> None:
    copy_compatibility_store(store_root, "dev25")
    store_activation.activate("dev25")
    store_activation.activate("first")

    store_status = store_activation.roll_back()

    assert store_status.active_store is not None
    assert store_status.active_store.name == "dev25"


# --- An unreadable ACTIVE -------------------------------------------------------------


def write_unreadable_active(store_root: Path, first_store: Path, kind: str) -> None:
    active_path = store_root / "ACTIVE"
    pointer = describe_pointer(first_store)
    record = {"active": pointer, "active_format_version": 1, "previous": None}
    if kind == "not_json":
        active_path.write_bytes(b"first\n")
    elif kind == "not_canonical":
        active_path.write_text(json.dumps(record, indent=2))
    elif kind == "later_format":
        active_path.write_text(
            json.dumps(
                {**record, "active_format_version": 2}, sort_keys=True, separators=(",", ":")
            )
        )
    elif kind == "unknown_field":
        active_path.write_text(
            json.dumps({**record, "note": "x"}, sort_keys=True, separators=(",", ":"))
        )
    elif kind == "active_named_active":
        bad_record = {**record, "active": {**pointer, "name": "Active"}}
        active_path.write_text(json.dumps(bad_record, sort_keys=True, separators=(",", ":")))
    elif kind == "equal_names":
        bad_record = {**record, "previous": pointer}
        active_path.write_text(json.dumps(bad_record, sort_keys=True, separators=(",", ":")))
    elif kind == "symbolic_link":
        target = store_root.parent / "elsewhere"
        target.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")))
        active_path.symlink_to(target)
    elif kind == "directory":
        active_path.mkdir()
    elif kind == "over_the_cap":
        active_path.write_bytes(b" " * (MAX_ACTIVE_BYTES + 1))


UNREADABLE_KINDS = [
    "not_json",
    "not_canonical",
    "later_format",
    "unknown_field",
    "active_named_active",
    "equal_names",
    "symbolic_link",
    "directory",
    "over_the_cap",
]


@pytest.mark.parametrize("kind", UNREADABLE_KINDS)
def test_activation_over_an_unreadable_active_is_refused_and_leaves_it(
    store_activation: StoreActivation, store_root: Path, first_store: Path, kind: str
) -> None:
    write_unreadable_active(store_root, first_store, kind)
    recorded_state = os.lstat(store_root / "ACTIVE")
    recorded_bytes = read_active_bytes(store_root) if kind != "directory" else None

    expect_failure(
        lambda: store_activation.activate("first"), StoreOperationFailure.ACTIVE_UNREADABLE
    )

    assert os.lstat(store_root / "ACTIVE").st_ino == recorded_state.st_ino
    if kind != "directory":
        assert read_active_bytes(store_root) == recorded_bytes


@pytest.mark.parametrize("kind", UNREADABLE_KINDS)
def test_status_of_an_unreadable_active_names_no_store(
    store_activation: StoreActivation, store_root: Path, first_store: Path, kind: str
) -> None:
    write_unreadable_active(store_root, first_store, kind)

    store_status = store_activation.describe_status()

    assert store_status.active_record is ActiveRecordState.ACTIVE_UNREADABLE
    assert (store_status.active_store, store_status.previous_store) == (None, None)


def test_rollback_over_an_unreadable_active_is_refused(
    store_activation: StoreActivation, store_root: Path, first_store: Path
) -> None:
    write_unreadable_active(store_root, first_store, "not_json")

    expect_failure(store_activation.roll_back, StoreOperationFailure.ACTIVE_UNREADABLE)


@pytest.mark.parametrize(
    ("size_bytes", "refusal"),
    [
        (MAX_ACTIVE_BYTES, "not a record this release reads"),
        (MAX_ACTIVE_BYTES + 1, "larger than a record"),
    ],
    ids=["at_the_cap_read_whole", "one_byte_over_refused"],
)
def test_active_is_read_up_to_its_cap_and_refused_past_it(
    store_root: Path, size_bytes: int, refusal: str
) -> None:
    (store_root / "ACTIVE").write_bytes(b" " * size_bytes)

    with pytest.raises(ActiveRecordUnreadableError, match=refusal):
        read_active_record(store_root)


# --- The lock and the write -----------------------------------------------------------


def test_activation_while_another_operation_holds_the_lock_is_refused(
    store_activation: StoreActivation, store_root: Path, first_store: Path
) -> None:
    with hold_store_lock(store_root):
        expect_failure(
            lambda: store_activation.activate("first"), StoreOperationFailure.STORE_LOCK_HELD
        )

    assert read_active_bytes(store_root) is None


def test_lock_held_by_another_process_descriptor_refuses_rollback(
    store_activation: StoreActivation, store_root: Path, first_store: Path, second_store: Path
) -> None:
    store_activation.activate("first")
    store_activation.activate("second")
    lock_descriptor = os.open(store_root / ".lock", os.O_RDWR)
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        expect_failure(store_activation.roll_back, StoreOperationFailure.STORE_LOCK_HELD)
    finally:
        os.close(lock_descriptor)


@pytest.mark.parametrize("lock_kind", ["directory", "symbolic_link"])
def test_lock_that_is_not_a_regular_file_fails_the_write(
    store_activation: StoreActivation, store_root: Path, first_store: Path, lock_kind: str
) -> None:
    lock_path = store_root / ".lock"
    if lock_kind == "directory":
        lock_path.mkdir()
    else:
        (store_root.parent / "lock-target").write_bytes(b"")
        lock_path.symlink_to(store_root.parent / "lock-target")

    expect_failure(
        lambda: store_activation.activate("first"), StoreOperationFailure.ACTIVE_WRITE_FAILED
    )

    assert read_active_bytes(store_root) is None


@pytest.mark.skipif(os.geteuid() == 0, reason="the superuser writes through any mode")
def test_activation_in_a_read_only_root_fails_the_write_and_changes_nothing(
    store_activation: StoreActivation, store_root: Path, first_store: Path
) -> None:
    store_root.chmod(0o555)
    try:
        expect_failure(
            lambda: store_activation.activate("first"), StoreOperationFailure.ACTIVE_WRITE_FAILED
        )
    finally:
        store_root.chmod(0o755)

    assert read_active_bytes(store_root) is None


@pytest.mark.parametrize("failing_point", ["check", "temporary", "replace"])
def test_failure_before_the_replace_leaves_active_as_it_was(
    store_root: Path, first_store: Path, second_store: Path, failing_point: str
) -> None:
    StoreActivation(store_root, OsActiveRecordFiles()).activate("first")
    recorded_bytes = read_active_bytes(store_root)
    failing_activation = StoreActivation(store_root, FailingActiveRecordFiles(failing_point))

    expect_failure(
        lambda: failing_activation.activate("second"), StoreOperationFailure.ACTIVE_WRITE_FAILED
    )

    assert read_active_bytes(store_root) == recorded_bytes
    assert list_hidden_entries(store_root) == []


def test_failure_of_the_confirming_sync_is_reported_unconfirmed_with_the_new_record(
    store_root: Path, first_store: Path, second_store: Path
) -> None:
    StoreActivation(store_root, OsActiveRecordFiles()).activate("first")
    failing_activation = StoreActivation(store_root, FailingActiveRecordFiles("confirm"))

    expect_failure(
        lambda: failing_activation.activate("second"),
        StoreOperationFailure.ACTIVE_WRITE_UNCONFIRMED,
    )

    assert read_record_fields(store_root)["active"] == describe_pointer(second_store)


def test_rollback_whose_replace_fails_leaves_the_record_to_roll_back_again(
    store_root: Path, first_store: Path, second_store: Path
) -> None:
    store_activation = StoreActivation(store_root, OsActiveRecordFiles())
    store_activation.activate("first")
    store_activation.activate("second")
    failing_activation = StoreActivation(store_root, FailingActiveRecordFiles("replace"))
    expect_failure(failing_activation.roll_back, StoreOperationFailure.ACTIVE_WRITE_FAILED)

    store_status = store_activation.roll_back()

    assert store_status.active_store is not None
    assert store_status.active_store.name == "first"


# --- The root -------------------------------------------------------------------------


@pytest.mark.parametrize("break_root", ROOT_BREAKERS)
@pytest.mark.parametrize("operation_name", ["validate", "activate", "roll_back", "describe_status"])
def test_every_operation_on_an_unusable_root_fails_as_store_root_unusable(
    store_root: Path, break_root: Callable[[Path], None], operation_name: str
) -> None:
    break_root(store_root)
    store_activation = StoreActivation(store_root, OsActiveRecordFiles())
    operation = getattr(store_activation, operation_name)
    arguments = ("first",) if operation_name in ("validate", "activate") else ()

    expect_failure(lambda: operation(*arguments), StoreOperationFailure.STORE_ROOT_UNUSABLE)


def test_root_whose_parent_is_a_symbolic_link_is_usable(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    (real_parent / "stores").mkdir(parents=True)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent)
    store_root = linked_parent / "stores"
    import_store(store_root, "first")

    store_status = StoreActivation(store_root, OsActiveRecordFiles()).activate("first")

    assert store_status.active_store is not None


# --- Validation and status ------------------------------------------------------------


def test_validate_verifies_the_store_and_writes_nothing(
    store_activation: StoreActivation, store_root: Path, first_store: Path
) -> None:
    verified_store = store_activation.validate("first")

    assert verified_store == verify_corpus_store(first_store)
    assert read_active_bytes(store_root) is None
    assert not (store_root / ".lock").exists()


def test_status_without_active_reports_no_active_store(
    store_activation: StoreActivation, first_store: Path
) -> None:
    store_status = store_activation.describe_status()

    assert store_status.active_record is ActiveRecordState.NO_ACTIVE_STORE
    assert store_status.active_store is None


@pytest.mark.parametrize(
    ("break_active", "condition"),
    [
        (
            move_store,
            ActiveStoreCondition.ACTIVE_STORE_MISSING,
        ),
        (rewrite_manifest, ActiveStoreCondition.ACTIVE_STORE_CHANGED),
        (tamper_with_records, ActiveStoreCondition.STORE_INVALID),
    ],
    ids=["missing", "replaced", "tampered"],
)
def test_status_reports_the_active_store_in_startup_reasons_without_its_digests(
    store_activation: StoreActivation,
    first_store: Path,
    break_active: Callable[[Path], object],
    condition: ActiveStoreCondition,
) -> None:
    store_activation.activate("first")
    recorded_manifest_sha256 = hash_manifest(first_store)
    break_active(first_store)

    store_status = store_activation.describe_status()

    assert store_status.active_store is not None
    assert store_status.active_store.condition is condition
    assert store_status.active_store.identity is None
    assert store_status.active_store.store_manifest_sha256 == recorded_manifest_sha256


def test_status_names_no_path(
    store_activation: StoreActivation, store_root: Path, first_store: Path, second_store: Path
) -> None:
    store_activation.activate("first")
    store_activation.activate("second")

    status_json = store_activation.describe_status().model_dump_json()

    assert str(store_root.parent) not in status_json
