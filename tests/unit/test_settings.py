"""Settings are read from the environment once, default to off, and never name a value."""

import logging
import traceback
from pathlib import Path

import pytest

from cve_kgrag.settings import (
    FightSnapshotSettings,
    HttpSettings,
    ModelPlannerSettings,
    SemanticSettings,
    ServiceSettings,
    SettingsError,
    fingerprint_endpoint,
    load_settings,
)
from tests.support.secrets import assert_secret_absent

PLANNER_KEY = "sk-test-settings-key-0123456789"
ENABLED_PLANNER = {
    "CVE_KGRAG_PLANNER_ENABLED": "true",
    "CVE_KGRAG_PLANNER_BASE_URL": "https://api.example.test/v1",
    "CVE_KGRAG_PLANNER_MODEL_NAME": "example-chat",
    "CVE_KGRAG_PLANNER_API_KEY": PLANNER_KEY,
}
HTTP_TOKEN = "Kq3vY8xN2pL5sT7wB9dF1gH4jM6zC0aE-_.~+/R"
CREDENTIAL_URL = "https://planner-user:hunter2-password@api.example.test/v1"


def describe_raised(error: BaseException) -> str:
    """Everything a raised error prints: its message, its chain and its traceback."""
    return "".join(traceback.format_exception(error))


def test_empty_environment_leaves_every_adapter_off() -> None:
    settings = load_settings({})

    assert settings == ServiceSettings(model_planner=None, semantic=None)


@pytest.mark.parametrize("switch", ["", "false", "0", "no", "OFF"])
def test_planner_switched_off_ignores_its_other_variables(switch: str) -> None:
    environment = {
        "CVE_KGRAG_PLANNER_ENABLED": switch,
        "CVE_KGRAG_PLANNER_BASE_URL": "ftp://not-read",
        "CVE_KGRAG_PLANNER_API_KEY": PLANNER_KEY,
    }

    settings = load_settings(environment)

    assert settings.model_planner is None


@pytest.mark.parametrize("switch", ["true", "1", "yes", "On", " TRUE "])
def test_enabled_planner_reads_its_endpoint_model_and_key(switch: str) -> None:
    environment = {**ENABLED_PLANNER, "CVE_KGRAG_PLANNER_ENABLED": switch}

    settings = load_settings(environment)

    planner_settings = settings.model_planner
    assert planner_settings is not None
    assert planner_settings.base_url == "https://api.example.test/v1"
    assert planner_settings.model_name == "example-chat"
    assert planner_settings.api_key is not None
    assert planner_settings.api_key.get_secret_value() == PLANNER_KEY


def test_empty_key_counts_as_unset_so_the_planner_has_no_key() -> None:
    environment = {**ENABLED_PLANNER, "CVE_KGRAG_PLANNER_API_KEY": ""}

    settings = load_settings(environment)

    assert settings.model_planner is not None
    assert settings.model_planner.api_key is None


def test_switch_that_is_not_a_boolean_is_an_error_naming_the_variable() -> None:
    with pytest.raises(SettingsError) as raised:
        load_settings({"CVE_KGRAG_PLANNER_ENABLED": "maybe"})

    assert str(raised.value) == (
        "invalid settings: CVE_KGRAG_PLANNER_ENABLED: must be true or false"
    )


def test_enabled_planner_without_endpoint_or_model_names_both_variables() -> None:
    with pytest.raises(SettingsError) as raised:
        load_settings({"CVE_KGRAG_PLANNER_ENABLED": "true"})

    assert str(raised.value) == (
        "invalid settings: CVE_KGRAG_PLANNER_BASE_URL: Field required; "
        "CVE_KGRAG_PLANNER_MODEL_NAME: Field required"
    )


@pytest.mark.parametrize(
    "base_url",
    [
        "http://api.example.test/v1",
        CREDENTIAL_URL,
        "https://api.example.test/v1?key=abc",
        "https://api.example.test/v1#fragment",
        "https:///v1",
        "https://api.example.test:99999/v1",
        "https://api.example.test:port/v1",
        "https://api.example.test:0/v1",
        "https://api.example.test /v1",
        "https://planner-user@api.example.test/v1",
        "https://api.example.test/v1?",
        "https://api.example.test/v1#",
        "https://api.example.test\\evil.test/v1",
        "https://evil.test%2F.api.example.test/v1",
        "https://api.example.test/v1\x00",
        "ftp://api.example.test/v1",
        "api.example.test/v1",
        "http://127.0.0.1.evil.test/v1",
        "http://localhost.evil.test/v1",
        "http://10.0.0.5/v1",
    ],
    ids=[
        "http_to_a_remote_host",
        "credentials",
        "query",
        "fragment",
        "no_host",
        "port_out_of_range",
        "port_not_a_number",
        "port_zero",
        "space",
        "username_only",
        "empty_query",
        "empty_fragment",
        "backslash_in_host",
        "percent_escape_in_host",
        "control_character",
        "other_scheme",
        "no_scheme",
        "loopback_lookalike_host",
        "localhost_lookalike_host",
        "private_non_loopback_ip",
    ],
)
def test_endpoint_that_could_misdirect_the_key_is_rejected_without_quoting_it(
    base_url: str,
) -> None:
    environment = {**ENABLED_PLANNER, "CVE_KGRAG_PLANNER_BASE_URL": base_url}

    with pytest.raises(SettingsError) as raised:
        load_settings(environment)

    raised_text = describe_raised(raised.value)
    assert str(raised.value).startswith("invalid settings: CVE_KGRAG_PLANNER_BASE_URL: ")
    assert base_url not in raised_text
    assert "hunter2-password" not in raised_text


@pytest.mark.parametrize(
    "base_url",
    ["http://localhost:8000/v1", "http://127.0.0.1:8000/v1", "http://[::1]:8000/v1"],
    ids=["localhost", "ipv4_loopback", "ipv6_loopback"],
)
def test_plain_http_is_accepted_only_to_a_loopback_host(base_url: str) -> None:
    environment = {**ENABLED_PLANNER, "CVE_KGRAG_PLANNER_BASE_URL": base_url}

    settings = load_settings(environment)

    assert settings.model_planner is not None
    assert settings.model_planner.base_url == base_url


def test_invalid_model_name_error_never_quotes_the_key_or_the_name() -> None:
    environment = {**ENABLED_PLANNER, "CVE_KGRAG_PLANNER_MODEL_NAME": f"name with {PLANNER_KEY}"}

    with pytest.raises(SettingsError) as raised:
        load_settings(environment)

    raised_text = describe_raised(raised.value)
    assert str(raised.value).startswith("invalid settings: CVE_KGRAG_PLANNER_MODEL_NAME: ")
    assert PLANNER_KEY not in raised_text
    assert raised.value.__context__ is None


def test_settings_error_logged_with_its_traceback_quotes_no_value(
    caplog: pytest.LogCaptureFixture,
) -> None:
    environment = {**ENABLED_PLANNER, "CVE_KGRAG_PLANNER_BASE_URL": CREDENTIAL_URL}

    with caplog.at_level(logging.ERROR):
        try:
            load_settings(environment)
        except SettingsError:
            logging.getLogger(__name__).exception("settings rejected")

    logged_text = caplog.text
    assert "CVE_KGRAG_PLANNER_BASE_URL" in logged_text
    assert "hunter2-password" not in logged_text
    assert PLANNER_KEY not in logged_text


def test_key_is_masked_in_every_rendering_of_the_settings() -> None:
    settings = load_settings(ENABLED_PLANNER)

    renderings = [
        repr(settings),
        str(settings),
        settings.model_dump_json(),
        str(settings.model_dump()),
        str(settings.model_dump(mode="json")),
    ]

    for rendering in renderings:
        assert PLANNER_KEY not in rendering


def test_settings_models_reject_fields_they_do_not_declare() -> None:
    with pytest.raises(ValueError):
        ModelPlannerSettings.model_validate(
            {"base_url": "https://api.example.test/v1", "model_name": "m", "provider": "x"}
        )


@pytest.mark.parametrize(
    "spelling",
    [
        "https://api.example.test/v1",
        "https://API.Example.Test/v1",
        "https://api.example.test:443/v1",
        "HTTPS://api.example.test/v1",
    ],
    ids=["plain", "host_case", "default_port", "scheme_case"],
)
def test_one_endpoint_spelled_differently_has_one_fingerprint(spelling: str) -> None:
    assert fingerprint_endpoint(spelling) == fingerprint_endpoint("https://api.example.test/v1")


@pytest.mark.parametrize(
    "other_endpoint",
    [
        "https://other.example.test/v1",
        "https://api.example.test:8443/v1",
        "https://api.example.test/v2",
        "http://localhost/v1",
        "https://api.example.test:0/v1",
        "https://api.example.test/v1/",
        "https://api.example.test/v1//",
    ],
    ids=[
        "host",
        "port",
        "path",
        "scheme_and_host",
        "port_zero",
        "trailing_slash",
        "two_trailing_slashes",
    ],
)
def test_another_endpoint_has_another_fingerprint_that_names_no_host(
    other_endpoint: str,
) -> None:
    fingerprint = fingerprint_endpoint(other_endpoint)

    assert fingerprint != fingerprint_endpoint("https://api.example.test/v1")
    assert "example" not in fingerprint


@pytest.mark.parametrize(
    ("base_url", "expected_base_url"),
    [
        ("https://api.example.test/v1/", "https://api.example.test/v1"),
        ("https://api.example.test/v1//", "https://api.example.test/v1/"),
        ("https://api.example.test/v1", "https://api.example.test/v1"),
    ],
    ids=["one_trailing_slash", "two_trailing_slashes", "none"],
)
def test_endpoint_loses_exactly_one_trailing_slash(base_url: str, expected_base_url: str) -> None:
    environment = {**ENABLED_PLANNER, "CVE_KGRAG_PLANNER_BASE_URL": base_url}

    settings = load_settings(environment)

    assert settings.model_planner is not None
    assert settings.model_planner.base_url == expected_base_url


def load_endpoint_fingerprint(base_url: str) -> str:
    """The fingerprint of ``base_url`` as the settings hand it to the adapter."""
    settings = load_settings({**ENABLED_PLANNER, "CVE_KGRAG_PLANNER_BASE_URL": base_url})
    assert settings.model_planner is not None
    return fingerprint_endpoint(settings.model_planner.base_url)


def test_configured_endpoint_with_one_trailing_slash_is_the_same_endpoint() -> None:
    assert load_endpoint_fingerprint("https://api.example.test/v1/") == (
        load_endpoint_fingerprint("https://api.example.test/v1")
    )


@pytest.mark.parametrize(
    "other_spelling",
    ["https://api.example.test/v1//", "https://api.example.test/v1///"],
    ids=["two_trailing_slashes", "three_trailing_slashes"],
)
def test_configured_endpoint_with_more_trailing_slashes_is_another_endpoint(
    other_spelling: str,
) -> None:
    fingerprint = load_endpoint_fingerprint(other_spelling)

    assert fingerprint != load_endpoint_fingerprint("https://api.example.test/v1")
    assert fingerprint != load_endpoint_fingerprint("https://api.example.test/v1/")


@pytest.mark.parametrize(
    "api_key",
    [f"{PLANNER_KEY}\n", f"{PLANNER_KEY} extra", f"{PLANNER_KEY}é", "x" * 1025],
    ids=["trailing_newline", "embedded_space", "non_ascii", "over_1024_characters"],
)
def test_key_a_request_header_cannot_carry_is_rejected_without_quoting_it(api_key: str) -> None:
    environment = {**ENABLED_PLANNER, "CVE_KGRAG_PLANNER_API_KEY": api_key}

    with pytest.raises(SettingsError) as raised:
        load_settings(environment)

    assert str(raised.value).startswith("invalid settings: CVE_KGRAG_PLANNER_API_KEY: ")
    assert_secret_absent(describe_raised(raised.value), PLANNER_KEY, "the settings error")


@pytest.mark.parametrize(
    "base_url",
    ["https://api.example.test/vé", "https://bücher.example.test/v1"],
    ids=["non_ascii_path", "non_ascii_host"],
)
def test_endpoint_that_is_not_ascii_is_rejected(base_url: str) -> None:
    environment = {**ENABLED_PLANNER, "CVE_KGRAG_PLANNER_BASE_URL": base_url}

    with pytest.raises(SettingsError) as raised:
        load_settings(environment)

    assert str(raised.value).startswith("invalid settings: CVE_KGRAG_PLANNER_BASE_URL: ")


def test_reasoning_effort_is_read_when_set_and_absent_otherwise() -> None:
    configured = load_settings({**ENABLED_PLANNER, "CVE_KGRAG_PLANNER_REASONING_EFFORT": "none"})
    unconfigured = load_settings(ENABLED_PLANNER)

    assert configured.model_planner is not None
    assert configured.model_planner.reasoning_effort == "none"
    assert unconfigured.model_planner is not None
    assert unconfigured.model_planner.reasoning_effort is None


@pytest.mark.parametrize("reasoning_effort", ["High", "very high", "x" * 17], ids=str)
def test_reasoning_effort_outside_the_pattern_is_rejected(reasoning_effort: str) -> None:
    environment = {**ENABLED_PLANNER, "CVE_KGRAG_PLANNER_REASONING_EFFORT": reasoning_effort}

    with pytest.raises(SettingsError) as raised:
        load_settings(environment)

    assert str(raised.value).startswith("invalid settings: CVE_KGRAG_PLANNER_REASONING_EFFORT: ")


def test_enabled_semantic_channel_takes_the_store_s_collection_and_model_defaults() -> None:
    settings = load_settings(
        {
            "CVE_KGRAG_SEMANTIC_ENABLED": "true",
            "CVE_KGRAG_SEMANTIC_PERSIST_DIRECTORY": "/srv/vectors",
        }
    )

    assert settings.semantic == SemanticSettings(
        collection_name="cve_documents",
        persist_directory="/srv/vectors",
        model_name="sentence-transformers/all-MiniLM-L6-v2",
    )


def test_enabled_semantic_channel_without_a_directory_is_an_error_naming_it() -> None:
    with pytest.raises(SettingsError) as raised:
        load_settings({"CVE_KGRAG_SEMANTIC_ENABLED": "true"})

    assert str(raised.value) == (
        "invalid settings: CVE_KGRAG_SEMANTIC_PERSIST_DIRECTORY: Field required"
    )


def test_enabled_semantic_channel_reads_its_collection_directory_and_model() -> None:
    environment = {
        "CVE_KGRAG_SEMANTIC_ENABLED": "yes",
        "CVE_KGRAG_SEMANTIC_COLLECTION_NAME": "cve_chunks",
        "CVE_KGRAG_SEMANTIC_PERSIST_DIRECTORY": "/srv/vectors",
        "CVE_KGRAG_SEMANTIC_MODEL_NAME": "BAAI/bge-small-en-v1.5",
    }

    settings = load_settings(environment)

    assert settings.semantic == SemanticSettings(
        collection_name="cve_chunks",
        persist_directory="/srv/vectors",
        model_name="BAAI/bge-small-en-v1.5",
    )


def test_semantic_switch_off_ignores_its_other_variables() -> None:
    environment = {"CVE_KGRAG_SEMANTIC_COLLECTION_NAME": "x"}

    settings = load_settings(environment)

    assert settings.semantic is None


@pytest.mark.parametrize(
    ("variable_name", "value"),
    [
        ("CVE_KGRAG_SEMANTIC_COLLECTION_NAME", "Zq"),
        ("CVE_KGRAG_SEMANTIC_COLLECTION_NAME", "has space"),
        ("CVE_KGRAG_SEMANTIC_MODEL_NAME", "model with spaces"),
        ("CVE_KGRAG_SEMANTIC_PERSIST_DIRECTORY", "/srv/vectors\x00/../etc"),
    ],
    ids=["collection_too_short", "collection_with_a_space", "model_with_spaces", "nul_in_path"],
)
def test_invalid_semantic_setting_names_the_variable_not_the_value(
    variable_name: str, value: str
) -> None:
    environment = {
        "CVE_KGRAG_SEMANTIC_ENABLED": "true",
        "CVE_KGRAG_SEMANTIC_PERSIST_DIRECTORY": "/srv/vectors",
        variable_name: value,
    }

    with pytest.raises(SettingsError) as raised:
        load_settings(environment)

    assert str(raised.value).startswith(f"invalid settings: {variable_name}: ")
    assert_secret_absent(describe_raised(raised.value), value, "the settings error")


def test_invalid_semantic_switch_is_an_error_naming_it() -> None:
    with pytest.raises(SettingsError) as raised:
        load_settings({"CVE_KGRAG_SEMANTIC_ENABLED": "sometimes"})

    assert (
        str(raised.value) == "invalid settings: CVE_KGRAG_SEMANTIC_ENABLED: must be true or false"
    )


def test_http_settings_default_to_loopback_port_8765_and_no_token() -> None:
    settings = load_settings({})

    assert settings.http == HttpSettings(host="127.0.0.1", token=None, mcp_port=8765, api_port=8766)


def test_http_settings_read_their_host_port_and_token() -> None:
    environment = {
        "CVE_KGRAG_HTTP_HOST": "::1",
        "CVE_KGRAG_MCP_HTTP_PORT": "9001",
        "CVE_KGRAG_API_PORT": "9002",
        "CVE_KGRAG_HTTP_TOKEN": HTTP_TOKEN,
    }

    http_settings = load_settings(environment).http

    assert http_settings.host == "::1"
    assert http_settings.mcp_port == 9001
    assert http_settings.api_port == 9002
    assert http_settings.token is not None
    assert http_settings.token.get_secret_value() == HTTP_TOKEN


@pytest.mark.parametrize(
    ("variable_name", "value"),
    [
        ("CVE_KGRAG_HTTP_HOST", "0.0.0.0"),
        ("CVE_KGRAG_HTTP_HOST", "0:0:0:0:0:0:0:0"),
        ("CVE_KGRAG_HTTP_HOST", "localhost"),
        ("CVE_KGRAG_HTTP_HOST", "127.0.0.2"),
        ("CVE_KGRAG_HTTP_HOST", "::ffff:127.0.0.1"),
        ("CVE_KGRAG_HTTP_HOST", "192.0.2.10"),
        ("CVE_KGRAG_MCP_HTTP_PORT", "00000"),
        ("CVE_KGRAG_MCP_HTTP_PORT", "65536"),
        ("CVE_KGRAG_MCP_HTTP_PORT", "port-eighty"),
        ("CVE_KGRAG_API_PORT", "70000"),
        ("CVE_KGRAG_HTTP_TOKEN", "Kq3vY8xN2pL5sT7wB9dF1gH4jM6zC0a"),
        ("CVE_KGRAG_HTTP_TOKEN", "Kq3vY8xN2pL5sT7wB9dF1gH4jM6zC0aE secret"),
        ("CVE_KGRAG_HTTP_TOKEN", "Kq3vY8xN2pL5sT7wB9dF1gH4jM6zC0aEé"),
        ("CVE_KGRAG_HTTP_TOKEN", "Kq3vY8xN2pL5sT7wB9dF1gH4jM6zC0aE=x"),
        ("CVE_KGRAG_HTTP_TOKEN", "K" * 513),
    ],
    ids=[
        "every_ipv4_address",
        "every_ipv6_address",
        "name_to_resolve",
        "other_loopback_address",
        "mapped_loopback_address",
        "other_address",
        "port_zero",
        "port_out_of_range",
        "port_not_a_number",
        "api_port_out_of_range",
        "token_too_short",
        "token_with_a_space",
        "token_not_ascii",
        "token_with_padding_inside",
        "token_too_long",
    ],
)
def test_invalid_http_setting_names_the_variable_not_the_value(
    variable_name: str, value: str
) -> None:
    with pytest.raises(SettingsError) as raised:
        load_settings({variable_name: value})

    assert str(raised.value).startswith(f"invalid settings: {variable_name}: ")
    assert_secret_absent(describe_raised(raised.value), value, "the settings error")
    assert raised.value.__context__ is None


def test_http_token_is_masked_in_every_rendering_of_the_settings() -> None:
    settings = load_settings({"CVE_KGRAG_HTTP_TOKEN": HTTP_TOKEN})

    renderings = [
        repr(settings),
        str(settings),
        settings.model_dump_json(),
        str(settings.model_dump()),
        str(settings.model_dump(mode="json")),
    ]

    for rendering in renderings:
        assert_secret_absent(rendering, HTTP_TOKEN, "a rendering of the settings")


SNAPSHOT_SHA256 = "59a9addb" + "0" * 56


def test_served_data_defaults_to_the_packaged_fixture_and_excerpt() -> None:
    settings = load_settings({})

    assert settings.store_root is None
    assert settings.fight_snapshot is None


def test_served_data_settings_read_the_store_root_and_the_snapshot_pin() -> None:
    environment = {
        "CVE_KGRAG_STORE_ROOT": "/srv/cve-kgrag/stores",
        "CVE_KGRAG_FIGHT_SNAPSHOT_PATH": "/srv/cve-kgrag/fight.yaml",
        "CVE_KGRAG_FIGHT_SNAPSHOT_SHA256": SNAPSHOT_SHA256,
    }

    settings = load_settings(environment)

    assert settings.store_root == Path("/srv/cve-kgrag/stores")
    assert settings.fight_snapshot == FightSnapshotSettings(
        path=Path("/srv/cve-kgrag/fight.yaml"), sha256=SNAPSHOT_SHA256
    )


def test_settings_open_nothing_the_served_data_variables_name(tmp_path: Path) -> None:
    missing_root = tmp_path / "no-such-root"
    environment = {
        "CVE_KGRAG_STORE_ROOT": str(missing_root),
        "CVE_KGRAG_FIGHT_SNAPSHOT_PATH": str(tmp_path / "no-such-snapshot.yaml"),
        "CVE_KGRAG_FIGHT_SNAPSHOT_SHA256": SNAPSHOT_SHA256,
    }

    settings = load_settings(environment)

    assert settings.store_root == missing_root
    assert not missing_root.exists()


@pytest.mark.parametrize(
    ("variable_name", "value"),
    [
        ("CVE_KGRAG_STORE_ROOT", "stores"),
        ("CVE_KGRAG_STORE_ROOT", "./stores"),
        ("CVE_KGRAG_STORE_ROOT", "~/stores"),
        ("CVE_KGRAG_STORE_ROOT", "/srv/stores\x01"),
        ("CVE_KGRAG_STORE_ROOT", "/" + "s" * 4096),
        ("CVE_KGRAG_FIGHT_SNAPSHOT_PATH", "fight.yaml"),
        ("CVE_KGRAG_FIGHT_SNAPSHOT_PATH", "/srv/fight\n.yaml"),
    ],
    ids=[
        "relative_root",
        "dot_relative_root",
        "unexpanded_home_root",
        "root_with_a_control_character",
        "root_too_long",
        "relative_snapshot",
        "snapshot_with_a_newline",
    ],
)
def test_path_that_is_not_absolute_names_the_variable_not_the_value(
    variable_name: str, value: str
) -> None:
    environment = {
        "CVE_KGRAG_FIGHT_SNAPSHOT_PATH": "/srv/fight.yaml",
        "CVE_KGRAG_FIGHT_SNAPSHOT_SHA256": SNAPSHOT_SHA256,
        variable_name: value,
    }

    with pytest.raises(SettingsError) as raised:
        load_settings(environment)

    assert str(raised.value).startswith(f"invalid settings: {variable_name}: ")
    assert_secret_absent(describe_raised(raised.value), value, "the settings error")
    assert raised.value.__context__ is None


@pytest.mark.parametrize(
    "snapshot_sha256",
    ["59A9ADDB" + "0" * 56, "0" * 63, "0" * 65, "sha256:" + "0" * 64],
    ids=["upper_case", "too_short", "too_long", "prefixed"],
)
def test_snapshot_hash_that_is_not_lower_case_hex_names_the_variable(
    snapshot_sha256: str,
) -> None:
    environment = {
        "CVE_KGRAG_FIGHT_SNAPSHOT_PATH": "/srv/fight.yaml",
        "CVE_KGRAG_FIGHT_SNAPSHOT_SHA256": snapshot_sha256,
    }

    with pytest.raises(SettingsError) as raised:
        load_settings(environment)

    assert str(raised.value).startswith("invalid settings: CVE_KGRAG_FIGHT_SNAPSHOT_SHA256: ")
    assert snapshot_sha256 not in describe_raised(raised.value)


@pytest.mark.parametrize(
    ("present_variable", "value", "missing_variable"),
    [
        ("CVE_KGRAG_FIGHT_SNAPSHOT_SHA256", SNAPSHOT_SHA256, "CVE_KGRAG_FIGHT_SNAPSHOT_PATH"),
    ],
    ids=["hash_without_path"],
)
def test_snapshot_hash_without_a_path_is_refused(
    present_variable: str, value: str, missing_variable: str
) -> None:
    with pytest.raises(SettingsError) as raised:
        load_settings({present_variable: value})

    assert str(raised.value) == (
        f"invalid settings: {missing_variable}: required with {present_variable}"
    )


@pytest.mark.parametrize("source", ["FIGHT", "MITRE"])
def test_snapshot_path_without_expected_hash_is_configured(source: str) -> None:
    # Arrange
    path = "/srv/snapshot"

    # Act
    settings = load_settings({f"CVE_KGRAG_{source}_SNAPSHOT_PATH": path})
    snapshot = settings.fight_snapshot if source == "FIGHT" else settings.mitre_snapshot

    # Assert
    assert snapshot is not None
    assert snapshot.path == Path(path)
    assert snapshot.sha256 is None
