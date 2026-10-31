"""The typed settings boundary: the only code that reads configuration (ADR 0004).

Settings come from the environment variables named here, read once at the entry point;
an empty variable counts as unset, and an unset one takes its default. Nothing else is
read: no configuration file, no ``.env`` file, and no command-line flag, which would leave
a key in shell history and process listings.

A setting may be a credential, so no error names a value: ``SettingsError`` names the
variables and what was wrong with each, and the API key is a ``SecretStr``, masked in
every repr and JSON dump, until an adapter builds its request header from it.
"""

import hashlib
import ipaddress
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Literal, TypeVar
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator

from cve_kgrag.domain.evidence import SHA256_PATTERN
from cve_kgrag.domain.planning import MODEL_NAME_PATTERN, REASONING_EFFORT_PATTERN

PLANNER_ENABLED_VARIABLE = "CVE_KGRAG_PLANNER_ENABLED"
# The variables an enabled planner reads, and the field each sets.
PLANNER_VARIABLES = {
    "CVE_KGRAG_PLANNER_BASE_URL": "base_url",
    "CVE_KGRAG_PLANNER_MODEL_NAME": "model_name",
    "CVE_KGRAG_PLANNER_API_KEY": "api_key",
    "CVE_KGRAG_PLANNER_REASONING_EFFORT": "reasoning_effort",
}
SEMANTIC_ENABLED_VARIABLE = "CVE_KGRAG_SEMANTIC_ENABLED"
# The variables an enabled semantic channel reads, and the field each sets.
SEMANTIC_VARIABLES = {
    "CVE_KGRAG_SEMANTIC_COLLECTION_NAME": "collection_name",
    "CVE_KGRAG_SEMANTIC_PERSIST_DIRECTORY": "persist_directory",
    "CVE_KGRAG_SEMANTIC_MODEL_NAME": "model_name",
}
# The variables the HTTP servers read, and the field each sets; the section has no switch,
# since a server is started by its own command (ADR 0007).
HTTP_VARIABLES = {
    "CVE_KGRAG_HTTP_HOST": "host",
    "CVE_KGRAG_HTTP_TOKEN": "token",
    "CVE_KGRAG_MCP_HTTP_PORT": "mcp_port",
    "CVE_KGRAG_API_PORT": "api_port",
}
# The variables naming the served data, and the field each sets; the section has no switch:
# an unset store root serves the packaged fixture, an unset snapshot the packaged excerpt
# (ADR 0009 §3).
SERVED_DATA_VARIABLES = {
    "CVE_KGRAG_STORE_ROOT": "store_root",
    "CVE_KGRAG_MITRE_SNAPSHOT_PATH": "mitre_snapshot_path",
    "CVE_KGRAG_MITRE_SNAPSHOT_SHA256": "mitre_snapshot_sha256",
    "CVE_KGRAG_FIGHT_SNAPSHOT_PATH": "fight_snapshot_path",
    "CVE_KGRAG_FIGHT_SNAPSHOT_SHA256": "fight_snapshot_sha256",
}
MAX_PATH_CHARS = 4096
INVALID_ABSOLUTE_PATH = "must be an absolute path with no control character"
# A bearer token as RFC 6750 writes one (``b64token``), long enough to be a generated
# secret, for example ``python -c "import secrets; print(secrets.token_urlsafe(32))"``.
HTTP_TOKEN_PATTERN = r"^[A-Za-z0-9._~+/-]+=*$"
MIN_HTTP_TOKEN_CHARS = 32
MAX_HTTP_TOKEN_CHARS = 512
INVALID_HTTP_TOKEN = (
    f"must be {MIN_HTTP_TOKEN_CHARS} to {MAX_HTTP_TOKEN_CHARS} characters of letters, digits "
    "and -._~+/, optionally ending in ="
)
# Chroma's collection name rule; a sentence-transformers model is a hub name or a path.
COLLECTION_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{1,61}[A-Za-z0-9]$"
EMBEDDING_MODEL_PATTERN = r"^[A-Za-z0-9._/-]{1,256}$"
TRUE_SPELLINGS = frozenset({"true", "1", "yes", "on"})
FALSE_SPELLINGS = frozenset({"false", "0", "no", "off"})
LOOPBACK_HOST_NAME = "localhost"
DEFAULT_PORTS = {"https": 443, "http": 80}
# Characters no endpoint URL holds: each of the first could make two URL parsers disagree
# on its host, and ``?`` and ``#`` start a query or a fragment, even an empty one.
FORBIDDEN_URL_CHARACTERS = frozenset(" \t\r\n\\%?#")
INVALID_ENDPOINT_URL = (
    "must be an ASCII https URL, or an http URL to a loopback host, with a host and without "
    "credentials, a query or a fragment"
)
# A key is sent in an HTTP header, so it is printable ASCII without whitespace.
API_KEY_PATTERN = r"^[\x21-\x7e]{1,1024}$"
INVALID_API_KEY = "must be 1 to 1024 printable ASCII characters without whitespace"


class SettingsError(ValueError):
    """The environment holds invalid settings; the message names variables, never values."""


SectionSettings = TypeVar("SectionSettings", bound=BaseModel)


def is_loopback_host(host: str) -> bool:
    if host == LOOPBACK_HOST_NAME:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_endpoint_url(url: str) -> str:
    """``url`` as an endpoint a credential may be sent to: ASCII, https or http only to a
    loopback host, with a host, a port other than 0 if any, and no user information, query or
    fragment; returned with one trailing ``/`` removed, the one spelling difference the
    adapter contract makes equivalent (``ModelPortFactory``). Raises ``ValueError`` with a
    message that does not quote the URL."""
    if not url.isascii() or any(
        character in FORBIDDEN_URL_CHARACTERS or not character.isprintable() for character in url
    ):
        raise ValueError(INVALID_ENDPOINT_URL)
    try:
        parts = urlsplit(url)
        host = parts.hostname
        # Reading the port raises ValueError for one that is not a number in range.
        port = parts.port
    except ValueError:
        raise ValueError(INVALID_ENDPOINT_URL) from None
    has_credentials = parts.username is not None or parts.password is not None
    if not host or port == 0 or has_credentials or parts.query or parts.fragment:
        raise ValueError(INVALID_ENDPOINT_URL)
    is_allowed_scheme = parts.scheme == "https" or (
        parts.scheme == "http" and is_loopback_host(host)
    )
    if not is_allowed_scheme:
        raise ValueError(INVALID_ENDPOINT_URL)
    return url.removesuffix("/")


def fingerprint_endpoint(url: str) -> str:
    """SHA-256 of ``url`` normalized to scheme, lower-case host and port (the scheme's
    default when none is written), with its path exactly as written, so spellings of one
    endpoint share one fingerprint, any other difference (another port, another path)
    gives another, and the fingerprint names no host. ``check_endpoint_url`` has already
    removed the one trailing ``/`` the adapter contract makes equivalent. Raises
    ``ValueError`` for a URL without a host."""
    parts = urlsplit(url)
    host = parts.hostname
    if host is None:
        raise ValueError(INVALID_ENDPOINT_URL)
    port = parts.port if parts.port is not None else DEFAULT_PORTS[parts.scheme]
    normalized_url = f"{parts.scheme}://{host}:{port}{parts.path}"
    return hashlib.sha256(normalized_url.encode()).hexdigest()


class ModelPlannerSettings(BaseModel):
    """An enabled model planner: the OpenAI-compatible endpoint it plans through, the model
    it names, and the key that authenticates it. A missing key leaves the planner
    unavailable rather than failing the service (brief §15)."""

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    base_url: str
    model_name: str = Field(pattern=MODEL_NAME_PATTERN)
    api_key: SecretStr | None = None
    reasoning_effort: str | None = Field(
        default=None,
        pattern=REASONING_EFFORT_PATTERN,
        description="Sent as the request's reasoning_effort only when set.",
    )

    @field_validator("base_url")
    @classmethod
    def check_base_url(cls, base_url: str) -> str:
        return check_endpoint_url(base_url)

    @field_validator("api_key")
    @classmethod
    def check_api_key(cls, api_key: SecretStr | None) -> SecretStr | None:
        if api_key is not None and not re.fullmatch(API_KEY_PATTERN, api_key.get_secret_value()):
            raise ValueError(INVALID_API_KEY)
        return api_key


class SemanticSettings(BaseModel):
    """An enabled semantic channel: the Chroma collection it searches, the directory that
    holds it (relative to the working directory unless absolute; required, since this
    repository builds no store) and the sentence-transformers model that embeds queries.
    The collection and model defaults are those of the store CVE-KGRAG's RAG pipeline
    builds, which the adapter reads (ADR 0006)."""

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    collection_name: str = Field(default="cve_documents", pattern=COLLECTION_NAME_PATTERN)
    persist_directory: str = Field(min_length=1, max_length=4096)
    model_name: str = Field(
        default="sentence-transformers/all-MiniLM-L6-v2", pattern=EMBEDDING_MODEL_PATTERN
    )

    @field_validator("persist_directory")
    @classmethod
    def check_persist_directory(cls, persist_directory: str) -> str:
        if not persist_directory.isprintable():
            raise ValueError("must hold no control character")
        return persist_directory


class HttpSettings(BaseModel):
    """What the HTTP servers listen on and the bearer token every route but ``/health``
    requires. Only loopback is accepted; a server without a token refuses to start, so
    the token is optional here and required by the command that serves."""

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    # Loopback written as the one literal each address family has, so the hosts a
    # request may name are a closed list (no other 127/8 address, no name to resolve).
    host: Literal["127.0.0.1", "::1"] = "127.0.0.1"
    token: SecretStr | None = None
    mcp_port: int = Field(default=8765, ge=1, le=65535)
    api_port: int = Field(default=8766, ge=1, le=65535)

    @field_validator("token")
    @classmethod
    def check_token(cls, token: SecretStr | None) -> SecretStr | None:
        if token is None:
            return None
        token_text = token.get_secret_value()
        is_token_length = MIN_HTTP_TOKEN_CHARS <= len(token_text) <= MAX_HTTP_TOKEN_CHARS
        if not is_token_length or not re.fullmatch(HTTP_TOKEN_PATTERN, token_text):
            raise ValueError(INVALID_HTTP_TOKEN)
        return token


def check_absolute_path(path: Path) -> Path:
    path_text = str(path)
    if not path.is_absolute() or not path_text.isprintable() or len(path_text) > MAX_PATH_CHARS:
        raise ValueError(INVALID_ABSOLUTE_PATH)
    return path


class ServedDataVariables(BaseModel):
    """The served-data variables as read, each checked on its own; ``load_settings``
    checks that the snapshot's path and hash are set together, so its error names the
    variable that is missing."""

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    store_root: Path | None = None
    mitre_snapshot_path: Path | None = None
    mitre_snapshot_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    fight_snapshot_path: Path | None = None
    fight_snapshot_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)

    @field_validator("store_root", "fight_snapshot_path", "mitre_snapshot_path")
    @classmethod
    def check_path(cls, path: Path | None) -> Path | None:
        if path is None:
            return None
        return check_absolute_path(path)


class FightSnapshotSettings(BaseModel):
    """An operator FiGHT snapshot: the file and the SHA-256 it must have. Whether the
    catalog lists that hash is checked when a command loads the snapshot (ADR 0009 §11)."""

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    path: Path
    sha256: str = Field(pattern=SHA256_PATTERN)


class MitreSnapshotSettings(BaseModel):
    """The operator's derived mapping file and its required SHA-256."""

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    path: Path
    sha256: str = Field(pattern=SHA256_PATTERN)


class ServiceSettings(BaseModel):
    """Every setting a service reads; a switched section is ``None`` unless it is enabled.
    ``store_root`` is ``None`` when the packaged fixture is served, and ``fight_snapshot``
    when the packaged FiGHT excerpt is."""

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    model_planner: ModelPlannerSettings | None = None
    semantic: SemanticSettings | None = None
    http: HttpSettings = HttpSettings()
    store_root: Path | None = None
    fight_snapshot: FightSnapshotSettings | None = None
    mitre_snapshot: MitreSnapshotSettings | None = None


def find_section_variable(section_variables: Mapping[str, str], field_name: str) -> str:
    """The variable of a section that sets ``field_name``."""
    for variable_name, variable_field in section_variables.items():
        if variable_field == field_name:
            return variable_name
    raise ValueError(f"no variable sets {field_name}")


def parse_switch(environment: Mapping[str, str], variable_name: str) -> bool | SettingsError:
    """Whether the switch ``variable_name`` is on (off when unset or empty)."""
    spelling = environment.get(variable_name, "").strip().lower()
    if not spelling or spelling in FALSE_SPELLINGS:
        return False
    if spelling in TRUE_SPELLINGS:
        return True
    return SettingsError(f"invalid settings: {variable_name}: must be true or false")


def parse_section(
    environment: Mapping[str, str],
    section_variables: Mapping[str, str],
    section_model: type[SectionSettings],
) -> SectionSettings | SettingsError:
    """A section's settings, or one error naming each invalid variable and what was wrong,
    read without the input. Returned rather than raised, so the caller raises it outside
    this ``except`` and it carries no reference to the error that held the values."""
    section_fields: dict[str, str] = {}
    for variable_name, field_name in section_variables.items():
        value = environment.get(variable_name, "")
        if value:
            section_fields[field_name] = value
    try:
        return section_model.model_validate(section_fields)
    except ValidationError as error:
        problems: list[str] = []
        for field_error in error.errors(
            include_url=False, include_context=False, include_input=False
        ):
            variable_name = find_section_variable(section_variables, str(field_error["loc"][0]))
            problems.append(f"{variable_name}: {field_error['msg']}")
        return SettingsError("invalid settings: " + "; ".join(problems))


def require_section(
    environment: Mapping[str, str],
    section_variables: Mapping[str, str],
    section_model: type[SectionSettings],
) -> SectionSettings:
    """A section's settings (``parse_section``); raises its ``SettingsError``, outside
    the ``except`` that built it."""
    section_settings = parse_section(environment, section_variables, section_model)
    if isinstance(section_settings, SettingsError):
        raise section_settings
    return section_settings


def load_section(
    environment: Mapping[str, str],
    switch_variable: str,
    section_variables: Mapping[str, str],
    section_model: type[SectionSettings],
) -> SectionSettings | None:
    """A section's settings when its switch is on, else ``None`` with its other variables
    unread. Raises ``SettingsError`` for an invalid switch or variable."""
    is_enabled = parse_switch(environment, switch_variable)
    if isinstance(is_enabled, SettingsError):
        raise is_enabled
    if not is_enabled:
        return None
    return require_section(environment, section_variables, section_model)


def pair_fight_snapshot(served_data: ServedDataVariables) -> FightSnapshotSettings | None:
    """The snapshot the path and hash name, ``None`` when neither is set. Raises
    ``SettingsError`` naming the one that is missing when only the other is set."""
    path = served_data.fight_snapshot_path
    sha256 = served_data.fight_snapshot_sha256
    if path is None and sha256 is None:
        return None
    if path is None or sha256 is None:
        missing_field = "fight_snapshot_path" if path is None else "fight_snapshot_sha256"
        present_field = "fight_snapshot_sha256" if path is None else "fight_snapshot_path"
        missing_variable = find_section_variable(SERVED_DATA_VARIABLES, missing_field)
        present_variable = find_section_variable(SERVED_DATA_VARIABLES, present_field)
        raise SettingsError(
            f"invalid settings: {missing_variable}: required with {present_variable}"
        )
    return FightSnapshotSettings(path=path, sha256=sha256)


def pair_mitre_snapshot(served_data: ServedDataVariables) -> MitreSnapshotSettings | None:
    """Require both MITRE variables together; an unset pair serves the packaged excerpt."""
    path = served_data.mitre_snapshot_path
    sha256 = served_data.mitre_snapshot_sha256
    if path is None and sha256 is None:
        return None
    if path is None or sha256 is None:
        raise SettingsError(
            "invalid settings: CVE_KGRAG_MITRE_SNAPSHOT_PATH and "
            "CVE_KGRAG_MITRE_SNAPSHOT_SHA256 must be set together"
        )
    return MitreSnapshotSettings(path=path, sha256=sha256)


def load_settings(environment: Mapping[str, str]) -> ServiceSettings:
    """The settings ``environment`` holds. Raises ``SettingsError``, naming the variables
    and never their values, when any is invalid. A switched section's variables are read
    only when its switch (``CVE_KGRAG_PLANNER_ENABLED``, ``CVE_KGRAG_SEMANTIC_ENABLED``) is
    on; the HTTP and served-data variables are always read. Nothing is opened: whether
    the store root or the snapshot can be used is checked by the commands that load them."""
    http_settings = require_section(environment, HTTP_VARIABLES, HttpSettings)
    served_data = require_section(environment, SERVED_DATA_VARIABLES, ServedDataVariables)
    fight_snapshot = pair_fight_snapshot(served_data)
    return ServiceSettings(
        model_planner=load_section(
            environment, PLANNER_ENABLED_VARIABLE, PLANNER_VARIABLES, ModelPlannerSettings
        ),
        semantic=load_section(
            environment, SEMANTIC_ENABLED_VARIABLE, SEMANTIC_VARIABLES, SemanticSettings
        ),
        http=http_settings,
        store_root=served_data.store_root,
        fight_snapshot=fight_snapshot,
        mitre_snapshot=pair_mitre_snapshot(served_data),
    )
