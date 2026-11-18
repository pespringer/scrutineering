"""Every setting the Python services read from the environment, in one place.

Code reads configuration only through `get_settings()`; nothing else in `src/` reads
`os.environ` for a setting (a test enforces it). An invalid value fails with the
variable's name. An empty value means "use the default", since Compose passes unset
variables as empty strings. `docs/CONFIGURATION.md` is generated from this module:

    python -m src.config > docs/CONFIGURATION.md
"""

from __future__ import annotations

import ipaddress
import json
import sys
from dataclasses import dataclass
from typing import Annotated, Literal, Mapping

from pydantic import Field, SecretStr, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

API, WORKER, BEAT = "api", "worker", "beat"
ALL = (API, WORKER, BEAT)
CommaList = Annotated[list[str], NoDecode]
ROLES = ("dashboard", "operator", "remediator", "security-operator", "admin")
# RemediationStatus values (src/db/models.py), kept here so settings don't import the models.
REMEDIATION_STATUSES = (
    "proposed",
    "approved",
    "building",
    "verifying",
    "needs_acceptance",
    "ready",
    "published",
    "completed",
    "failed",
    "cancelled",
)


def plain_http_allowed(url: str) -> bool:
    """`http://` is allowed only to a private address or a single-label host (a LAN receiver)."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    if parts.scheme != "http" or not parts.hostname:
        return False
    try:
        return ipaddress.ip_address(parts.hostname).is_private
    except ValueError:
        return "." not in parts.hostname


def setting(default, description: str, group: str, used_by: tuple[str, ...], **constraints):
    """A field with what the generated documentation needs to describe it."""
    return Field(
        default, description=description, json_schema_extra={"group": group, "used_by": used_by}, **constraints
    )


class Settings(BaseSettings):
    """Field `foo_bar` is read from the environment variable `FOO_BAR`."""

    model_config = SettingsConfigDict(case_sensitive=False, env_ignore_empty=True, extra="ignore", frozen=True)

    # -- Database ---------------------------------------------------------------
    database_url: SecretStr = setting(
        SecretStr(""), "SQLAlchemy URL of the Postgres database. Required.", "Database", ALL
    )
    async_database_url: SecretStr = setting(
        SecretStr(""), "Async SQLAlchemy URL. Derived from `DATABASE_URL` when empty.", "Database", (API,)
    )
    db_pool_size: int = setting(20, "Connections kept in each process's pool.", "Database", ALL, ge=1, le=100)
    db_max_overflow: int = setting(10, "Extra connections allowed above the pool size.", "Database", ALL, ge=1, le=100)

    # -- Queue ------------------------------------------------------------------
    celery_broker_url: str = setting("redis://localhost:6379/0", "Celery broker.", "Queue", ALL)
    celery_result_backend: str = setting("redis://localhost:6379/1", "Celery result backend.", "Queue", ALL)
    redis_url: str = setting(
        "redis://localhost:6379/0",
        "Redis for the shared scan cache (`SCANNER_CACHE_BACKEND=redis`) and the runtime discovery status.",
        "Queue",
        (API, WORKER),
    )

    # -- API and access ---------------------------------------------------------
    python_api_key: SecretStr = setting(
        SecretStr(""), "Key the dashboard sends to the API. Required.", "API and access", (API,)
    )
    dashboard_default_roles: CommaList = setting(
        ["dashboard", "operator"],
        "Roles of API-key sessions. `remediator` and `security-operator` are needed to propose, approve, "
        "execute and publish remediations.",
        "API and access",
        (API,),
    )
    dashboard_auth_mode: Literal["local", "trusted-proxy"] = setting(
        "local",
        "`local`: no sign-in, every session gets `DASHBOARD_DEFAULT_ROLES` (trusted networks only). "
        "`trusted-proxy`: a forward-auth proxy signs users in (docs/design/forward-auth.md). Read by the API "
        "and the dashboard.",
        "API and access",
        (API,),
    )
    dashboard_group_roles: CommaList = setting(
        [],
        "`group=role` pairs mapping identity-provider groups to roles, e.g. "
        "`ops=operator,security=security-operator`. Empty: group names are used as role names.",
        "API and access",
        (API,),
    )
    dashboard_trusted_proxy_secret: SecretStr = setting(
        SecretStr(""),
        "Shared secret of a trusted ingress that forwards verified user identity headers.",
        "API and access",
        (API,),
    )
    service_auth_secret: SecretStr = setting(
        SecretStr(""), "HMAC secret for signed service-to-service requests.", "API and access", (API,)
    )
    service_auth_required: bool = setting(
        False, "Require signed service requests instead of accepting the API key.", "API and access", (API,)
    )
    service_auth_max_skew_seconds: int = setting(
        300, "Allowed clock skew for signed service requests.", "API and access", (API,), ge=1
    )
    node_env: str = setting("", "`production` refuses SQLite database URLs.", "API and access", ALL)
    scrutineering_version: str = setting("1.0", "Version reported by `/version`.", "API and access", (API,))
    scrutineering_revision: str = setting("unknown", "Revision reported by `/version`.", "API and access", (API,))

    # -- Local registry ---------------------------------------------------------
    local_registry_host: str = setting(
        "registry:5000", "The bundled registry as the services reach it.", "Local registry", ALL
    )
    local_registry_url: str = setting(
        "", "Its URL for the services. Derived from the host when empty.", "Local registry", (API,)
    )
    local_registry_public_host: str = setting(
        "localhost:5000", "The bundled registry as you push to it from the host.", "Local registry", (API,)
    )
    local_registry_public_url: str = setting(
        "", "Its URL from the host. Derived from the public host when empty.", "Local registry", (API,)
    )
    registry_insecure: bool = setting(
        False,
        "Allow plain HTTP to the local registry (and `localhost`) only. Every other registry uses TLS.",
        "Local registry",
        ALL,
    )

    # -- Scanning ---------------------------------------------------------------
    scanner_timeout: int = setting(600, "Seconds one scanner may run against one image.", "Scanning", (WORKER,), ge=1)
    scanner_max_output_bytes: int = setting(50_000_000, "Largest scanner report accepted.", "Scanning", (WORKER,), ge=1)
    scanner_max_findings: int = setting(100_000, "Most findings accepted from one report.", "Scanning", (WORKER,), ge=1)
    scanner_retry_attempts: int = setting(2, "Retries for transient scanner failures.", "Scanning", (WORKER,), ge=0)
    scanner_retry_backoff_seconds: float = setting(
        5.0, "First retry delay; it doubles each retry.", "Scanning", (WORKER,), ge=0
    )
    scanner_cache_dir: str = setting("/tmp/trivy-cache", "Trivy's cache directory.", "Scanning", (WORKER,))
    scanner_cache_backend: Literal["local", "redis"] = setting(
        "local", "Where scan results are cached: per worker, or shared in Redis.", "Scanning", (WORKER,)
    )
    scanner_cache_ttl_seconds: int = setting(3600, "How long cached results are reused.", "Scanning", (WORKER,), ge=1)
    require_immutable_scan_identity: bool = setting(
        False,
        "Fail a scan whose tag cannot be resolved to a digest, instead of scanning by tag.",
        "Scanning",
        (WORKER,),
    )
    scan_cooldown_seconds: int = setting(
        3600, "Scheduled scans skip images scanned this recently.", "Scanning", (WORKER,), ge=0
    )
    schedule_cron_scan: str = setting(
        "0 */6 * * *", "Cron expression (five fields) for scheduled rescans of known images.", "Scanning", (BEAT,)
    )

    # -- Runtime discovery ------------------------------------------------------
    scan_runtime_discovery_enabled: bool = setting(
        False,
        "Every 15 minutes, record the images of running containers and scan new ones "
        "(docs/design/runtime-discovery.md).",
        "Runtime discovery",
        (WORKER,),
    )
    scan_runtime_use_containerd: bool = setting(
        False, "List containers with `ctr` instead of `docker`.", "Runtime discovery", (WORKER,)
    )
    scan_runtime_docker_bin: str = setting(
        "docker", "Docker CLI to list containers with.", "Runtime discovery", (WORKER,)
    )
    scan_runtime_ctr_bin: str = setting(
        "ctr", "containerd CLI to list containers with.", "Runtime discovery", (WORKER,)
    )
    scan_runtime_containerd_namespace: str = setting(
        "default", "containerd namespace to list.", "Runtime discovery", (WORKER,)
    )
    scan_runtime_include_images: CommaList = setting(
        [], "Only images matching these glob patterns.", "Runtime discovery", (WORKER,)
    )
    scan_runtime_exclude_images: CommaList = setting(
        [], "Skip images matching these glob patterns.", "Runtime discovery", (WORKER,)
    )
    scan_runtime_exclude_containers: CommaList = setting(
        [], "Skip containers whose names match these glob patterns.", "Runtime discovery", (WORKER,)
    )
    scan_runtime_include_label: str = setting(
        "", "Only containers with this `key=value` label.", "Runtime discovery", (WORKER,)
    )
    scan_runtime_max_images: int = setting(
        100,
        "Most scans queued per discovery run; every running image is still recorded.",
        "Runtime discovery",
        (WORKER,),
        ge=1,
    )

    # -- Registry credentials ---------------------------------------------------
    dockerhub_username: str = setting("", "Docker Hub user, with `DOCKERHUB_PASSWORD`.", "Registry credentials", ALL)
    dockerhub_password: SecretStr = setting(SecretStr(""), "Docker Hub password or token.", "Registry credentials", ALL)
    github_username: str = setting(
        "gh_token", "User name sent with `GITHUB_TOKEN` to ghcr.io.", "Registry credentials", ALL
    )
    gitlab_username: str = setting(
        "gitlab-ci-token", "User name sent with the GitLab token to registry.gitlab.com.", "Registry credentials", ALL
    )
    gitlab_token: SecretStr = setting(SecretStr(""), "Token for registry.gitlab.com.", "Registry credentials", ALL)
    ci_job_token: SecretStr = setting(
        SecretStr(""), "GitLab CI job token, used when `GITLAB_TOKEN` is empty.", "Registry credentials", ALL
    )
    registry_credentials_json: SecretStr = setting(
        SecretStr(""),
        'Credentials for any other registry: `{"harbor.example": {"username": "bot", "password": "..."}}`.',
        "Registry credentials",
        ALL,
    )
    aws_access_key_id: str = setting(
        "", "AWS key for ECR, read by the scanners. Must be set with the secret.", "Registry credentials", (WORKER,)
    )
    aws_secret_access_key: SecretStr = setting(
        SecretStr(""), "AWS secret for ECR, read by the scanners.", "Registry credentials", (WORKER,)
    )

    # -- Remediation and GitHub -------------------------------------------------
    remediation_execution_enabled: bool = setting(
        False,
        "Allow approved remediations to patch the source, build a candidate and scan it.",
        "Remediation and GitHub",
        (API,),
    )
    remediation_sources_root: str = setting(
        "/workspace/sources", "Where the worker finds local source repositories.", "Remediation and GitHub", (WORKER,)
    )
    buildkit_host: str = setting(
        "tcp://buildkitd:1234",
        "The rootless BuildKit service candidates are built on.",
        "Remediation and GitHub",
        (WORKER,),
    )
    github_token: SecretStr = setting(
        SecretStr(""),
        "Opens pull requests and clones github.com sources (Contents and Pull requests read/write on the "
        "source repositories), and pulls from ghcr.io.",
        "Remediation and GitHub",
        ALL,
    )
    github_webhook_secret: SecretStr = setting(
        SecretStr(""), "Verifies the `pull_request` webhook that reports merges.", "Remediation and GitHub", (API,)
    )

    # -- Notifications ----------------------------------------------------------
    notification_slack_webhook_url: SecretStr = setting(
        SecretStr(""),
        "Slack incoming webhook (`https://hooks.slack.com/...`) to post notifications to.",
        "Notifications",
        (API, WORKER),
    )
    notification_webhook_url: SecretStr = setting(
        SecretStr(""),
        "Receiver for signed JSON notifications. `https://`, or `http://` to a private address or a "
        "single-label host name.",
        "Notifications",
        (API, WORKER),
    )
    notification_webhook_secret: SecretStr = setting(
        SecretStr(""),
        "Signs each webhook body (HMAC-SHA256). Required with `NOTIFICATION_WEBHOOK_URL`.",
        "Notifications",
        (API, WORKER),
    )
    notification_events: CommaList = setting(
        ["proposed", "needs_acceptance", "ready", "published", "completed", "failed"],
        "Remediation statuses that send a notification.",
        "Notifications",
        (API, WORKER),
    )
    dashboard_public_url: str = setting(
        "",
        "The dashboard's URL, for links in notifications. Links are left out when empty.",
        "Notifications",
        (API, WORKER),
    )

    # -- Tests ------------------------------------------------------------------
    scrutineering_test_mode: bool = setting(
        False, "Tests only: allow an in-memory database when `DATABASE_URL` is unset.", "Tests", ALL
    )

    @field_validator(
        "dashboard_default_roles",
        "scan_runtime_include_images",
        "scan_runtime_exclude_images",
        "scan_runtime_exclude_containers",
        "notification_events",
        "dashboard_group_roles",
        mode="before",
    )
    @classmethod
    def _comma_list(cls, value):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("registry_credentials_json")
    @classmethod
    def _credentials_json(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value().strip()
        if raw:
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError("must be valid JSON") from exc
            if not isinstance(parsed, dict):
                raise ValueError("must map registry hosts to credentials")
        return value

    @field_validator("dashboard_group_roles")
    @classmethod
    def _group_roles(cls, value: list[str]) -> list[str]:
        for pair in value:
            group, _, role = pair.partition("=")
            if not group.strip() or not role.strip():
                raise ValueError(f"{pair!r} is not a group=role pair")
            if role.strip() not in ROLES:
                raise ValueError(f"unknown role {role.strip()!r}; roles are {', '.join(ROLES)}")
        return [f"{pair.partition('=')[0].strip()}={pair.partition('=')[2].strip()}" for pair in value]

    @property
    def group_role_map(self) -> dict[str, list[str]]:
        mapping: dict[str, list[str]] = {}
        for pair in self.dashboard_group_roles:
            group, _, role = pair.partition("=")
            mapping.setdefault(group, []).append(role)
        return mapping

    @field_validator("notification_events")
    @classmethod
    def _notification_events(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - set(REMEDIATION_STATUSES))
        if unknown:
            raise ValueError(f"unknown remediation statuses: {', '.join(unknown)}")
        return value

    @field_validator("notification_webhook_url")
    @classmethod
    def _notification_url(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value().strip()
        if raw and not plain_http_allowed(raw) and not raw.startswith("https://"):
            raise ValueError("must be https://, or http:// to a private address or a single-label host")
        return value

    @field_validator("notification_slack_webhook_url")
    @classmethod
    def _slack_url(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value().strip()
        if raw and not raw.startswith("https://hooks.slack.com/"):
            raise ValueError("must be a Slack incoming webhook, https://hooks.slack.com/...")
        return value

    @model_validator(mode="after")
    def _trusted_proxy_secret(self):
        if self.dashboard_auth_mode == "trusted-proxy" and not self.dashboard_trusted_proxy_secret.get_secret_value():
            raise ValueError("DASHBOARD_TRUSTED_PROXY_SECRET is required with DASHBOARD_AUTH_MODE=trusted-proxy")
        return self

    @model_validator(mode="after")
    def _notification_secret(self):
        if self.notification_webhook_url.get_secret_value() and not self.notification_webhook_secret.get_secret_value():
            raise ValueError("NOTIFICATION_WEBHOOK_SECRET is required with NOTIFICATION_WEBHOOK_URL")
        return self


@dataclass(frozen=True)
class External:
    """A variable the Python services do not read: Compose, the dashboard or a scanner reads it."""

    name: str
    description: str
    read_by: str


EXTERNAL = (
    External("POSTGRES_USER", "Postgres user created by the Compose `postgres` service.", "Compose"),
    External("POSTGRES_PASSWORD", "Its password. Required.", "Compose"),
    External("POSTGRES_DB", "Database created by the `postgres` service.", "Compose"),
    External("POSTGRES_PORT", "Host port for Postgres with `docker-compose.host-access.yml`.", "Compose"),
    External("REDIS_PORT", "Host port for Redis with `docker-compose.host-access.yml`.", "Compose"),
    External("LOCAL_REGISTRY_PORT", "Host port of the bundled registry.", "Compose"),
    External("PYTHON_API_PORT", "Host port of the API.", "Compose"),
    External("DASHBOARD_PORT", "Host port of the dashboard.", "Compose"),
    External("REMEDIATION_HOST_SOURCES", "Host folder mounted read-only as the worker's sources root.", "Compose"),
    External(
        "CELERY_QUEUES",
        "Queues the worker consumes. Include `remediation.normal` to run remediations and `notify` to send "
        "notifications.",
        "Compose",
    ),
    External("CELERY_CONCURRENCY", "Worker processes.", "Compose"),
    External("CELERY_LOG_LEVEL", "Worker and beat log level.", "Compose"),
    External("DASHBOARD_API_URL", "API URL the dashboard server calls. Defaults to the Compose service.", "dashboard"),
    External("DASHBOARD_API_KEY", "Key the dashboard server sends. Defaults to `PYTHON_API_KEY`.", "dashboard"),
    External(
        "DASHBOARD_AUTH_HEADERS",
        "In `trusted-proxy` mode, whose headers carry the user: `scrutineering` (`x-authenticated-*`), "
        "`authelia`, `authentik` or `oauth2-proxy`.",
        "dashboard",
    ),
    External(
        "DASHBOARD_LOGOUT_URL", "Sign-out link shown in the header, e.g. your auth proxy's logout URL.", "dashboard"
    ),
    External("HOSTNAME", "Address the dashboard server listens on (Kubernetes sets `0.0.0.0`).", "dashboard"),
    External("PORT", "Port the dashboard server listens on.", "dashboard"),
    External("HOME", "The worker's home for git and npm; Kubernetes sets `/tmp` (read-only root).", "worker"),
    External("PGDATA", "Postgres data directory; Kubernetes uses a subdirectory of the volume.", "Postgres image"),
    External("REGISTRY_STORAGE_DELETE_ENABLED", "Lets the in-cluster registry delete images.", "registry image"),
    External("GRYPE_DB_CACHE_DIR", "Grype's vulnerability database directory.", "Grype"),
    External("GOOGLE_APPLICATION_CREDENTIALS", "Service account file for GCR and Artifact Registry.", "Trivy, Grype"),
)


class _MappingSettings(Settings):
    """Settings from an explicit mapping only (tests); the process environment is ignored."""

    @classmethod
    def settings_customise_sources(cls, settings_cls, init_settings, **other_sources):
        return (init_settings,)


def _environment_name(field: str) -> str:
    return field.upper()


def _friendly(error: ValidationError) -> ValueError:
    problems = []
    for item in error.errors():
        name = _environment_name(str(item["loc"][0])) if item.get("loc") else "settings"
        problems.append(f"{name}: {item['msg']}")
    return ValueError("invalid configuration: " + "; ".join(problems))


def get_settings(env: Mapping[str, str] | None = None) -> Settings:
    """The current settings, read from the environment (or from `env`, for tests) on every call."""
    try:
        if env is None:
            return Settings()
        values = {key.lower(): value for key, value in env.items() if str(value).strip() != ""}
        return _MappingSettings(**{key: value for key, value in values.items() if key in Settings.model_fields})
    except ValidationError as exc:
        raise _friendly(exc) from None


def _default(field) -> str:
    value = field.default
    if isinstance(value, SecretStr):
        value = value.get_secret_value()
    if isinstance(value, list):
        value = ",".join(value)
    if isinstance(value, bool):
        value = str(value).lower()
    return f"`{value}`" if value not in ("", None) else ""


def documentation() -> str:
    """docs/CONFIGURATION.md."""
    lines = [
        "# Configuration",
        "",
        "<!-- Generated by `python -m src.config > docs/CONFIGURATION.md`; edit src/config.py instead. -->",
        "",
        "Set these in `.env` (start from `.env.example`). The Python services read them only",
        "through `src/config.py`, which rejects invalid values by name when a service starts or",
        "a request needs them. An empty value means the default. Secrets are marked 🔒.",
    ]
    groups: dict[str, list[str]] = {}
    for name, field in Settings.model_fields.items():
        extra = field.json_schema_extra or {}
        secret = " 🔒" if field.annotation is SecretStr else ""
        row = (
            f"| `{_environment_name(name)}`{secret} | {_default(field)} | {field.description} "
            f"| {', '.join(extra['used_by'])} |"
        )
        groups.setdefault(extra["group"], []).append(row)
    for group, rows in groups.items():
        lines += ["", f"## {group}", "", "| Variable | Default | Meaning | Read by |", "|---|---|---|---|", *rows]
    lines += [
        "",
        "## Read by Compose, the dashboard or the scanners",
        "",
        "| Variable | Meaning | Read by |",
        "|---|---|---|",
        *[f"| `{item.name}` | {item.description} | {item.read_by} |" for item in EXTERNAL],
    ]
    return "\n".join(lines) + "\n"


def variable_names() -> set[str]:
    """Every documented environment variable."""
    return {_environment_name(name) for name in Settings.model_fields} | {item.name for item in EXTERNAL}


if __name__ == "__main__":
    sys.stdout.write(documentation())
