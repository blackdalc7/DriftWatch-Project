"""Settings, read once from environment variables (or a ``.env`` file loaded by the process manager).

Every setting has a safe default for the docker-compose lab. Secrets (the admin token and the proxy
shared secret) have no default: the server refuses to start without them.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(ValueError):
    """Raised when a required setting is missing or malformed."""


def _int(env: dict[str, str], name: str, default: int, minimum: int = 0) -> int:
    raw = env.get(name)
    if raw in (None, ""):
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from None
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}")
    return value


def _list(env: dict[str, str], name: str, default: str) -> list[str]:
    return [p.strip() for p in env.get(name, default).split(",") if p.strip()]


@dataclass(frozen=True)
class Settings:
    """All runtime configuration for the server and CLI."""

    data_dir: Path
    library_dirs: list[Path]
    rules_dir: Path
    admin_token: str
    proxy_secret: str
    signing_key_path: Path
    ca_cert_path: Path
    ca_key_path: Path
    heartbeat_interval: int = 30
    offline_after: int = 120
    agent_cert_days: int = 30
    elastic_url: str = "http://localhost:9200"
    elastic_user: str | None = None
    elastic_password: str | None = None
    elastic_verify_tls: bool = True
    telemetry_index: str = "logs-*"
    alerts_index: str = ".alerts-security.alerts-*"
    evaluation_delay: int = 120
    evidence_dir: Path = field(default_factory=lambda: Path("evidence"))
    lab_tags: list[str] = field(default_factory=lambda: ["lab"])
    scheduler_enabled: bool = True
    scheduler_tick: int = 60
    timezone: str = "UTC"
    hygiene_interval: int = 3600
    bundle_ttl: int = 900

    @property
    def db_path(self) -> Path:
        return self.data_dir / "driftwatch.sqlite3"


def load_settings(env: dict[str, str] | None = None, require_secrets: bool = True) -> Settings:
    """Build :class:`Settings` from ``env`` (defaults to ``os.environ``)."""
    env = dict(os.environ if env is None else env)
    data_dir = Path(env.get("DRIFTWATCH_DATA_DIR", "data"))
    admin_token = env.get("DRIFTWATCH_ADMIN_TOKEN", "")
    proxy_secret = env.get("DRIFTWATCH_PROXY_SECRET", "")
    if require_secrets:
        if len(admin_token) < 24:
            raise ConfigError("DRIFTWATCH_ADMIN_TOKEN must be set to at least 24 characters")
        if len(proxy_secret) < 24:
            raise ConfigError("DRIFTWATCH_PROXY_SECRET must be set to at least 24 characters")
    pki = Path(env.get("DRIFTWATCH_PKI_DIR", str(data_dir / "pki")))
    heartbeat = _int(env, "DRIFTWATCH_HEARTBEAT_INTERVAL", 30, minimum=5)
    return Settings(
        data_dir=data_dir,
        library_dirs=[Path(p) for p in _list(env, "DRIFTWATCH_LIBRARY_DIRS", "library/tests,library/drafts")],
        rules_dir=Path(env.get("DRIFTWATCH_RULES_DIR", "rules")),
        admin_token=admin_token,
        proxy_secret=proxy_secret,
        signing_key_path=Path(env.get("DRIFTWATCH_SIGNING_KEY", str(pki / "bundle-signing.key"))),
        ca_cert_path=pki / "ca.crt",
        ca_key_path=pki / "ca.key",
        heartbeat_interval=heartbeat,
        offline_after=_int(env, "DRIFTWATCH_OFFLINE_AFTER", heartbeat * 4, minimum=heartbeat),
        agent_cert_days=_int(env, "DRIFTWATCH_AGENT_CERT_DAYS", 30, minimum=1),
        elastic_url=env.get("DRIFTWATCH_ELASTIC_URL", "http://localhost:9200").rstrip("/"),
        elastic_user=env.get("DRIFTWATCH_ELASTIC_USER") or None,
        elastic_password=env.get("DRIFTWATCH_ELASTIC_PASSWORD") or None,
        elastic_verify_tls=env.get("DRIFTWATCH_ELASTIC_VERIFY_TLS", "true").lower() != "false",
        telemetry_index=env.get("DRIFTWATCH_TELEMETRY_INDEX", "logs-*"),
        alerts_index=env.get("DRIFTWATCH_ALERTS_INDEX", ".alerts-security.alerts-*"),
        evaluation_delay=_int(env, "DRIFTWATCH_EVALUATION_DELAY", 120, minimum=0),
        evidence_dir=Path(env.get("DRIFTWATCH_EVIDENCE_DIR", str(data_dir / "evidence"))),
        lab_tags=_list(env, "DRIFTWATCH_LAB_TAGS", "lab"),
        scheduler_enabled=env.get("DRIFTWATCH_SCHEDULER", "on").lower() != "off",
        scheduler_tick=_int(env, "DRIFTWATCH_SCHEDULER_TICK", 60, minimum=5),
        timezone=env.get("DRIFTWATCH_TIMEZONE", "UTC"),
        hygiene_interval=_int(env, "DRIFTWATCH_HYGIENE_INTERVAL", 3600, minimum=300),
        bundle_ttl=_int(env, "DRIFTWATCH_BUNDLE_TTL", 900, minimum=60),
    )
