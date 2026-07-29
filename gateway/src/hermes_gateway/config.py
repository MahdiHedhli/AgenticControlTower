from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

DEFAULT_CLEARANCE_RISK_CHANNEL_MAP = {
    "observe": ("mobile_signed", "local_terminal"),
    "read_only": ("mobile_signed", "local_terminal"),
    "routine": ("mobile_signed", "local_terminal"),
    "external_effect": ("mobile_signed",),
    "destructive": ("mobile_signed",),
    "credential_or_secret": ("mobile_signed",),
    "safety_critical": ("mobile_signed",),
    "irreversible": ("mobile_signed",),
}


@dataclass(frozen=True)
class Settings:
    default_clearance_risk_channel_map: ClassVar[dict[str, tuple[str, ...]]] = (
        DEFAULT_CLEARANCE_RISK_CHANNEL_MAP
    )
    node_id: str = "node_local"
    node_display_name: str = "Local Hermes"
    node_environment: str = "homelab"
    node_fingerprint: str = "local-dev-fingerprint"
    gateway_base_url: str = "http://127.0.0.1:8787/v1"
    gateway_version: str = "0.1.0"
    hermes_version: str | None = None
    database_path: str = ".hermes-mobile-gateway/gateway.sqlite3"
    pairing_ttl_seconds: int = 300
    allowed_hermes_callers: tuple[str, ...] = ()
    cors_allowed_origin_regex: str | None = r"^http://(localhost|127\.0\.0\.1):[0-9]+$"
    tui_enable_local_pty: bool = False
    tui_allowed_commands: tuple[str, ...] = ("/bin/sh",)
    tui_default_command: str = "/bin/sh"
    tui_allowed_working_directory: str = "."
    tui_command_risk_family: dict[str, str] | None = None
    tui_allow_shell_commands: bool = False
    tui_max_sessions: int = 2
    tui_idle_timeout_seconds: int = 900
    tui_attach_token_ttl_seconds: int = 60
    tui_output_retention_enabled: bool = False
    clearance_enabled_channels: tuple[str, ...] = ("mobile_signed",)
    clearance_default_channel: str = "mobile_signed"
    clearance_local_terminal_enabled: bool = False
    clearance_default_deployment_trust_context: str = "untrusted_host"
    clearance_risk_channel_map: dict[str, tuple[str, ...]] | None = None
    # APNs push (token-based / .p8 key). Push payloads are wake-up hints only —
    # no secrets (ADR-0005). Unset => push_dispatch reports "unavailable".
    apns_key_path: str | None = None
    apns_key_id: str | None = None
    apns_team_id: str | None = None
    apns_topic: str = "app.act.agenticControlTower"
    apns_environment: str = "production"  # "production" or "sandbox"
    # Standing approval grants ("approve for this session" / "allow forever").
    # Every grant carries a HARD expiry — there is no unbounded standing
    # authorization, not even at scope=permanent. Defaults are deliberately
    # short enough that a forgotten grant lapses on its own:
    #   session   —  4h, roughly one working session
    #   agent     — 24h, a day of repeated invocations by one agent
    #   permanent — 30d, "allow forever" as a renewable standing order
    # ACT_STANDING_GRANTS_ENABLED=0 is the operator kill switch: with grants off
    # the gateway neither mints nor consumes them, so every request prompts
    # again regardless of what was granted earlier.
    standing_grants_enabled: bool = True
    grant_ttl_session_seconds: int = 4 * 60 * 60
    grant_ttl_agent_seconds: int = 24 * 60 * 60
    grant_ttl_permanent_seconds: int = 30 * 24 * 60 * 60
    # Seed demo agents/sessions for an empty dashboard. Disable in real
    # deployments so the fleet shows only real (bridge-fed) agents.
    seed_mock_data: bool = True

    @property
    def push_configured(self) -> bool:
        return bool(self.apns_key_path and self.apns_key_id and self.apns_team_id)

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            node_id=os.getenv("HERMES_NODE_ID", cls.node_id),
            node_display_name=os.getenv("HERMES_NODE_DISPLAY_NAME", cls.node_display_name),
            node_environment=os.getenv("HERMES_NODE_ENVIRONMENT", cls.node_environment),
            node_fingerprint=os.getenv("HERMES_NODE_FINGERPRINT", cls.node_fingerprint),
            gateway_base_url=os.getenv("HERMES_GATEWAY_BASE_URL", cls.gateway_base_url),
            gateway_version=os.getenv("HERMES_GATEWAY_VERSION", cls.gateway_version),
            hermes_version=os.getenv("HERMES_VERSION"),
            database_path=os.getenv("HERMES_GATEWAY_DB", cls.database_path),
            pairing_ttl_seconds=int(
                os.getenv("HERMES_PAIRING_TTL_SECONDS", str(cls.pairing_ttl_seconds))
            ),
            allowed_hermes_callers=_csv_env("HERMES_ALLOWED_HERMES_CALLERS")
            or _csv_env("HERMES_GATEWAY_ALLOWED_HERMES_CALLERS"),
            cors_allowed_origin_regex=os.getenv(
                "HERMES_GATEWAY_CORS_ALLOWED_ORIGIN_REGEX",
                cls.cors_allowed_origin_regex or "",
            )
            or None,
            tui_enable_local_pty=_bool_env(
                "HERMES_TUI_ENABLE_LOCAL_PTY", cls.tui_enable_local_pty
            ),
            tui_allowed_commands=_csv_env("HERMES_TUI_ALLOWED_COMMANDS")
            or cls.tui_allowed_commands,
            tui_default_command=os.getenv(
                "HERMES_TUI_DEFAULT_COMMAND", cls.tui_default_command
            ),
            tui_allowed_working_directory=os.getenv(
                "HERMES_TUI_ALLOWED_WORKING_DIRECTORY",
                cls.tui_allowed_working_directory,
            ),
            tui_command_risk_family=_map_env("HERMES_TUI_COMMAND_RISK_FAMILY"),
            tui_allow_shell_commands=_bool_env(
                "HERMES_TUI_ALLOW_SHELL_COMMANDS",
                cls.tui_allow_shell_commands,
            ),
            tui_max_sessions=int(os.getenv("HERMES_TUI_MAX_SESSIONS", str(cls.tui_max_sessions))),
            tui_idle_timeout_seconds=int(
                os.getenv(
                    "HERMES_TUI_IDLE_TIMEOUT_SECONDS",
                    str(cls.tui_idle_timeout_seconds),
                )
            ),
            tui_attach_token_ttl_seconds=int(
                os.getenv(
                    "HERMES_TUI_ATTACH_TOKEN_TTL_SECONDS",
                    str(cls.tui_attach_token_ttl_seconds),
                )
            ),
            tui_output_retention_enabled=_bool_env(
                "HERMES_TUI_OUTPUT_RETENTION_ENABLED",
                cls.tui_output_retention_enabled,
            ),
            clearance_enabled_channels=_csv_env("ACT_CLEARANCE_ENABLED_CHANNELS")
            or cls.clearance_enabled_channels,
            clearance_default_channel=os.getenv(
                "ACT_CLEARANCE_DEFAULT_CHANNEL",
                cls.clearance_default_channel,
            ),
            clearance_local_terminal_enabled=_bool_env(
                "ACT_CLEARANCE_LOCAL_TERMINAL_ENABLED",
                cls.clearance_local_terminal_enabled,
            ),
            clearance_default_deployment_trust_context=os.getenv(
                "ACT_CLEARANCE_DEFAULT_DEPLOYMENT_TRUST_CONTEXT",
                cls.clearance_default_deployment_trust_context,
            ),
            clearance_risk_channel_map=_risk_channel_map_env()
            or dict(cls.default_clearance_risk_channel_map),
            apns_key_path=os.getenv("APNS_KEY_PATH") or None,
            apns_key_id=os.getenv("APNS_KEY_ID") or None,
            apns_team_id=os.getenv("APNS_TEAM_ID") or None,
            apns_topic=os.getenv("APNS_TOPIC", cls.apns_topic),
            apns_environment=os.getenv("APNS_ENVIRONMENT", cls.apns_environment),
            seed_mock_data=_bool_env("ACT_SEED_MOCK_DATA", cls.seed_mock_data),
            standing_grants_enabled=_bool_env(
                "ACT_STANDING_GRANTS_ENABLED", cls.standing_grants_enabled
            ),
            grant_ttl_session_seconds=int(
                os.getenv(
                    "ACT_GRANT_TTL_SESSION_SECONDS", str(cls.grant_ttl_session_seconds)
                )
            ),
            grant_ttl_agent_seconds=int(
                os.getenv("ACT_GRANT_TTL_AGENT_SECONDS", str(cls.grant_ttl_agent_seconds))
            ),
            grant_ttl_permanent_seconds=int(
                os.getenv(
                    "ACT_GRANT_TTL_PERMANENT_SECONDS",
                    str(cls.grant_ttl_permanent_seconds),
                )
            ),
        )

    @property
    def database_file(self) -> Path:
        return Path(self.database_path)


def _csv_env(name: str) -> tuple[str, ...]:
    value = os.getenv(name, "")
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _risk_channel_map_env() -> dict[str, tuple[str, ...]] | None:
    raw = os.getenv("ACT_CLEARANCE_RISK_CHANNEL_MAP")
    if not raw:
        return None
    mapping: dict[str, tuple[str, ...]] = {}
    for entry in raw.split(";"):
        if not entry.strip() or "=" not in entry:
            continue
        risk, channels = entry.split("=", 1)
        mapping[risk.strip()] = tuple(
            channel.strip() for channel in channels.split(",") if channel.strip()
        )
    return mapping


def _map_env(name: str) -> dict[str, str] | None:
    raw = os.getenv(name)
    if not raw:
        return None
    mapping: dict[str, str] = {}
    for entry in raw.split(";"):
        if not entry.strip() or "=" not in entry:
            continue
        key, value = entry.split("=", 1)
        mapping[key.strip()] = value.strip()
    return mapping
