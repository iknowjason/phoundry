"""Configuration, loaded from .env with safety switches defaulting to closed."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[2]


def _flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class ConfigError(RuntimeError):
    """Raised when required configuration is missing."""


@dataclass(slots=True)
class Settings:
    """Runtime configuration for a triage session."""

    # Foundry
    foundry_resource: str
    triage_model: str
    escalation_model: str
    foundry_api_key: str | None
    foundry_project_endpoint: str | None

    # Sublime
    sublime_base_url: str
    sublime_api_key: str

    # VirusTotal
    vt_api_key: str | None
    vt_tier: str

    # Safety switches — both default closed.
    allow_mailbox_actions: bool = False
    allow_vt_submit: bool = False

    # Local paths
    cache_dir: Path = field(default_factory=lambda: REPO_ROOT / ".cache")
    report_dir: Path = field(default_factory=lambda: REPO_ROOT / "reports")

    @property
    def use_entra_auth(self) -> bool:
        """True when no API key is set, so we authenticate as the signed-in analyst."""
        return not self.foundry_api_key

    def require_vt(self) -> str:
        if not self.vt_api_key:
            raise ConfigError("VT_API_KEY is not set — VirusTotal enrichment is unavailable.")
        return self.vt_api_key

    def describe(self) -> dict[str, str]:
        """Redacted summary, safe to display in a notebook cell."""
        return {
            "Foundry resource": self.foundry_resource,
            "Triage model": self.triage_model,
            "Escalation model": self.escalation_model,
            "Foundry auth": "Entra ID (az login)" if self.use_entra_auth else "API key",
            "Sublime endpoint": self.sublime_base_url,
            "Sublime key": _redact(self.sublime_api_key),
            "VirusTotal": f"{self.vt_tier} ({_redact(self.vt_api_key)})" if self.vt_api_key else "not configured",
            "Mailbox actions": "ENABLED" if self.allow_mailbox_actions else "disabled (read-only)",
            "VT submission": "ENABLED" if self.allow_vt_submit else "disabled (lookup only)",
        }


def _redact(secret: str | None) -> str:
    if not secret:
        return "not set"
    return f"…{secret[-4:]}" if len(secret) > 4 else "set"


def load_settings(env_file: str | Path | None = None) -> Settings:
    """Load settings from .env (repo root by default)."""
    load_dotenv(env_file or REPO_ROOT / ".env", override=False)

    resource = os.getenv("ANTHROPIC_FOUNDRY_RESOURCE", "").strip()
    sublime_key = os.getenv("SUBLIME_API_KEY", "").strip()

    missing = [
        name
        for name, value in (
            ("ANTHROPIC_FOUNDRY_RESOURCE", resource),
            ("SUBLIME_API_KEY", sublime_key),
        )
        if not value
    ]
    if missing:
        raise ConfigError(
            f"Missing required settings: {', '.join(missing)}. "
            "Copy .env.example to .env and fill it in."
        )

    settings = Settings(
        foundry_resource=resource,
        triage_model=os.getenv("TRIAGE_MODEL", "claude-sonnet-5").strip(),
        escalation_model=os.getenv("ESCALATION_MODEL", "claude-opus-5").strip(),
        foundry_api_key=os.getenv("ANTHROPIC_FOUNDRY_API_KEY", "").strip() or None,
        foundry_project_endpoint=os.getenv("FOUNDRY_PROJECT_ENDPOINT", "").strip() or None,
        sublime_base_url=os.getenv("SUBLIME_BASE_URL", "https://platform.sublime.security").rstrip("/"),
        sublime_api_key=sublime_key,
        vt_api_key=os.getenv("VT_API_KEY", "").strip() or None,
        vt_tier=os.getenv("VT_TIER", "public").strip().lower(),
        allow_mailbox_actions=_flag("ALLOW_MAILBOX_ACTIONS"),
        allow_vt_submit=_flag("ALLOW_VT_SUBMIT"),
    )
    settings.cache_dir.mkdir(parents=True, exist_ok=True)
    settings.report_dir.mkdir(parents=True, exist_ok=True)
    return settings
