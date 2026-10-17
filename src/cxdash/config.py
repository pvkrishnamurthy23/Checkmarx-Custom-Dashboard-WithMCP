"""Application settings (spec section 5).

Single source of configuration. Loaded once into a frozen ``Settings`` object.
No tenant, region, credential or scope value is hard-coded anywhere else.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from sqlalchemy.engine import make_url

from cxdash.cx_client.deeplink import validate_template

log = logging.getLogger(__name__)

ENGINES: tuple[str, ...] = ("sast", "sca", "containers", "kics", "secrets", "apisec", "sscs")
REGIONS: tuple[str, ...] = ("us", "us2", "eu", "eu2", "deu", "anz", "ind", "sng", "mea")

# Region -> host prefix (spec 6.1). "us" has no prefix.
_REGION_PREFIX = {
    "us": "",
    "us2": "us.",
    "eu": "eu.",
    "eu2": "eu-2.",
    "deu": "deu.",
    "anz": "anz.",
    "ind": "ind.",
    "sng": "sng.",
    "mea": "mea.",
}

_SECRET_FIELDS = (
    "cx_api_key",
    "cx_client_secret",
    "oidc_client_secret",
    "smtp_password",
    "session_secret",
    "metrics_token",
    "alert_webhook_url",
    "redis_url",
)


def _split(value: object) -> list[str]:
    if value is None:
        return []
    items = [str(v) for v in value] if isinstance(value, (list, tuple, set)) else str(value).split(",")
    seen: dict[str, None] = {}
    for item in items:
        item = item.strip()
        if item:
            seen.setdefault(item, None)
    return list(seen)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="forbid",  # typos in .env fail fast
        frozen=True,
        case_sensitive=False,
    )

    # ---- Checkmarx One connection ----
    cx_region: str = "eu"
    cx_tenant: str = ""
    cx_base_url: str = ""
    cx_iam_url: str = ""
    cx_ui_base_url: str = ""
    cx_deeplink_template: str = "{ui_base}/results/{scan_id}/{project_id}/{engine}"
    cx_auth_method: Literal["api_key", "oauth_client"] = "api_key"
    cx_api_key: SecretStr = SecretStr("")
    cx_client_id: str = ""
    cx_client_secret: SecretStr = SecretStr("")

    # ---- Scope ----
    cx_branches: Annotated[tuple[str, ...], NoDecode] = ("master", "dis-devinteg")
    cx_project_name_regex: str = ""
    cx_project_tags: Annotated[tuple[str, ...], NoDecode] = ()
    cx_applications: Annotated[tuple[str, ...], NoDecode] = ()
    cx_engines: Annotated[tuple[str, ...], NoDecode] = ENGINES

    # ---- What counts as open ----
    cx_closed_states: Annotated[tuple[str, ...], NoDecode] = ("NOT_EXPLOITABLE",)
    cx_closed_statuses: Annotated[tuple[str, ...], NoDecode] = ("FIXED",)

    # ---- Sync ----
    sync_inventory_minutes: int = Field(30, ge=1)
    sync_scans_minutes: int = Field(10, ge=1)
    sync_findings_cron: str = "0 2 * * *"
    sync_backfill_days: int = Field(90, ge=1)
    sync_request_poll_seconds: int = Field(30, ge=5)
    # --- API-call economy (ADR 0013) ---
    # last_scan: fetch only the newest scan per project/branch (via /api/projects/last-scan); all: every scan since a high-water mark
    sync_scan_selection: Literal["last_scan", "all"] = "last_scan"
    sync_last_scan_status: str = "Completed"  # "full" = Completed (not Partial/Failed/Canceled)
    # Opt-in: skip scans whose SAST config says incremental and look back for the newest other one. The flag is the
    # *configured* mode, not proof the scan was incremental (a first scan cannot be), so it is off by default (ADR 0013).
    sync_full_scans_only: bool = False
    sync_full_scan_lookback: int = Field(20, ge=1, le=100)
    sync_last_scan_batch: int = Field(50, ge=1, le=100)  # project ids per last-scan / scan-ids call
    sync_load_findings: bool = True  # False = counters only (scan-summary), no per-finding results calls
    sync_nightly_findings_refresh: bool = False  # True = re-pull findings of every latest scan each night
    sync_keep_scan_history: bool = True  # False = nightly purge keeps only the latest scan per project/branch
    sync_max_api_calls_per_run: int = Field(2500, ge=0)  # hard cap per job run; 0 = unlimited
    cx_results_page_size: int = Field(500, ge=1, le=1000)
    cx_page_size: int = Field(100, ge=1, le=1000)
    cx_max_concurrency: int = Field(5, ge=1, le=50)
    cx_http_timeout_seconds: float = Field(60, gt=0)
    cx_max_retries: int = Field(5, ge=1, le=15)
    findings_keep_scans_per_branch: int = Field(2, ge=1)

    # ---- Metrics ----
    sla_days_critical: int = 7
    sla_days_high: int = 30
    sla_days_medium: int = 90
    sla_days_low: int = 180
    risk_weight_critical: float = 10
    risk_weight_high: float = 5
    risk_weight_medium: float = 2
    risk_weight_low: float = 0.5
    stale_project_days: int = 14

    # ---- Storage ----
    database_url: SecretStr = SecretStr("sqlite:///./cxdash-dev.db")
    redis_url: SecretStr = SecretStr("")

    # ---- Dashboard auth ----
    auth_mode: Literal["none", "oidc", "proxy_headers"] = "none"
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: SecretStr = SecretStr("")
    oidc_group_claim: str = "groups"
    role_admin_groups: Annotated[tuple[str, ...], NoDecode] = ()
    role_analyst_groups: Annotated[tuple[str, ...], NoDecode] = ()
    trusted_proxy_ips: Annotated[tuple[str, ...], NoDecode] = ()
    session_secret: SecretStr = SecretStr("")
    session_cookie_secure: bool = True
    scope_map_path: str = ""
    metrics_token: SecretStr = SecretStr("")

    # ---- Alerts ----
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: SecretStr = SecretStr("")
    alert_email_from: str = ""
    alert_webhook_url: SecretStr = SecretStr("")
    alert_cooldown_hours: int = Field(24, ge=0)

    # ---- Web / ops ----
    web_host: str = "127.0.0.1"
    web_port: int = 8050
    worker_metrics_host: str = "127.0.0.1"
    worker_metrics_port: int = Field(9102, ge=0)
    export_row_cap: int = Field(1_000_000, ge=1)
    refresh_rate_limit_seconds: int = Field(60, ge=1)
    log_level: str = "INFO"
    enable_writeback: bool = False

    # ------------------------------------------------------------------ validators
    @field_validator(
        "cx_branches",
        "cx_project_tags",
        "cx_applications",
        "role_admin_groups",
        "role_analyst_groups",
        "trusted_proxy_ips",
        mode="before",
    )
    @classmethod
    def _csv(cls, v: object) -> list[str]:
        return _split(v)

    @field_validator("cx_closed_states", "cx_closed_statuses", mode="before")
    @classmethod
    def _csv_upper(cls, v: object) -> list[str]:
        return [x.upper() for x in _split(v)]

    @field_validator("cx_engines", mode="before")
    @classmethod
    def _engines(cls, v: object) -> list[str]:
        engines = [x.lower() for x in _split(v)]
        unknown = [e for e in engines if e not in ENGINES]
        if unknown:
            raise ValueError(f"unknown engine(s) {unknown}; allowed: {list(ENGINES)}")
        return engines

    @field_validator("cx_region", mode="before")
    @classmethod
    def _region(cls, v: object) -> str:
        return str(v).strip().lower()

    @field_validator("log_level", mode="before")
    @classmethod
    def _log_level(cls, v: object) -> str:
        level = str(v).strip().upper()
        if level not in logging.getLevelNamesMapping():
            raise ValueError(f"invalid LOG_LEVEL {v!r}")
        return level

    @model_validator(mode="after")
    def _cross_checks(self) -> Settings:
        both_urls = bool(self.cx_base_url and self.cx_iam_url)
        if self.cx_region not in REGIONS and not both_urls:
            raise ValueError(
                f"CX_REGION must be one of {list(REGIONS)} unless CX_BASE_URL and CX_IAM_URL are set"
            )
        if self.cx_auth_method == "api_key" and not self.cx_api_key.get_secret_value():
            raise ValueError("CX_API_KEY is required when CX_AUTH_METHOD=api_key")
        if self.cx_auth_method == "oauth_client" and not (
            self.cx_client_id and self.cx_client_secret.get_secret_value()
        ):
            raise ValueError(
                "CX_CLIENT_ID and CX_CLIENT_SECRET are required when CX_AUTH_METHOD=oauth_client"
            )
        if not self.cx_tenant:
            raise ValueError("CX_TENANT is required")
        validate_template(self.cx_deeplink_template)
        if self.sync_scan_selection == "last_scan" and (
            not self.cx_branches or any("*" in b for b in self.cx_branches)
        ):
            raise ValueError(
                "SYNC_SCAN_SELECTION=last_scan needs CX_BRANCHES to list exact branch names (no globs, not empty); "
                "use SYNC_SCAN_SELECTION=all for glob or all-branch scope"
            )
        if self.enable_writeback:
            raise ValueError("ENABLE_WRITEBACK=true is not implemented in v1")
        if self.auth_mode == "oidc":
            missing = [
                n
                for n, v in (
                    ("OIDC_ISSUER", self.oidc_issuer),
                    ("OIDC_CLIENT_ID", self.oidc_client_id),
                    ("OIDC_CLIENT_SECRET", self.oidc_client_secret.get_secret_value()),
                    ("SESSION_SECRET", self.session_secret.get_secret_value()),
                )
                if not v
            ]
            if missing:
                raise ValueError(f"AUTH_MODE=oidc requires {', '.join(missing)}")
        if self.auth_mode == "proxy_headers" and not self.trusted_proxy_ips:
            raise ValueError("AUTH_MODE=proxy_headers requires TRUSTED_PROXY_IPS")
        secret = self.session_secret.get_secret_value()
        if secret and len(secret) < 32:
            raise ValueError("SESSION_SECRET must be at least 32 characters")
        return self

    # ------------------------------------------------------------------ derived values
    @property
    def base_url(self) -> str:
        if self.cx_base_url:
            return self.cx_base_url.rstrip("/")
        return f"https://{_REGION_PREFIX[self.cx_region]}ast.checkmarx.net"

    @property
    def iam_url(self) -> str:
        if self.cx_iam_url:
            return self.cx_iam_url.rstrip("/")
        return f"https://{_REGION_PREFIX[self.cx_region]}iam.checkmarx.net"

    @property
    def ui_base_url(self) -> str:
        return (self.cx_ui_base_url or self.base_url).rstrip("/")

    @property
    def token_url(self) -> str:
        return f"{self.iam_url}/auth/realms/{self.cx_tenant}/protocol/openid-connect/token"

    @property
    def all_branches(self) -> bool:
        return not self.cx_branches

    def sla_days(self, severity: str) -> int | None:
        return {
            "CRITICAL": self.sla_days_critical,
            "HIGH": self.sla_days_high,
            "MEDIUM": self.sla_days_medium,
            "LOW": self.sla_days_low,
        }.get(severity.upper())

    @property
    def risk_weights(self) -> dict[str, float]:
        return {
            "CRITICAL": self.risk_weight_critical,
            "HIGH": self.risk_weight_high,
            "MEDIUM": self.risk_weight_medium,
            "LOW": self.risk_weight_low,
            "INFO": 0.0,
        }

    def masked_dump(self) -> dict[str, object]:
        """Effective configuration with every secret masked (Admin page)."""
        out: dict[str, object] = {}
        for name in type(self).model_fields:
            value = getattr(self, name)
            if name in _SECRET_FIELDS:
                out[name] = "********" if value.get_secret_value() else ""
            elif name == "database_url":
                out[name] = make_url(value.get_secret_value()).render_as_string(hide_password=True)
            elif isinstance(value, tuple):
                out[name] = list(value)
            else:
                out[name] = value
        out["base_url (derived)"] = self.base_url
        out["iam_url (derived)"] = self.iam_url
        return out

    def secret_values(self) -> list[str]:
        """Plain secret strings, used by the log redaction filter."""
        values = [getattr(self, n).get_secret_value() for n in _SECRET_FIELDS]
        values.append(make_url(self.database_url.get_secret_value()).password or "")
        return [v for v in values if len(v) >= 4]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    if settings.all_branches:
        log.warning("CX_BRANCHES is empty: every branch will be synced; volume may be large")
    if settings.auth_mode == "none":
        log.warning("AUTH_MODE=none: dashboard is unauthenticated (local development only)")
    return settings
