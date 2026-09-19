"""Runtime configuration sourced from env vars with the ``B2B_INTEL_`` prefix.

Pydantic-Settings handles the loading; a ``.env`` file in the project root is
read if present. See ``.env.example`` for the available knobs.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_db_path() -> Path:
    """``$XDG_DATA_HOME/b2b-intel/b2b-intel.db`` or the XDG-spec fallback."""
    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    base = (
        Path(xdg_data_home)
        if xdg_data_home
        else Path.home() / ".local" / "share"
    )
    return base / "b2b-intel" / "b2b-intel.db"


class Settings(BaseSettings):
    """Runtime config, read from env vars prefixed ``B2B_INTEL_``.

    Attributes:
        db_path: SQLite database location. Default: XDG_DATA_HOME or
            ``~/.local/share/b2b-intel/b2b-intel.db``.
        resolvers: List of upstream DNS resolver IPs to try in order on
            transient failure. Settable via comma-separated env var
            (``B2B_INTEL_RESOLVERS=1.1.1.1,8.8.8.8``).
        rate_limit_qps: Per-resolver max queries per second.
        dns_timeout: Per-query timeout in seconds before falling back to the
            next resolver.
    """

    model_config = SettingsConfigDict(
        env_prefix="B2B_INTEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    db_path: Path = Field(default_factory=_default_db_path)
    resolvers: list[str] = Field(
        default_factory=lambda: ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    )
    rate_limit_qps: float = 5.0
    dns_timeout: float = 5.0

    @field_validator("resolvers", mode="before")
    @classmethod
    def _split_csv(cls, v: object) -> object:
        if isinstance(v, str):
            return [s.strip() for s in v.split(",") if s.strip()]
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the singleton Settings instance."""
    return Settings()
