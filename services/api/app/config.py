"""Validated application configuration."""

from functools import lru_cache
from typing import Literal
from urllib.parse import quote_plus, urlsplit

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings loaded from environment variables and an optional local .env file."""

    model_config = SettingsConfigDict(
        env_file="../../.env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_env: Literal["development", "test", "staging", "production"] = "development"
    app_name: str = "Cyber Intelligence Platform API"
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)
    web_origin: str = "http://127.0.0.1:5173"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    auth_secret_key: str = "change_me_in_development_only_32_chars_plus"
    auth_algorithm: Literal["HS256", "RS256"] = "HS256"
    auth_issuer: str = "cip-local"
    auth_audience: str = "cip"
    auth_token_ttl_minutes: int = Field(default=60, ge=1, le=1440)
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None

    postgres_host: str = "127.0.0.1"
    postgres_port: int = Field(default=5432, ge=1, le=65535)
    postgres_db: str = "cip_dev"
    postgres_user: str = "cip_user"
    postgres_password: str = "change_me"

    @field_validator("oidc_issuer")
    @classmethod
    def validate_oidc_issuer(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return value
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("OIDC_ISSUER must be an HTTPS URL.")
        return value

    @field_validator("oidc_jwks_url")
    @classmethod
    def validate_oidc_jwks_url(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("OIDC_JWKS_URL must be an HTTPS URL.")
        return value

    @property
    def database_url(self) -> str:
        """Build a PostgreSQL connection string for the local environment."""

        return (
            "postgresql+psycopg://"
            f"{quote_plus(self.postgres_user)}:{quote_plus(self.postgres_password)}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached settings; tests can clear the cache when overriding the environment."""

    return Settings()
