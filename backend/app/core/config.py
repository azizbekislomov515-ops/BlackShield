import re
from functools import lru_cache

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# scheme://host[:port] with no path, query or wildcard.
_ORIGIN = re.compile(r"https?://[A-Za-z0-9.-]+(:\d{1,5})?")


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings(BaseSettings):
    """Application settings, read from environment variables and an optional .env file."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "BlackShield API"
    environment: str = "development"
    debug: bool = False
    # PostgreSQL in every deployment. SQLite URLs are accepted for tests and local experiments.
    database_url: str = "postgresql+psycopg://blackshield:blackshield@localhost:5432/blackshield"

    # Logging. JSON lines by default so log shippers can parse them.
    log_level: str = "INFO"
    log_json: bool = True

    # OpenAPI UI (/docs, /redoc, /openapi.json).
    docs_enabled: bool = True

    # --- /v1 security --------------------------------------------------------------------------
    # Comma-separated "key_id:sha256_hex_of_key" pairs. Only hashes are configured, never keys.
    # Generate an entry with `blackshield-signatures generate-api-key --id android-v1`.
    # Empty means every /v1 request is rejected (fail closed).
    api_keys: str = ""
    # Token bucket per (API key, client IP): sustained rate and burst size.
    rate_limit_per_minute: int = Field(default=120, ge=1)
    rate_limit_burst: int = Field(default=30, ge=1)
    # Requests with a missing or wrong key, per client IP.
    auth_failure_limit_per_minute: int = Field(default=10, ge=1)
    # Hard cap on request bodies (100 SHA-256 hashes in JSON are ~7 KiB).
    max_request_body_bytes: int = Field(default=16_384, ge=1_024)
    # Comma-separated origins allowed to call the API from a browser. Empty disables CORS.
    cors_allowed_origins: str = ""

    # --- Sync protocol -------------------------------------------------------------------------
    delta_default_limit: int = Field(default=5_000, ge=1)
    delta_max_limit: int = Field(default=20_000, ge=1)

    # --- YARA rules publishing (CLI only; the API server never needs the private key) ----------
    # PEM file of the EC P-256 signing key, created with `blackshield-signatures rules-keygen`.
    # Keep it offline (a secrets manager or the release machine), never in the repository.
    rules_signing_key_file: str | None = None
    # Must match the key id the app trusts (Gradle property blackshield.yaraRulesPublicKeys).
    rules_signing_key_id: str = "k1"

    # --- Ingestion -----------------------------------------------------------------------------
    malwarebazaar_api_key: SecretStr | None = None
    malwarebazaar_url: str = "https://mb-api.abuse.ch/api/v1/"
    # File types queried with get_file_type; tag results are filtered to these types too.
    malwarebazaar_file_types: str = "apk"
    # Optional tags queried with get_taginfo, e.g. "android,hydra".
    malwarebazaar_tags: str = ""
    malwarebazaar_limit: int = Field(default=1_000, ge=1, le=1_000)
    malwarebazaar_min_interval_seconds: float = Field(default=2.0, ge=0)
    malwarebazaar_max_retries: int = Field(default=5, ge=0)
    malwarebazaar_timeout_seconds: float = Field(default=30.0, gt=0)
    # Interval of `blackshield-signatures schedule`.
    ingest_interval_seconds: int = Field(default=3_600, ge=60)

    @field_validator("cors_allowed_origins")
    @classmethod
    def _explicit_origins_only(cls, value: str) -> str:
        for origin in _split_csv(value):
            if not _ORIGIN.fullmatch(origin):
                # A "*" here would open the API to every web page; list origins explicitly.
                raise ValueError(
                    "CORS_ALLOWED_ORIGINS entries must be explicit origins like "
                    "https://admin.example.com (no wildcard, path or trailing slash)"
                )
        return value

    @property
    def cors_origins(self) -> list[str]:
        return _split_csv(self.cors_allowed_origins)

    @property
    def malwarebazaar_file_type_list(self) -> list[str]:
        return [item.lower() for item in _split_csv(self.malwarebazaar_file_types)]

    @property
    def malwarebazaar_tag_list(self) -> list[str]:
        return _split_csv(self.malwarebazaar_tags)


@lru_cache
def get_settings() -> Settings:
    return Settings()
