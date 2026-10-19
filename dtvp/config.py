from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DTVP_", env_file=".env", extra="ignore")
    database_url: str = "postgresql+psycopg://dtvp:dtvp@127.0.0.1:5432/dtvp"
    migration_database_url: str | None = None
    artifact_dir: Path = Path("data/artifacts")
    public_url: str = "http://127.0.0.1:8000"
    session_secret: str = ""
    playground: bool = False
    evidence_jws_trust: list[dict] = []
    frontend_dir: Path = Path("frontend/dist")
    max_upload_bytes: int = 32 * 1024 * 1024
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    providers_enabled: list[str] = []
    dt_url: str = ""
    dt_api_key: str = ""
    cybeats_url: str = ""
    cybeats_access_key: str = ""
    cybeats_secret_access_key: str = ""
    vscorer_url: str = ""
    agentyzer_enabled: bool = False
    agentyzer_url: str = ""
    agentyzer_token: str = ""
    agentyzer_reconciliation_enabled: bool = False
    agentyzer_timeout_seconds: int = 3600

    @model_validator(mode="after")
    def secure_defaults(self):
        if not self.playground:
            if len(self.session_secret) < 32:
                raise ValueError("DTVP_SESSION_SECRET must contain at least 32 characters")
            if not self.database_url.startswith("postgresql"):
                raise ValueError("Production requires PostgreSQL")
        else:
            self.session_secret = self.session_secret or "isolated-playground-session-secret-0000"
            if not self.providers_enabled:
                self.providers_enabled = ["demo", "demo-failure"]
        if self.agentyzer_enabled:
            from urllib.parse import urlsplit

            endpoint = urlsplit(self.agentyzer_url)
            if (
                endpoint.scheme not in {"http", "https"}
                or not endpoint.hostname
                or endpoint.username
                or endpoint.password
                or endpoint.query
                or endpoint.fragment
            ):
                raise ValueError(
                    "Configure an HTTP(S) Agentyzer URL without credentials, query or fragment"
                )
        if not 60 <= self.agentyzer_timeout_seconds <= 86400:
            raise ValueError("Agentyzer observation timeout must be between 60 and 86400 seconds")
        if self.evidence_jws_trust:
            from dtvp.knowledge.signature_verification import validate_trust_policy

            validate_trust_policy(self.evidence_jws_trust)
        return self
