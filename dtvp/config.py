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
    frontend_dir: Path = Path("frontend/dist")
    max_upload_bytes: int = 32 * 1024 * 1024
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    providers_enabled: list[str] = []
    dt_url: str = ""
    dt_api_key: str = ""
    vscorer_url: str = ""

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
        return self
