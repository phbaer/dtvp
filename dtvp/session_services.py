"""Browser session signing key, session tokens, and their lifetime.

The session cookie is an HS256 JWT signed with ``DTVP_SESSION_SECRET_KEY``.
The same key signs the transient OIDC login-state cookie and SSVC evidence
tokens, so DTVP refuses to start without a strong one: unset, the old
``change_me`` placeholder, or shorter than 32 bytes. Keys committed to the
repository for development and tests start with ``dtvp-dev-only-``; such a
key is refused unless ``DTVP_SESSION_ALLOW_DEV_KEY=true`` says this is a
development or test setup, so copying one into production fails loudly.

A session token is typed (``typ``), carries the user (``sub``), the user's
session version (``ver``), its issue and expiry times (``iat``, ``exp``),
and the sign-in time (``auth_time``). Renewal never moves a session past
``auth_time`` plus the absolute maximum age. The version is stored
server-side (see ``AccessTokenStore.session_version``); raising it ends
every session of that user. See docs/adr/0008.

This module has no FastAPI or database imports so the boot wrapper can load
it cheaply before the application.
"""

import time
from dataclasses import dataclass

from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

SESSION_KEY_ENV = "DTVP_SESSION_SECRET_KEY"
SESSION_KEY_FILE_ENV = "DTVP_SESSION_SECRET_KEY_FILE"
SESSION_TTL_ENV = "DTVP_SESSION_TTL_HOURS"
SESSION_MAX_AGE_ENV = "DTVP_SESSION_MAX_AGE_HOURS"
SESSION_ALLOW_DEV_KEY_ENV = "DTVP_SESSION_ALLOW_DEV_KEY"
DEV_KEY_PREFIX = "dtvp-dev-only-"
PLACEHOLDER_KEYS = frozenset({"change_me"})
MIN_SESSION_KEY_BYTES = 32
DEFAULT_SESSION_TTL_HOURS = 12
MAX_SESSION_TTL_HOURS = 720
DEFAULT_SESSION_MAX_AGE_HOURS = 168
MAX_SESSION_MAX_AGE_HOURS = 2160
SESSION_TOKEN_TYPE = "dtvp-session"
SESSION_COOKIE = "session_token"
SESSION_ALGORITHM = "HS256"

KEY_GENERATION_HINT = (
    "DTVP refuses to start without a session signing key of at least "
    f"{MIN_SESSION_KEY_BYTES} random bytes. Generate one with "
    "`python3 -c 'import secrets; print(secrets.token_urlsafe(48))'` or "
    f"`openssl rand -base64 48`, then set {SESSION_KEY_ENV} or write it to a "
    f"file named by {SESSION_KEY_FILE_ENV}."
)


class SessionConfigError(RuntimeError):
    """The session signing key or lifetime is missing or unsafe."""


class SessionSettings(BaseSettings):
    SECRET_KEY: str = Field(alias=SESSION_KEY_ENV, default="")
    SECRET_KEY_FILE: str = Field(alias=SESSION_KEY_FILE_ENV, default="")
    # Kept as text so an invalid value is reported with the variable name.
    TTL_HOURS: str = Field(
        alias=SESSION_TTL_ENV, default=str(DEFAULT_SESSION_TTL_HOURS)
    )
    MAX_AGE_HOURS: str = Field(
        alias=SESSION_MAX_AGE_ENV, default=str(DEFAULT_SESSION_MAX_AGE_HOURS)
    )
    ALLOW_DEV_KEY: bool = Field(alias=SESSION_ALLOW_DEV_KEY_ENV, default=False)

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )


@dataclass(frozen=True)
class SessionConfig:
    secret_key: str
    ttl_seconds: int
    max_age_seconds: int = DEFAULT_SESSION_MAX_AGE_HOURS * 3600

    def __repr__(self) -> str:
        return (
            "SessionConfig(secret_key=<redacted>, "
            f"ttl_seconds={self.ttl_seconds}, max_age_seconds={self.max_age_seconds})"
        )

    __str__ = __repr__


@dataclass(frozen=True)
class SessionClaims:
    username: str
    version: int
    issued_at: int
    expires_at: int
    authenticated_at: int


def _refuse(problem: str) -> SessionConfigError:
    return SessionConfigError(f"{problem} {KEY_GENERATION_HINT}")


def _load_key(settings: SessionSettings) -> str:
    direct = (settings.SECRET_KEY or "").strip()
    path = (settings.SECRET_KEY_FILE or "").strip()
    if direct and path:
        raise _refuse(
            f"Set either {SESSION_KEY_ENV} or {SESSION_KEY_FILE_ENV}, not both."
        )

    source = SESSION_KEY_ENV
    key = direct
    if path:
        source = SESSION_KEY_FILE_ENV
        try:
            with open(path, encoding="utf-8") as handle:
                key = handle.read().rstrip()
        except (OSError, UnicodeDecodeError) as exc:
            reason = getattr(exc, "strerror", None) or type(exc).__name__
            raise _refuse(
                f"{SESSION_KEY_FILE_ENV} points to {path}, which cannot be read "
                f"({reason})."
            ) from None

    if not key:
        if path:
            raise _refuse(f"{SESSION_KEY_FILE_ENV} points to {path}, which is empty.")
        raise _refuse(f"{SESSION_KEY_ENV} is not set.")
    if key in PLACEHOLDER_KEYS:
        raise _refuse(f"{source} is the placeholder 'change_me'.")
    if key.startswith(DEV_KEY_PREFIX) and not settings.ALLOW_DEV_KEY:
        raise _refuse(
            f"{source} is a development key committed to the repository "
            f"(it starts with '{DEV_KEY_PREFIX}'); it is accepted only with "
            f"{SESSION_ALLOW_DEV_KEY_ENV}=true in a development or test setup."
        )
    length = len(key.encode("utf-8"))
    if length < MIN_SESSION_KEY_BYTES:
        raise _refuse(
            f"{source} is {length} bytes long; at least "
            f"{MIN_SESSION_KEY_BYTES} are required."
        )
    return key


def _load_ttl_seconds(settings: SessionSettings) -> int:
    raw = (settings.TTL_HOURS or "").strip() or str(DEFAULT_SESSION_TTL_HOURS)
    try:
        hours = int(raw, 10)
    except ValueError:
        hours = 0
    if not 1 <= hours <= MAX_SESSION_TTL_HOURS:
        raise SessionConfigError(
            f"{SESSION_TTL_ENV} must be a whole number of hours between 1 and "
            f"{MAX_SESSION_TTL_HOURS}."
        )
    return hours * 3600


def _load_max_age_seconds(settings: SessionSettings, ttl_seconds: int) -> int:
    raw = (settings.MAX_AGE_HOURS or "").strip() or str(DEFAULT_SESSION_MAX_AGE_HOURS)
    try:
        hours = int(raw, 10)
    except ValueError:
        hours = 0
    if not 1 <= hours <= MAX_SESSION_MAX_AGE_HOURS or hours * 3600 < ttl_seconds:
        raise SessionConfigError(
            f"{SESSION_MAX_AGE_ENV} must be a whole number of hours between "
            f"{SESSION_TTL_ENV} and {MAX_SESSION_MAX_AGE_HOURS}."
        )
    return hours * 3600


def load_session_config(settings: SessionSettings | None = None) -> SessionConfig:
    """Read and check the session key and lifetimes, or raise SessionConfigError.

    No message contains the key value.
    """
    settings = settings if settings is not None else SessionSettings()
    ttl_seconds = _load_ttl_seconds(settings)
    return SessionConfig(
        secret_key=_load_key(settings),
        ttl_seconds=ttl_seconds,
        max_age_seconds=_load_max_age_seconds(settings, ttl_seconds),
    )


def issue_session_token(
    config: SessionConfig,
    username: str,
    version: int,
    *,
    now: float | None = None,
    authenticated_at: int | None = None,
) -> str:
    """A session token for ``username``.

    ``authenticated_at`` is when the user signed in; a renewal passes the
    original time so that no renewal outlives the absolute maximum age.
    """
    issued_at = int(time.time() if now is None else now)
    signed_in = issued_at if authenticated_at is None else int(authenticated_at)
    expires_at = min(issued_at + config.ttl_seconds, signed_in + config.max_age_seconds)
    claims = {
        "typ": SESSION_TOKEN_TYPE,
        "sub": username,
        "ver": version,
        "iat": issued_at,
        "exp": expires_at,
        "auth_time": signed_in,
    }
    return jwt.encode(claims, config.secret_key, algorithm=SESSION_ALGORITHM)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def decode_session_token(config: SessionConfig, token: str) -> SessionClaims | None:
    """The claims of a valid, unexpired session token, else None.

    Tokens without the session type, version, or lifetime (legacy cookies and
    SSVC evidence tokens signed with the same key) are rejected.
    """
    if not isinstance(token, str) or not token:
        return None
    try:
        claims = jwt.decode(
            token,
            config.secret_key,
            algorithms=[SESSION_ALGORITHM],
            options={"require_exp": True, "require_iat": True, "require_sub": True},
        )
    except (ExpiredSignatureError, JWTClaimsError, JWTError):
        return None
    except Exception:  # malformed input the library does not wrap
        return None

    username = claims.get("sub")
    version = claims.get("ver")
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    authenticated_at = claims.get("auth_time")
    if (
        claims.get("typ") != SESSION_TOKEN_TYPE
        or not isinstance(username, str)
        or not username
        or not _is_int(version)
        or version < 0
        or not _is_int(issued_at)
        or not _is_int(expires_at)
        or expires_at <= issued_at
        or not _is_int(authenticated_at)
        or authenticated_at > issued_at
        # A token must never reach past the absolute maximum age, even one
        # signed before the maximum was lowered.
        or expires_at > authenticated_at + config.max_age_seconds
        or time.time() >= authenticated_at + config.max_age_seconds
    ):
        return None
    return SessionClaims(
        username=username,
        version=version,
        issued_at=issued_at,
        expires_at=expires_at,
        authenticated_at=authenticated_at,
    )


def needs_refresh(
    claims: SessionClaims,
    *,
    now: float | None = None,
    config: SessionConfig | None = None,
) -> bool:
    """True once more than half of the token's lifetime is used, unless the
    token already ends at the absolute maximum age (renewing cannot extend
    it)."""
    current = time.time() if now is None else now
    if config is not None and (
        claims.expires_at >= claims.authenticated_at + config.max_age_seconds
    ):
        return False
    return current - claims.issued_at > (claims.expires_at - claims.issued_at) / 2
