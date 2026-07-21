import base64
import hashlib
import logging
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from jwt.exceptions import PyJWTError as JWTError
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .authorization import Principal, normalize_role
from .security_audit import emit_security_audit
from .logic import get_user_role

logger = logging.getLogger(__name__)

SESSION_COOKIE_NAME = "session_token"
OIDC_TRANSACTION_COOKIE_NAME = "oidc_transaction"
SESSION_ISSUER = "dtvp"
SESSION_AUDIENCE = "dtvp-session"
OIDC_TRANSACTION_AUDIENCE = "dtvp-oidc-transaction"
SESSION_ALGORITHM = "HS256"
OIDC_CACHE_TTL_SECONDS = 300
MINIMUM_SESSION_SECRET_LENGTH = 32
WEAK_SESSION_SECRETS = frozenset(
    {
        "change_me",
        "changeme",
        "default",
        "password",
        "secret",
        "test",
        "xxx",
    }
)
ASYMMETRIC_OIDC_ALGORITHMS = frozenset(
    {
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512",
        "RS256",
        "RS384",
        "RS512",
    }
)


class AuthSettings(BaseSettings):
    ENVIRONMENT: str = Field(alias="DTVP_ENVIRONMENT", default="production")
    OIDC_CLIENT_ID: Optional[str] = Field(alias="DTVP_OIDC_CLIENT_ID", default=None)
    OIDC_CLIENT_SECRET: Optional[str] = Field(
        alias="DTVP_OIDC_CLIENT_SECRET", default=None
    )
    OIDC_CLIENT_SECRET_FILE: Optional[str] = Field(
        alias="DTVP_OIDC_CLIENT_SECRET_FILE", default=None
    )
    OIDC_AUTHORITY: Optional[str] = Field(alias="DTVP_OIDC_AUTHORITY", default=None)
    OIDC_REDIRECT_URI: Optional[str] = Field(
        alias="DTVP_OIDC_REDIRECT_URI", default=None
    )
    OIDC_ALLOWED_ALGORITHMS: str = Field(
        alias="DTVP_OIDC_ALLOWED_ALGORITHMS", default="RS256"
    )
    OIDC_TRANSACTION_TTL_SECONDS: int = Field(
        alias="DTVP_OIDC_TRANSACTION_TTL_SECONDS", default=300, ge=60, le=900
    )
    SESSION_SECRET_KEY: Optional[str] = Field(
        alias="DTVP_SESSION_SECRET_KEY", default=None
    )
    SESSION_SECRET_KEY_FILE: Optional[str] = Field(
        alias="DTVP_SESSION_SECRET_KEY_FILE", default=None
    )
    SESSION_TTL_SECONDS: int = Field(
        alias="DTVP_SESSION_TTL_SECONDS", default=28800, ge=300, le=86400
    )
    SESSION_COOKIE_SECURE: Optional[bool] = Field(
        alias="DTVP_SESSION_COOKIE_SECURE", default=None
    )
    FRONTEND_URL: str = Field(
        alias="DTVP_FRONTEND_URL", default="http://localhost:8000"
    )
    CONTEXT_PATH: str = Field(alias="DTVP_CONTEXT_PATH", default="/")

    # Deployment aliases retained for compatibility.
    ISSUER_URL: Optional[str] = Field(default=None)
    CLIENT_ID: Optional[str] = Field(default=None)
    DEV_DISABLE_AUTH: bool = Field(alias="DTVP_DEV_DISABLE_AUTH", default=False)

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    @property
    def environment(self) -> str:
        return self.ENVIRONMENT.strip().lower()

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def authority(self) -> str:
        return (self.OIDC_AUTHORITY or self.ISSUER_URL or "").rstrip("/")

    @property
    def client_id(self) -> str:
        return self.OIDC_CLIENT_ID or self.CLIENT_ID or ""

    @staticmethod
    def _read_secret_file(path: Optional[str]) -> str:
        if not path:
            return ""
        return Path(path).read_text(encoding="utf-8").strip()

    @property
    def client_secret(self) -> str:
        direct = (self.OIDC_CLIENT_SECRET or "").strip()
        return direct or self._read_secret_file(self.OIDC_CLIENT_SECRET_FILE)

    @property
    def session_secret(self) -> str:
        direct = (self.SESSION_SECRET_KEY or "").strip()
        return direct or self._read_secret_file(self.SESSION_SECRET_KEY_FILE)

    @property
    def allowed_oidc_algorithms(self) -> tuple[str, ...]:
        return tuple(
            value.strip().upper()
            for value in self.OIDC_ALLOWED_ALGORITHMS.split(",")
            if value.strip()
        )

    @property
    def cookie_path(self) -> str:
        path = self.CONTEXT_PATH.strip() or "/"
        if not path.startswith("/"):
            path = "/" + path
        path = path.rstrip("/")
        return path or "/"

    @property
    def cookie_secure(self) -> bool:
        if self.SESSION_COOKIE_SECURE is not None:
            return self.SESSION_COOKIE_SECURE
        return self.is_production or urlparse(self.FRONTEND_URL).scheme == "https"

    @property
    def frontend_target(self) -> str:
        base = self.FRONTEND_URL.rstrip("/")
        context_path = self.cookie_path
        if context_path == "/":
            return base
        parsed = urlparse(base)
        if parsed.path.rstrip("/") == context_path:
            return base
        return f"{base}{context_path}"

    @property
    def redirect_uri(self) -> str:
        if self.OIDC_REDIRECT_URI:
            return self.OIDC_REDIRECT_URI
        return f"{self.frontend_target}/auth/callback"


auth_settings = AuthSettings()
router = APIRouter(prefix="/auth", tags=["auth"])

_oidc_config_cache: Optional[dict[str, Any]] = None
_oidc_config_cached_at = 0.0
_jwks_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def validate_auth_configuration(settings: AuthSettings = auth_settings) -> None:
    if settings.environment not in {"development", "production", "test"}:
        raise RuntimeError("DTVP_ENVIRONMENT must be development, production, or test")
    if settings.is_production and settings.DEV_DISABLE_AUTH:
        raise RuntimeError("DTVP_DEV_DISABLE_AUTH cannot be enabled in production")
    if settings.DEV_DISABLE_AUTH:
        return

    missing = []
    if not settings.authority:
        missing.append("DTVP_OIDC_AUTHORITY")
    if not settings.client_id:
        missing.append("DTVP_OIDC_CLIENT_ID")
    if not settings.client_secret:
        missing.append("DTVP_OIDC_CLIENT_SECRET or DTVP_OIDC_CLIENT_SECRET_FILE")
    if missing:
        raise RuntimeError(f"Missing authentication configuration: {', '.join(missing)}")

    session_secret = settings.session_secret
    if (
        len(session_secret) < MINIMUM_SESSION_SECRET_LENGTH
        or session_secret.lower() in WEAK_SESSION_SECRETS
    ):
        raise RuntimeError(
            "DTVP_SESSION_SECRET_KEY must be a non-default value of at least "
            f"{MINIMUM_SESSION_SECRET_LENGTH} characters"
        )

    algorithms = settings.allowed_oidc_algorithms
    if not algorithms or any(
        algorithm not in ASYMMETRIC_OIDC_ALGORITHMS for algorithm in algorithms
    ):
        raise RuntimeError(
            "DTVP_OIDC_ALLOWED_ALGORITHMS must contain only approved asymmetric algorithms"
        )

    if settings.is_production:
        if urlparse(settings.redirect_uri).scheme != "https":
            raise RuntimeError("DTVP_OIDC_REDIRECT_URI must use HTTPS in production")
        if not settings.cookie_secure:
            raise RuntimeError("Secure session cookies are required in production")


def _jwt_now() -> datetime:
    return datetime.now(UTC)


def _encode_transaction(*, state: str, nonce: str, code_verifier: str) -> str:
    now = _jwt_now()
    return jwt.encode(
        {
            "iss": SESSION_ISSUER,
            "aud": OIDC_TRANSACTION_AUDIENCE,
            "iat": int(now.timestamp()),
            "exp": int(
                (now + timedelta(seconds=auth_settings.OIDC_TRANSACTION_TTL_SECONDS)).timestamp()
            ),
            "jti": str(uuid.uuid4()),
            "state": state,
            "nonce": nonce,
            "code_verifier": code_verifier,
        },
        auth_settings.session_secret,
        algorithm=SESSION_ALGORITHM,
    )


def _decode_transaction(token: str) -> dict[str, Any]:
    payload = jwt.decode(
        token,
        auth_settings.session_secret,
        algorithms=[SESSION_ALGORITHM],
        issuer=SESSION_ISSUER,
        audience=OIDC_TRANSACTION_AUDIENCE,
        options={
            "require": ["aud", "exp", "iat", "iss", "jti"],
        },
    )
    for claim in ("state", "nonce", "code_verifier"):
        if not isinstance(payload.get(claim), str) or not payload[claim]:
            raise JWTError(f"Missing OIDC transaction claim: {claim}")
    return payload


def create_session_token(*, subject: str, username: str) -> str:
    now = _jwt_now()
    return jwt.encode(
        {
            "iss": SESSION_ISSUER,
            "aud": SESSION_AUDIENCE,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=auth_settings.SESSION_TTL_SECONDS)).timestamp()),
            "jti": str(uuid.uuid4()),
            "sub": subject,
            "username": username,
        },
        auth_settings.session_secret,
        algorithm=SESSION_ALGORITHM,
    )


def decode_session_token(token: str) -> dict[str, Any]:
    payload = jwt.decode(
        token,
        auth_settings.session_secret,
        algorithms=[SESSION_ALGORITHM],
        issuer=SESSION_ISSUER,
        audience=SESSION_AUDIENCE,
        options={
            "require": ["aud", "exp", "iat", "iss", "jti", "sub"],
        },
    )
    username = payload.get("username")
    if not isinstance(username, str) or not username.strip():
        raise JWTError("Session username is missing")
    return payload


def _validate_discovery_document(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise HTTPException(status_code=503, detail="OIDC discovery returned invalid data")
    if str(document.get("issuer") or "").rstrip("/") != auth_settings.authority:
        raise HTTPException(status_code=503, detail="OIDC discovery issuer mismatch")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        value = document.get(field)
        is_https = isinstance(value, str) and value.startswith("https://")
        is_local_http = (
            isinstance(value, str)
            and auth_settings.environment in {"development", "test"}
            and value.startswith("http://")
        )
        if not (is_https or is_local_http):
            raise HTTPException(
                status_code=503,
                detail=f"OIDC discovery is missing a valid {field}",
            )
    return document


async def get_oidc_config() -> dict[str, Any]:
    global _oidc_config_cache, _oidc_config_cached_at
    if (
        _oidc_config_cache is not None
        and time.monotonic() - _oidc_config_cached_at < OIDC_CACHE_TTL_SECONDS
    ):
        return _oidc_config_cache

    if not auth_settings.authority:
        raise HTTPException(status_code=500, detail="OIDC Authority not configured")

    config_url = f"{auth_settings.authority}/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(config_url)
            response.raise_for_status()
            document = _validate_discovery_document(response.json())
    except HTTPException:
        raise
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("OIDC discovery failed: %s", exc)
        raise HTTPException(status_code=503, detail="OIDC discovery unavailable") from exc

    _oidc_config_cache = document
    _oidc_config_cached_at = time.monotonic()
    return document


async def get_oidc_jwks(
    config: dict[str, Any], *, force_refresh: bool = False
) -> dict[str, Any]:
    jwks_uri = str(config["jwks_uri"])
    cached = _jwks_cache.get(jwks_uri)
    if (
        not force_refresh
        and cached is not None
        and time.monotonic() - cached[0] < OIDC_CACHE_TTL_SECONDS
    ):
        return cached[1]
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(jwks_uri)
            response.raise_for_status()
            jwks = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("OIDC JWKS fetch failed: %s", exc)
        raise HTTPException(status_code=503, detail="OIDC signing keys unavailable") from exc
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise HTTPException(status_code=503, detail="OIDC signing keys are invalid")
    _jwks_cache[jwks_uri] = (time.monotonic(), jwks)
    return jwks


async def _validate_id_token(
    id_token: Any,
    *,
    config: dict[str, Any],
    expected_nonce: str,
    access_token: Optional[str],
) -> dict[str, Any]:
    if not isinstance(id_token, str) or not id_token:
        raise JWTError("ID token is missing")
    header = jwt.get_unverified_header(id_token)
    algorithm = str(header.get("alg") or "").upper()
    key_id = header.get("kid")
    if algorithm not in auth_settings.allowed_oidc_algorithms:
        raise JWTError("ID token uses an unapproved algorithm")
    if not isinstance(key_id, str) or not key_id:
        raise JWTError("ID token key ID is missing")

    signing_key: Optional[dict[str, Any]] = None
    for force_refresh in (False, True):
        jwks = await get_oidc_jwks(config, force_refresh=force_refresh)
        signing_key = next(
            (
                key
                for key in jwks["keys"]
                if isinstance(key, dict)
                and key.get("kid") == key_id
                and key.get("use", "sig") == "sig"
            ),
            None,
        )
        if signing_key is not None:
            break
    if signing_key is None:
        raise JWTError("ID token signing key is unknown")

    claims = jwt.decode(
        id_token,
        jwt.PyJWK.from_dict(signing_key),
        algorithms=[algorithm],
        audience=auth_settings.client_id,
        issuer=str(config["issuer"]),
        options={
            "require": ["aud", "exp", "iat", "iss", "sub"],
        },
    )
    _validate_oidc_access_token_hash(
        claims,
        access_token=access_token,
        algorithm=algorithm,
    )
    nonce = claims.get("nonce")
    if not isinstance(nonce, str) or not secrets.compare_digest(nonce, expected_nonce):
        raise JWTError("ID token nonce mismatch")
    audience = claims.get("aud")
    if isinstance(audience, list) and len(audience) > 1:
        if claims.get("azp") != auth_settings.client_id:
            raise JWTError("ID token authorized party mismatch")
    return claims


def _validate_oidc_access_token_hash(
    claims: dict[str, Any],
    *,
    access_token: Optional[str],
    algorithm: str,
) -> None:
    claimed_hash = claims.get("at_hash")
    if claimed_hash is None:
        return
    if not isinstance(claimed_hash, str) or not claimed_hash or not access_token:
        raise JWTError("ID token access-token hash is invalid")

    digest_factory = {
        "256": hashlib.sha256,
        "384": hashlib.sha384,
        "512": hashlib.sha512,
    }.get(algorithm[-3:])
    if digest_factory is None:
        raise JWTError("ID token access-token hash algorithm is unsupported")
    try:
        encoded_access_token = access_token.encode("ascii")
    except UnicodeEncodeError as exc:
        raise JWTError("ID token access-token hash input is invalid") from exc
    digest = digest_factory(encoded_access_token).digest()
    expected_hash = base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=")
    if not secrets.compare_digest(claimed_hash, expected_hash.decode("ascii")):
        raise JWTError("ID token access-token hash mismatch")


def _code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _set_auth_cookie(
    response: Response,
    *,
    key: str,
    value: str,
    max_age: int,
) -> None:
    response.set_cookie(
        key=key,
        value=value,
        max_age=max_age,
        httponly=True,
        secure=auth_settings.cookie_secure,
        samesite="lax",
        path=auth_settings.cookie_path,
    )


def _delete_auth_cookie(response: Response, key: str) -> None:
    response.delete_cookie(
        key=key,
        secure=auth_settings.cookie_secure,
        httponly=True,
        samesite="lax",
        path=auth_settings.cookie_path,
    )


@router.get("/login")
async def login():
    validate_auth_configuration()
    config = await get_oidc_config()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    transaction = _encode_transaction(
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
    )
    params = {
        "client_id": auth_settings.client_id,
        "response_type": "code",
        "redirect_uri": auth_settings.redirect_uri,
        "state": state,
        "nonce": nonce,
        "scope": "openid profile email",
        "code_challenge": _code_challenge(code_verifier),
        "code_challenge_method": "S256",
    }
    response = RedirectResponse(
        str(httpx.URL(str(config["authorization_endpoint"]), params=params))
    )
    _set_auth_cookie(
        response,
        key=OIDC_TRANSACTION_COOKIE_NAME,
        value=transaction,
        max_age=auth_settings.OIDC_TRANSACTION_TTL_SECONDS,
    )
    emit_security_audit("auth.login.start", outcome="success")
    return response


@router.get("/callback")
async def callback(request: Request, code: str, state: str):
    transaction_token = request.cookies.get(OIDC_TRANSACTION_COOKIE_NAME)
    if not transaction_token:
        emit_security_audit(
            "auth.login.callback",
            outcome="denied",
            details={"reason": "missing_transaction"},
        )
        raise HTTPException(status_code=400, detail="Login transaction is missing")
    try:
        transaction = _decode_transaction(transaction_token)
        if not secrets.compare_digest(transaction["state"], state):
            raise JWTError("OIDC state mismatch")
    except JWTError as exc:
        logger.info("Rejected invalid OIDC transaction: %s", exc)
        emit_security_audit(
            "auth.login.callback",
            outcome="denied",
            details={"reason": "invalid_transaction"},
        )
        raise HTTPException(status_code=400, detail="Login transaction is invalid") from exc

    config = await get_oidc_config()
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            token_response = await client.post(
                str(config["token_endpoint"]),
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": auth_settings.redirect_uri,
                    "client_id": auth_settings.client_id,
                    "client_secret": auth_settings.client_secret,
                    "code_verifier": transaction["code_verifier"],
                },
            )
            token_response.raise_for_status()
            token_data = token_response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.info("OIDC token exchange failed: %s", exc)
        emit_security_audit(
            "auth.login.callback",
            outcome="failure",
            details={"reason": "token_exchange"},
        )
        raise HTTPException(status_code=400, detail="Authentication failed") from exc

    try:
        claims = await _validate_id_token(
            token_data.get("id_token"),
            config=config,
            expected_nonce=transaction["nonce"],
            access_token=token_data.get("access_token"),
        )
    except (JWTError, HTTPException) as exc:
        logger.info("OIDC ID token validation failed: %s", exc)
        emit_security_audit(
            "auth.login.callback",
            outcome="denied",
            details={"reason": "token_validation"},
        )
        if isinstance(exc, HTTPException) and exc.status_code == 503:
            raise
        raise HTTPException(status_code=400, detail="Authentication failed") from exc

    subject = str(claims["sub"]).strip()
    username = str(
        claims.get("preferred_username") or claims.get("email") or subject
    ).strip()
    if not subject or not username:
        emit_security_audit(
            "auth.login.callback",
            outcome="denied",
            details={"reason": "missing_identity"},
        )
        raise HTTPException(status_code=400, detail="Authentication failed")

    session_token = create_session_token(subject=subject, username=username)
    response = RedirectResponse(url=auth_settings.frontend_target)
    _set_auth_cookie(
        response,
        key=SESSION_COOKIE_NAME,
        value=session_token,
        max_age=auth_settings.SESSION_TTL_SECONDS,
    )
    _delete_auth_cookie(response, OIDC_TRANSACTION_COOKIE_NAME)
    emit_security_audit(
        "auth.login.callback",
        outcome="success",
        resource_type="user",
        resource_id=username,
    )
    return response


@router.post("/logout")
async def logout(response: Response):
    emit_security_audit("auth.logout", outcome="success")
    _delete_auth_cookie(response, SESSION_COOKIE_NAME)
    _delete_auth_cookie(response, OIDC_TRANSACTION_COOKIE_NAME)
    return {"status": "logged_out"}


async def get_current_principal(request: Request) -> Principal:
    if auth_settings.DEV_DISABLE_AUTH:
        username = "devuser"
        return Principal(
            subject="development:devuser",
            username=username,
            role=normalize_role(get_user_role(username)),
        )

    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        try:
            payload = decode_session_token(token)
            username = str(payload["username"])
            return Principal(
                subject=str(payload["sub"]),
                username=username,
                role=normalize_role(get_user_role(username)),
            )
        except JWTError as exc:
            logger.debug("Failed to decode DTVP session: %s", exc)

    emit_security_audit("auth.session", outcome="denied")
    raise HTTPException(status_code=401, detail="Not authenticated")


async def get_current_user(request: Request) -> str:
    return (await get_current_principal(request)).username


@router.get("/me")
async def get_user_info(user: str = Depends(get_current_user)):
    return {"username": user, "role": get_user_role(user)}
