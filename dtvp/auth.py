import asyncio
import logging
import sqlite3
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse

from authlib.integrations.base_client.errors import MismatchingStateError, OAuthError
from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from joserfc.errors import JoseError
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .access_token_services import (
    SCOPE_READ,
    AccessToken,
    access_token_store,
    access_tokens_enabled,
    looks_like_access_token,
)
from .logic import get_user_role
from .session_services import (
    SESSION_COOKIE,
    decode_session_token,
    issue_session_token,
    load_session_config,
    needs_refresh,
)

# POST routes that only read. Everything else a token may call is GET/HEAD.
# POST /api/assessments/details is deliberately absent: it rewrites the
# shared task snapshots from caller-supplied finding identities.
ACCESS_TOKEN_READ_ONLY_POST_ROUTES = ("/api/tasks/group-vulns",)

logger = logging.getLogger(__name__)


class AuthSettings(BaseSettings):
    OIDC_CLIENT_ID: Optional[str] = Field(alias="DTVP_OIDC_CLIENT_ID", default=None)
    OIDC_CLIENT_SECRET: Optional[str] = Field(
        alias="DTVP_OIDC_CLIENT_SECRET", default=None
    )
    OIDC_AUTHORITY: Optional[str] = Field(alias="DTVP_OIDC_AUTHORITY", default=None)
    OIDC_REDIRECT_URI: Optional[str] = Field(
        alias="DTVP_OIDC_REDIRECT_URI", default=None
    )
    FRONTEND_URL: str = Field(
        alias="DTVP_FRONTEND_URL", default="http://localhost:8000"
    )
    CONTEXT_PATH: str = Field(alias="DTVP_CONTEXT_PATH", default="/")

    # Support aliases from the deployment compose file too
    ISSUER_URL: Optional[str] = Field(default=None)
    CLIENT_ID: Optional[str] = Field(default=None)
    # Development settings
    DEV_DISABLE_AUTH: bool = Field(alias="DTVP_DEV_DISABLE_AUTH", default=False)

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    @property
    def authority(self) -> str:
        # Priority: DTVP_OIDC_AUTHORITY > ISSUER_URL > default None
        return self.OIDC_AUTHORITY or self.ISSUER_URL or ""

    @property
    def client_id(self) -> str:
        # Priority: DTVP_OIDC_CLIENT_ID > CLIENT_ID > default None
        return self.OIDC_CLIENT_ID or self.CLIENT_ID or ""

    @property
    def client_secret(self) -> str:
        # Priority: DTVP_OIDC_CLIENT_SECRET > OIDC_CLIENT_SECRET (alias) > default None
        return self.OIDC_CLIENT_SECRET or ""

    @property
    def redirect_uri(self) -> str:
        if self.OIDC_REDIRECT_URI:
            return self.OIDC_REDIRECT_URI

        base = self.FRONTEND_URL.rstrip("/")
        path = self.CONTEXT_PATH
        if path and not path.startswith("/"):
            path = "/" + path
        path = path.rstrip("/")

        return f"{base}{path}/auth/callback"

    @property
    def oidc_cookie_path(self) -> str:
        path = self.CONTEXT_PATH.strip("/")
        return f"/{path}/auth" if path else "/auth"

    @property
    def application_cookie_path(self) -> str:
        path = self.CONTEXT_PATH.strip("/")
        return f"/{path}" if path else "/"

    @property
    def secure_cookies(self) -> bool:
        return urlparse(self.redirect_uri).scheme.lower() == "https"


auth_settings = AuthSettings()
# Refuses a missing, placeholder, or short signing key. dtvp.boot checks it
# before loading the app too; this covers serving dtvp.main:app directly.
session_config = load_session_config()
router = APIRouter(prefix="/auth", tags=["auth"])


@lru_cache(maxsize=1)
def _create_oidc_client(authority: str, client_id: str, client_secret: str):
    oauth = OAuth()
    return oauth.register(
        name="oidc",
        client_id=client_id,
        client_secret=client_secret or None,
        server_metadata_url=(
            f"{authority.rstrip('/')}/.well-known/openid-configuration"
        ),
        client_kwargs={
            "scope": "openid profile email",
            "code_challenge_method": "S256",
            "token_endpoint_auth_method": (
                "client_secret_post" if client_secret else "none"
            ),
        },
    )


def get_oidc_client():
    authority = auth_settings.authority
    if not authority:
        raise HTTPException(status_code=500, detail="OIDC Authority not configured")
    if not auth_settings.client_id:
        raise HTTPException(status_code=500, detail="OIDC Client ID not configured")
    return _create_oidc_client(
        authority,
        auth_settings.client_id,
        auth_settings.client_secret,
    )


@router.get("/login")
async def login(request: Request):
    return await get_oidc_client().authorize_redirect(
        request,
        auth_settings.redirect_uri,
    )


@router.get("/callback")
async def callback(request: Request):
    try:
        token = await get_oidc_client().authorize_access_token(request)
    except MismatchingStateError as exc:
        logger.info("OIDC callback rejected due to invalid state")
        raise HTTPException(status_code=400, detail="Invalid OIDC login state") from exc
    except OAuthError as exc:
        logger.info("OIDC provider rejected the callback: %s", exc)
        raise HTTPException(
            status_code=400, detail="Failed to authenticate with OIDC provider"
        ) from exc
    except JoseError as exc:
        logger.info("OIDC identity token validation failed: %s", exc)
        raise HTTPException(
            status_code=400, detail="Invalid OIDC identity token"
        ) from exc

    claims = token.get("userinfo")
    if not claims:
        raise HTTPException(status_code=400, detail="OIDC identity token missing")

    username = (
        claims.get("sub")
        or claims.get("preferred_username")
        or claims.get("email")
    )
    if not isinstance(username, str) or not username:
        raise HTTPException(
            status_code=400, detail="OIDC identity token has no user identifier"
        )

    try:
        version = await asyncio.to_thread(access_token_store.session_version, username)
    except sqlite3.Error as exc:
        logger.exception("Session version lookup failed at sign-in")
        raise HTTPException(
            status_code=503, detail="Sign-in unavailable: the session store cannot be read"
        ) from exc
    session_token = issue_session_token(session_config, username, version)

    base = auth_settings.FRONTEND_URL.rstrip("/")
    path = auth_settings.CONTEXT_PATH
    if not path.startswith("/"):
        path = "/" + path
    target = f"{base}{path}"

    response = RedirectResponse(url=target)
    _set_session_cookie(response, session_token)
    return response


def _set_session_cookie(response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=session_config.ttl_seconds,
        path=auth_settings.application_cookie_path,
        secure=auth_settings.secure_cookies,
        httponly=True,
        samesite="lax",
    )


def _clear_session_cookie(response) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE,
        path=auth_settings.application_cookie_path,
        secure=auth_settings.secure_cookies,
        httponly=True,
        samesite="lax",
    )


@router.get("/logout")
async def logout(request: Request):
    """End every session of the signed-in user and return to the login page.

    Stays a GET because the SPA navigates here. A cross-site link can at most
    sign a user out.
    """
    if not auth_settings.DEV_DISABLE_AUTH:
        claims = decode_session_token(
            session_config, request.cookies.get(SESSION_COOKIE, "")
        )
        if claims is not None:
            try:
                current = await asyncio.to_thread(
                    access_token_store.session_version, claims.username
                )
                # A session that is already revoked must not end the
                # user's newer sessions.
                if claims.version == current:
                    await asyncio.to_thread(
                        access_token_store.revoke_sessions, claims.username
                    )
            except sqlite3.Error as exc:
                # Clearing only this cookie would look like a sign-out while
                # every copy of the session stays valid. Say so instead; the
                # user can try again.
                logger.exception("Could not revoke sessions on logout")
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "Sign-out failed: your sessions could not be ended. "
                        "Try again in a moment."
                    ),
                ) from exc

    base = auth_settings.FRONTEND_URL.rstrip("/")
    path = auth_settings.CONTEXT_PATH.rstrip("/")
    if path and not path.startswith("/"):
        path = "/" + path

    # Ensure exactly one slash between base/path and login
    redirect_path = "/login"
    target = f"{base}{path}{redirect_path}"

    response = RedirectResponse(url=target)
    _clear_session_cookie(response)
    return response


async def _session_user(request: Request) -> str:
    if auth_settings.DEV_DISABLE_AUTH:
        return "devuser"

    claims = decode_session_token(
        session_config, request.cookies.get(SESSION_COOKIE) or ""
    )
    if claims is None:
        if request.cookies.get(SESSION_COOKIE):
            logger.debug("Rejected an invalid, expired, or legacy session cookie")
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        current = await asyncio.to_thread(
            access_token_store.session_version, claims.username
        )
    except sqlite3.Error as exc:
        logger.exception("Session version lookup failed")
        # Fail closed, but not with 401: that would send the SPA to sign-in
        # in a loop while the database is unavailable.
        raise HTTPException(
            status_code=503, detail="Session check unavailable"
        ) from exc
    if claims.version != current:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if needs_refresh(claims, config=session_config):
        request.state.refreshed_session_token = issue_session_token(
            session_config,
            claims.username,
            claims.version,
            authenticated_at=claims.authenticated_at,
        )
    return claims.username


def apply_session_refresh(request: Request, response) -> None:
    """Send the renewed session cookie that authentication prepared, if any."""
    state = getattr(request, "state", None)
    token = getattr(state, "refreshed_session_token", None) if state else None
    if token:
        _set_session_cookie(response, token)


def _bearer_access_token(request: Request) -> str | None:
    """The access token a machine client sent, if any.

    Accepted as ``Authorization: Bearer <token>`` or, for clients built for
    API keys, as ``X-Api-Key: <token>``. Both carry the same token and the
    same limits.
    """
    scheme, _, value = request.headers.get("authorization", "").partition(" ")
    value = value.strip()
    if scheme.lower() == "bearer" and looks_like_access_token(value):
        return value
    api_key = request.headers.get("x-api-key", "").strip()
    if looks_like_access_token(api_key):
        return api_key
    return None


def _access_token_may_call(request: Request) -> bool:
    """Access tokens may read through the REST API; they cannot change data.

    Writes by machine clients go through the MCP tools, which apply the
    review and provenance rules. See docs/adr/0001.
    """
    if request.method in {"GET", "HEAD"}:
        return True
    # Neither route has path parameters, so the request path identifies it;
    # the suffix match tolerates a deployment context path.
    path = str(request.scope.get("path") or "").rstrip("/")
    return request.method == "POST" and path.endswith(
        ACCESS_TOKEN_READ_ONLY_POST_ROUTES
    )


async def authenticate_access_token(plain: str) -> AccessToken:
    """Resolve a plain access token or raise 401."""
    record = (
        await asyncio.to_thread(access_token_store.verify, plain)
        if access_tokens_enabled()
        else None
    )
    if record is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid, expired, or revoked access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return record


async def get_session_user(request: Request):
    """Authenticate an interactive browser session only.

    Used where a machine client must never act, such as managing tokens.
    """
    if _bearer_access_token(request) is not None:
        raise HTTPException(
            status_code=403,
            detail="This operation requires an interactive session",
        )
    return await _session_user(request)


async def get_current_user(request: Request):
    plain = _bearer_access_token(request)
    if plain is None:
        return await _session_user(request)

    record = await authenticate_access_token(plain)
    if not record.has_scope(SCOPE_READ) or not _access_token_may_call(request):
        raise HTTPException(
            status_code=403,
            detail=(
                "Access tokens can only read through this API; "
                "use the MCP tools to change assessments"
            ),
        )
    request.state.access_token = record
    return record.username


@router.get("/me")
async def get_user_info(user: str = Depends(get_current_user)):
    return {"username": user, "role": get_user_role(user)}


class SessionRevokeRequest(BaseModel):
    username: str = Field(min_length=1, max_length=256)

    @field_validator("username", mode="before")
    @classmethod
    def _strip(cls, value):
        return value.strip() if isinstance(value, str) else value


@router.post("/sessions/revoke")
async def revoke_sessions(
    body: SessionRevokeRequest,
    request: Request,
    user: str = Depends(get_session_user),
):
    """End every browser session of a user.

    Anyone may end their own sessions; reviewers may end anyone's. The
    username is the identity DTVP stores (the OIDC ``sub``, else
    ``preferred_username`` or ``email``), as in user_roles.json. Unknown
    names are accepted so a session can be revoked before it is used.
    """
    target = body.username
    if target != user and get_user_role(user) != "REVIEWER":
        raise HTTPException(
            status_code=403,
            detail="Only reviewers can revoke another user's sessions",
        )
    try:
        await asyncio.to_thread(access_token_store.revoke_sessions, target)
    except sqlite3.Error as exc:
        logger.exception("Could not revoke the sessions of %s", target)
        raise HTTPException(
            status_code=503,
            detail="The sessions could not be ended: the session store cannot be written",
        ) from exc
    logger.info("Sessions of %s revoked by %s", target, user)

    payload = {"status": "revoked", "username": target}
    if target != user:
        return payload
    # The caller's own session just ended: do not renew it, clear it.
    if hasattr(request.state, "refreshed_session_token"):
        del request.state.refreshed_session_token
    response = JSONResponse(payload)
    _clear_session_cookie(response)
    return response
