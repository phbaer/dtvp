import logging
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse

from authlib.integrations.base_client.errors import MismatchingStateError, OAuthError
from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from jose import jwt
from joserfc.errors import JoseError
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .logic import get_user_role

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
    SESSION_SECRET_KEY: str = Field(
        alias="DTVP_SESSION_SECRET_KEY", default="change_me"
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

    session_token = jwt.encode(
        {"sub": username}, auth_settings.SESSION_SECRET_KEY, algorithm="HS256"
    )

    base = auth_settings.FRONTEND_URL.rstrip("/")
    path = auth_settings.CONTEXT_PATH
    if not path.startswith("/"):
        path = "/" + path
    target = f"{base}{path}"

    response = RedirectResponse(url=target)
    response.set_cookie(
        key="session_token",
        value=session_token,
        path=auth_settings.application_cookie_path,
        secure=auth_settings.secure_cookies,
        httponly=True,
        samesite="lax",
    )
    return response


@router.get("/logout")
async def logout(response: Response):
    base = auth_settings.FRONTEND_URL.rstrip("/")
    path = auth_settings.CONTEXT_PATH.rstrip("/")
    if path and not path.startswith("/"):
        path = "/" + path

    # Ensure exactly one slash between base/path and login
    redirect_path = "/login"
    target = f"{base}{path}{redirect_path}"

    response = RedirectResponse(url=target)
    response.delete_cookie(
        key="session_token",
        path=auth_settings.application_cookie_path,
        secure=auth_settings.secure_cookies,
        httponly=True,
        samesite="lax",
    )
    return response


async def get_current_user(request: Request):
    if auth_settings.DEV_DISABLE_AUTH:
        return "devuser"

    token = request.cookies.get("session_token")
    if token:
        try:
            payload = jwt.decode(
                token, auth_settings.SESSION_SECRET_KEY, algorithms=["HS256"]
            )
            return payload.get("sub")
        except Exception as e:
            logger.debug(f"Failed to decode JWT token: {e}")
            pass

    raise HTTPException(status_code=401, detail="Not authenticated")


@router.get("/me")
async def get_user_info(user: str = Depends(get_current_user)):
    return {"username": user, "role": get_user_role(user)}
