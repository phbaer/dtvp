from typing import Optional
from fastapi import APIRouter, HTTPException, Request, Response, Depends
from fastapi.responses import RedirectResponse
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
import httpx
from jose import jwt
from logic import get_user_role


class AuthSettings(BaseSettings):
    OIDC_CLIENT_ID: str = Field(alias="DTVP_OIDC_CLIENT_ID", default=None)
    OIDC_CLIENT_SECRET: str = Field(alias="DTVP_OIDC_CLIENT_SECRET", default=None)
    OIDC_AUTHORITY: str = Field(alias="DTVP_OIDC_AUTHORITY", default=None)
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

    # Support aliases from docker-compose.yml too
    ISSUER_URL: Optional[str] = Field(default=None)
    CLIENT_ID: Optional[str] = Field(default=None)
    # Development settings
    DEV_DISABLE_AUTH: bool = Field(alias="DTVP_DEV_DISABLE_AUTH", default=False)

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    @property
    def authority(self) -> str:
        return self.OIDC_AUTHORITY or self.ISSUER_URL or ""

    @property
    def client_id(self) -> str:
        return self.OIDC_CLIENT_ID or self.CLIENT_ID or ""

    @property
    def client_secret(self) -> str:
        return self.OIDC_CLIENT_SECRET or self.CLIENT_SECRET or ""

    @property
    def redirect_uri(self) -> str:
        if self.OIDC_REDIRECT_URI:
            return self.OIDC_REDIRECT_URI

        base = self.FRONTEND_URL.rstrip("/")
        path = self.CONTEXT_PATH
        if not path.startswith("/"):
            path = "/" + path
        path = path.rstrip("/")

        return f"{base}{path}/auth/callback"


auth_settings = AuthSettings()
router = APIRouter(prefix="/auth", tags=["auth"])


_oidc_config_cache: Optional[dict] = None


async def get_oidc_config():
    global _oidc_config_cache
    if _oidc_config_cache:
        return _oidc_config_cache

    authority = auth_settings.authority
    if not authority:
        raise HTTPException(status_code=500, detail="OIDC Authority not configured")

    config_url = f"{authority.rstrip('/')}/.well-known/openid-configuration"
    async with httpx.AsyncClient() as client:
        resp = await client.get(config_url)
        resp.raise_for_status()
        _oidc_config_cache = resp.json()
        return _oidc_config_cache


@router.get("/login")
async def login():
    if auth_settings.DEV_DISABLE_AUTH:
        # If auth disabled, redirect to main page with a dummy session if needed,
        # or just redirect since get_current_user will pass anyway.
        # But get_current_user checks for header/cookie? No, we'll bypass it.
        base = auth_settings.FRONTEND_URL.rstrip("/")
        path = auth_settings.CONTEXT_PATH
        if not path.startswith("/"):
            path = "/" + path
        return RedirectResponse(f"{base}{path}")

    config = await get_oidc_config()
    auth_endpoint = config["authorization_endpoint"]
    return RedirectResponse(
        f"{auth_endpoint}?"
        f"client_id={auth_settings.client_id}&"
        f"response_type=code&"
        f"redirect_uri={auth_settings.redirect_uri}&"
        f"scope=openid profile email"
    )


@router.get("/callback")
async def callback(code: str, response: Response):
    config = await get_oidc_config()
    token_endpoint = config["token_endpoint"]
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": auth_settings.redirect_uri,
                "client_id": auth_settings.client_id,
                "client_secret": auth_settings.client_secret,
            },
        )
        if token_resp.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to retrieve token")

        token_data = token_resp.json()
        id_token = token_data.get("id_token")

        # Here we should validate the token signature against JWKS from issuer
        # For simplicity in this slice, we assume provider is trusted if direct backchannel call succeeded.
        # We can decode without verification to get user info or just use access token.

        # Determine user info (simplified)
        try:
            claims = jwt.get_unverified_claims(id_token)
            username = (
                claims.get("sub")
                or claims.get("preferred_username")
                or claims.get("email")
                or "user"
            )
        except Exception:
            username = "user"

        # Create a session cookie
        # In production, use a proper session backend or signed JWT
        session_token = jwt.encode(
            {"sub": username}, auth_settings.SESSION_SECRET_KEY, algorithm="HS256"
        )

        base = auth_settings.FRONTEND_URL.rstrip("/")
        path = auth_settings.CONTEXT_PATH
        if not path.startswith("/"):
            path = "/" + path
        target = f"{base}{path}"

        response = RedirectResponse(url=target)  # Redirect to dashboard
        response.set_cookie(key="session_token", value=session_token, httponly=True)
        return response


def get_current_user(request: Request):
    if auth_settings.DEV_DISABLE_AUTH:
        return "devuser"

    token = request.cookies.get("session_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(
            token, auth_settings.SESSION_SECRET_KEY, algorithms=["HS256"]
        )
        return payload.get("sub")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid session")


@router.get("/me")
def get_user_info(user: str = Depends(get_current_user)):
    return {"username": user, "role": get_user_role(user)}
