from typing import Optional
from fastapi import APIRouter, HTTPException, Request, Response, Depends
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
import httpx
from jose import jwt
from logic import get_user_role
from dt_client import DTSettings


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

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    @property
    def redirect_uri(self) -> str:
        if self.OIDC_REDIRECT_URI:
            return self.OIDC_REDIRECT_URI
        # Construct default: frontend_url + context_path + /auth/callback
        # Ensure context path has leading/trailing slashes handled correctly
        ctx = self.CONTEXT_PATH.strip("/")
        if ctx:
            ctx = f"/{ctx}"
        return f"{self.FRONTEND_URL}{ctx}/auth/callback"

    @property
    def authority(self) -> str:
        # Ensure authority doesn't have trailing slash for consistency
        if self.OIDC_AUTHORITY:
            return self.OIDC_AUTHORITY.rstrip("/")
        return ""


auth_settings = AuthSettings()
dt_settings = DTSettings()

router = APIRouter(prefix="/auth", tags=["auth"])

# Cache OIDC config
_oidc_config_cache = None


async def get_oidc_config():
    global _oidc_config_cache
    if _oidc_config_cache:
        return _oidc_config_cache

    if not auth_settings.authority:
        raise HTTPException(status_code=500, detail="OIDC Authority not configured")

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{auth_settings.authority}/.well-known/openid-configuration"
        )
        resp.raise_for_status()
        _oidc_config_cache = resp.json()
        return _oidc_config_cache


@router.get("/login")
async def login():
    """
    Initiates OIDC Login.
    """
    config = await get_oidc_config()
    auth_endpoint = config["authorization_endpoint"]

    params = {
        "client_id": auth_settings.OIDC_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": auth_settings.redirect_uri,
        "scope": "openid profile email",
    }

    # Construct URL manually to allow for proper encoding by starlette/fastapi if we returned RedirectResponse
    # But here we just return the URL or RedirectResponse?
    # Standard flow: User visits /auth/login -> 302 to IdP

    from urllib.parse import urlencode

    url = f"{auth_endpoint}?{urlencode(params)}"

    from fastapi.responses import RedirectResponse

    return RedirectResponse(url)


@router.get("/callback")
async def callback(code: str, response: Response):
    """
    OIDC Callback.
    """
    config = await get_oidc_config()
    token_endpoint = config["token_endpoint"]

    data = {
        "grant_type": "authorization_code",
        "client_id": auth_settings.OIDC_CLIENT_ID,
        "client_secret": auth_settings.OIDC_CLIENT_SECRET,
        "code": code,
        "redirect_uri": auth_settings.redirect_uri,
    }

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(token_endpoint, data=data)
            resp.raise_for_status()
            tokens = resp.json()
        except httpx.RequestError as e:
            raise HTTPException(
                status_code=400, detail=f"Failed to exchange code: {str(e)}"
            )
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=400, detail=f"Token exchange failed: {e.response.text}"
            )

    # Parse ID token to get user info
    id_token = tokens.get("id_token")
    access_token = tokens.get("access_token")

    # We should validate the token properly (verify sig, exp, etc.) using keys from jwks_uri
    # For now, we decode unverified claims to get 'sub'
    # TODO: Implement proper validation or use a library that does it against JWKS

    try:
        claims = jwt.get_unverified_claims(id_token)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID Token")

    username = (
        claims.get("preferred_username")
        or claims.get("email")
        or claims.get("sub")
        or "user"
    )

    session_payload = {
        "sub": username,
        "dt_token": access_token,  # Store access token to use for DT API calls
        "dt_url": dt_settings.api_url,  # Should we store this? Frontend uses /auth/config
    }

    session_token = jwt.encode(
        session_payload, auth_settings.SESSION_SECRET_KEY, algorithm="HS256"
    )

    # Redirect to frontend
    # If context path is set, we might need to be careful?
    # Usually redirect to /

    redirect_url = "/"
    if auth_settings.CONTEXT_PATH and auth_settings.CONTEXT_PATH != "/":
        redirect_url = auth_settings.CONTEXT_PATH

    from fastapi.responses import RedirectResponse

    resp = RedirectResponse(redirect_url)
    resp.set_cookie(
        key="session_token", value=session_token, httponly=True, samesite="lax"
    )
    return resp


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie("session_token")
    return {"status": "success"}


def get_current_user_token_payload(request: Request) -> dict:
    token = request.cookies.get("session_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(
            token, auth_settings.SESSION_SECRET_KEY, algorithms=["HS256"]
        )
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid session")


def get_current_user(payload: dict = Depends(get_current_user_token_payload)) -> str:
    return payload.get("sub", "user")


@router.get("/me")
def get_user_info(user: str = Depends(get_current_user)):
    return {"username": user, "role": get_user_role(user)}


@router.get("/config")
def get_auth_config():
    return {"default_url": dt_settings.api_url}
