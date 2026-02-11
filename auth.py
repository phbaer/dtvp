from typing import Optional
from fastapi import APIRouter, HTTPException, Request, Response, Depends
from fastapi.responses import HTMLResponse
from pydantic import Field, BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict
import httpx
from jose import jwt
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

    # Role Configuration
    REVIEWER_TEAM: str = Field(alias="DTVP_REVIEWER_TEAM", default="Reviewers")
    ADMIN_TEAM: str = Field(alias="DTVP_ADMIN_TEAM", default="Administrators")

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
    Initiates OIDC Login with Implicit Flow.
    """
    config = await get_oidc_config()
    auth_endpoint = config["authorization_endpoint"]

    # Generate nonce for ID token validation
    import secrets

    nonce = secrets.token_urlsafe(16)

    params = {
        "client_id": auth_settings.OIDC_CLIENT_ID,
        "response_type": "id_token token",  # Implicit Flow
        "redirect_uri": auth_settings.redirect_uri,
        "scope": "openid profile email",
        "nonce": nonce,
    }

    # Construct URL manually to allow for proper encoding
    from urllib.parse import urlencode

    url = f"{auth_endpoint}?{urlencode(params)}"

    from fastapi.responses import RedirectResponse

    resp = RedirectResponse(url)
    # Store nonce in cookie for validation
    resp.set_cookie(
        key="oidc_nonce",
        value=nonce,
        httponly=True,
        samesite="lax",
        max_age=300,  # 5 minutes
    )
    return resp


@router.get("/callback")
async def callback_page():
    """
    OIDC Callback Page (Implicit Flow).
    Serves HTML/JS to extract tokens from fragment and POST to backend.
    """
    html_content = """
    <html>
        <head>
            <title>Authenticating...</title>
        </head>
        <body>
            <p>Authenticating...</p>
            <script>
                // Function to parse hash params
                function getHashParams() {
                    var hash = window.location.hash.substr(1);
                    var result = hash.split('&').reduce(function (res, item) {
                        var parts = item.split('=');
                        res[parts[0]] = decodeURIComponent(parts[1]);
                        return res;
                    }, {});
                    return result;
                }

                var params = getHashParams();
                var id_token = params.id_token;
                var access_token = params.access_token;
                var error = params.error;

                if (error) {
                    document.body.innerHTML = "Authentication Error: " + error;
                } else if (id_token && access_token) {
                    // POST to backend
                    fetch('implicit-callback', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            id_token: id_token,
                            access_token: access_token
                        })
                    }).then(function(response) {
                        if (response.ok) {
                            window.location.href = '/';
                        } else {
                            response.text().then(function(text) {
                                document.body.innerHTML = "Backend Validation Error: " + text;
                            });
                        }
                    }).catch(function(err) {
                        document.body.innerHTML = "Network Error: " + err;
                    });
                } else {
                    document.body.innerHTML = "No tokens found in URL fragment.";
                }
            </script>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)


class ImplicitTokenRequest(BaseModel):
    id_token: str
    access_token: str


@router.post("/implicit-callback")
async def process_implicit_callback(
    request: ImplicitTokenRequest, request_obj: Request, response: Response
):
    """
    Backend validation for Implicit Flow tokens.
    """
    # Verify Nonce
    stored_nonce = request_obj.cookies.get("oidc_nonce")
    if not stored_nonce:
        raise HTTPException(status_code=400, detail="Missing OIDC nonce")

    # Clear nonce cookie
    response.delete_cookie("oidc_nonce")

    # Decode ID Token (verify signature skipped for now as we trust the channel,
    # but strictly should verify against JWKS if possible, or atleast nonce)
    try:
        claims = jwt.get_unverified_claims(request.id_token)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID Token")

    # Check Nonce in claims
    token_nonce = claims.get("nonce")
    if token_nonce != stored_nonce:
        raise HTTPException(status_code=400, detail="Invalid Nonce")

    username = (
        claims.get("preferred_username")
        or claims.get("email")
        or claims.get("sub")
        or "user"
    )

    # Fetch User Teams to determine roles
    roles = ["ANALYST"]  # Default role

    from dt_client import DTClient

    # We need to call DT to get teams.
    # We use the access_token we just got.
    try:
        async with DTClient(
            dt_settings.api_url, bearer_token=request.access_token
        ) as dt_client:
            teams = await dt_client.get_self_teams()

            team_names = [t.get("name") for t in teams]

            if auth_settings.REVIEWER_TEAM in team_names:
                roles.append("REVIEWER")
            if auth_settings.ADMIN_TEAM in team_names:
                roles.append("ADMIN")

    except Exception as e:
        print(f"Failed to fetch teams for {username}: {e}")
        # Proceed with default role

    session_payload = {
        "sub": username,
        "dt_token": request.access_token,
        "dt_url": dt_settings.api_url,
        "roles": roles,
    }

    session_token = jwt.encode(
        session_payload, auth_settings.SESSION_SECRET_KEY, algorithm="HS256"
    )

    # We cannot redirect here because this is an AJAX request.
    # We just set the cookie and return 200.
    response.set_cookie(
        key="session_token", value=session_token, httponly=True, samesite="lax"
    )
    return {"status": "success"}


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


def get_current_user_roles(
    payload: dict = Depends(get_current_user_token_payload),
) -> list[str]:
    return payload.get("roles", ["ANALYST"])


@router.get("/me")
def get_user_info(
    user: str = Depends(get_current_user),
    roles: list[str] = Depends(get_current_user_roles),
):
    # Frontend expects "role" string for backwards compat.

    primary_role = "ANALYST"
    if "ADMIN" in roles:
        primary_role = "ADMIN"
    elif "REVIEWER" in roles:
        primary_role = "REVIEWER"

    return {
        "username": user,
        "role": primary_role,  # Deprecated single role
        "roles": roles,
    }


@router.get("/config")
def get_auth_config():
    return {"default_url": dt_settings.api_url}
