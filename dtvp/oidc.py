"""Authlib OIDC authorization-code integration with bounded local identity claims."""

from urllib.parse import urlsplit

import httpx
from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.starlette_client import OAuth, StarletteOAuth2App
from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse
from joserfc.errors import JoseError
from sqlalchemy import select

from dtvp.auth import issue
from dtvp.models import User

AUTH_FAILURE = "Sign-in failed; start a new sign-in request"


def _text(value, limit, *, required=True):
    return (
        isinstance(value, str)
        and (bool(value.strip()) or not required)
        and len(value) <= limit
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
    )


def _identity(token, issuer):
    if not isinstance(token, dict) or not isinstance(token.get("id_token"), str):
        raise ValueError("A validated ID token is required")
    info = token.get("userinfo")
    if (
        not isinstance(info, dict)
        or info.get("iss") != issuer
        or not _text(info.get("iss"), 500)
        or not _text(info.get("sub"), 255)
        or not _text(info.get("nonce"), 512)
        or ("name" in info and not _text(info["name"], 200, required=False))
    ):
        raise ValueError("Untrusted identity claims")
    return info["iss"], info["sub"], info.get("name") or info["sub"][:200]


def _endpoint(value):
    if not _text(value, 2048):
        return False
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme in {"https", "http"}
            and bool(parsed.hostname)
            and not parsed.username
            and not parsed.password
            and not parsed.fragment
        )
    except ValueError:
        return False


class _ValidatedOIDC(StarletteOAuth2App):
    """Validate provider envelope shapes; Authlib owns all protocol verification."""

    def __init__(self, *args, expected_issuer, **kwargs):
        self.expected_issuer = expected_issuer
        super().__init__(*args, **kwargs)

    async def load_server_metadata(self):
        try:
            metadata = await super().load_server_metadata()
        except (TypeError, AttributeError) as error:
            raise ValueError("Malformed identity provider discovery") from error
        if (
            not isinstance(metadata, dict)
            or metadata.get("issuer") != self.expected_issuer
            or not _endpoint(metadata.get("authorization_endpoint"))
            or not _endpoint(metadata.get("token_endpoint"))
            or ("jwks_uri" in metadata and not _endpoint(metadata["jwks_uri"]))
        ):
            raise ValueError("Incomplete or untrusted identity provider discovery")
        algorithms = metadata.get("id_token_signing_alg_values_supported", ["RS256"])
        if (
            not isinstance(algorithms, list)
            or not algorithms
            or any(not _text(value, 50) or value == "none" for value in algorithms)
        ):
            raise ValueError("Malformed identity provider signing algorithms")
        return metadata

    async def fetch_jwk_set(self, force=False):
        metadata = await self.load_server_metadata()
        if not metadata.get("jwks") and not metadata.get("jwks_uri"):
            raise ValueError("Identity provider discovery lacks signing keys")
        keys = await super().fetch_jwk_set(force=force)
        if not isinstance(keys, dict) or not isinstance(keys.get("keys"), list):
            raise ValueError("Malformed identity provider signing keys")
        for key in keys["keys"]:
            if not isinstance(key, dict) or not _text(key.get("kty"), 50):
                raise ValueError("Malformed identity provider signing key")
            for field in (
                "kid",
                "alg",
                "use",
                "crv",
                "n",
                "e",
                "x",
                "y",
                "d",
                "p",
                "q",
                "dp",
                "dq",
                "qi",
                "k",
            ):
                if field in key and not _text(key[field], 64 * 1024):
                    raise ValueError("Malformed identity provider key parameter")
        return keys


def _token_response(response):
    # Validate the untrusted envelope before Authlib parses/verifies its JWT.
    # Keep all authentication and cryptographic decisions in Authlib.
    body = response.json()
    if not isinstance(body, dict) or (
        "id_token" in body and not _text(body["id_token"], 256 * 1024)
    ):
        raise ValueError("Malformed identity provider token response")
    return response


def _compliance(client):
    client.register_compliance_hook("access_token_response", _token_response)


def install_oidc(app, settings, factory):
    oauth = OAuth()
    if settings.oidc_issuer:
        oauth.register(
            name="oidc",
            client_cls=_ValidatedOIDC,
            expected_issuer=settings.oidc_issuer,
            client_id=settings.oidc_client_id,
            client_secret=settings.oidc_client_secret,
            compliance_fix=_compliance,
            server_metadata_url=settings.oidc_issuer.rstrip("/")
            + "/.well-known/openid-configuration",
            client_kwargs={"scope": "openid profile", "code_challenge_method": "S256"},
        )

    @app.get("/auth/login")
    async def oidc_login(request: Request):
        if not settings.oidc_issuer:
            raise HTTPException(503, "OIDC is not configured")
        try:
            return await oauth.oidc.authorize_redirect(
                request, settings.public_url.rstrip("/") + "/auth/callback"
            )
        except OAuthError, JoseError, httpx.HTTPError, ValueError:
            request.session.clear()
            raise HTTPException(503, "Sign-in provider is unavailable") from None

    @app.get("/auth/callback")
    async def oidc_callback(request: Request):
        if not settings.oidc_issuer:
            raise HTTPException(404)
        try:
            # Authlib verifies state and exchanges PKCE. Bind nonce as an explicit
            # claim too: a provider nonce_supported=false must never bypass it.
            saved = await oauth.oidc.framework.get_state_data(
                request.session, request.query_params.get("state")
            )
            if not isinstance(saved, dict) or not _text(saved.get("nonce"), 512):
                raise ValueError("Missing sign-in state")
            token = await oauth.oidc.authorize_access_token(
                request,
                claims_options={
                    "iss": {"essential": True, "value": settings.oidc_issuer},
                    "nonce": {"essential": True, "value": saved["nonce"]},
                    "aud": {"essential": True, "value": settings.oidc_client_id},
                },
            )
            issuer, subject, name = _identity(token, settings.oidc_issuer)
        except OAuthError, JoseError, httpx.HTTPError, ValueError:
            request.session.clear()
            raise HTTPException(403, AUTH_FAILURE) from None
        with factory.begin() as db:
            user = db.scalar(select(User).where(User.issuer == issuer, User.subject == subject))
            if not user:
                user = User(issuer=issuer, subject=subject, name=name)
                db.add(user)
                db.flush()
            value, csrf, _ = issue(db, user)
        request.session.clear()
        response = RedirectResponse("/")
        secure = settings.public_url.startswith("https://")
        response.set_cookie(
            "dtvp_session", value, httponly=True, secure=secure, samesite="strict", max_age=43200
        )
        response.set_cookie("dtvp_csrf", csrf, secure=secure, samesite="strict", max_age=43200)
        return response
