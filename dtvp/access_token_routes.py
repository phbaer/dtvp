import asyncio
from typing import Annotated, Any, Callable

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .access_token_services import (
    DEFAULT_EXPIRY_DAYS,
    MAX_EXPIRY_DAYS,
    SCOPE_READ,
    VALID_SCOPES,
    AccessTokenError,
    AccessTokenStore,
    access_tokens_enabled,
)


class AccessTokenCreateRequest(BaseModel):
    name: str
    scopes: list[str] = Field(default_factory=lambda: [SCOPE_READ])
    expires_in_days: int = DEFAULT_EXPIRY_DAYS


def create_access_token_router(
    store: AccessTokenStore,
    *,
    session_user_dependency: Callable[..., Any],
    get_user_role: Callable[[str], str],
) -> APIRouter:
    """Token management. Requires an interactive session: a token can never
    list, create, or revoke tokens."""
    router = APIRouter()
    SessionUser = Annotated[str, Depends(session_user_dependency)]

    def require_enabled() -> None:
        if not access_tokens_enabled():
            raise HTTPException(status_code=404, detail="Access tokens are disabled")

    @router.get("/settings/tokens")
    async def list_tokens(user: SessionUser):
        enabled = access_tokens_enabled()
        tokens = (
            await asyncio.to_thread(store.list_for_user, user) if enabled else []
        )
        return {
            "enabled": enabled,
            "scopes": list(VALID_SCOPES),
            "default_expiry_days": DEFAULT_EXPIRY_DAYS,
            "max_expiry_days": MAX_EXPIRY_DAYS,
            "tokens": [token.public() for token in tokens],
        }

    @router.post("/settings/tokens", status_code=201)
    async def create_token(req: AccessTokenCreateRequest, user: SessionUser):
        require_enabled()
        try:
            record, plain = await asyncio.to_thread(
                store.create,
                username=user,
                name=req.name,
                scopes=req.scopes,
                expires_in_days=req.expires_in_days,
            )
        except AccessTokenError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        # The plain value is shown once and cannot be recovered afterwards.
        return {**record.public(), "token": plain}

    @router.delete("/settings/tokens/{token_id}")
    async def revoke_token(token_id: str, user: SessionUser):
        require_enabled()
        revoked = await asyncio.to_thread(
            store.revoke, username=user, token_id=token_id
        )
        if not revoked:
            raise HTTPException(status_code=404, detail="Token not found")
        return {"status": "revoked", "id": token_id}

    @router.get("/settings/tokens/audit")
    async def list_token_audit(user: SessionUser, limit: int = 100):
        require_enabled()
        # Reviewers see every machine-client change; others see their own.
        scope_user = None if get_user_role(user) == "REVIEWER" else user
        return await asyncio.to_thread(
            store.list_audit, username=scope_user, limit=limit
        )

    return router
