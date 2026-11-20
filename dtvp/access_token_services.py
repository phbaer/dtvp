"""Personal access tokens for machine clients (REST bearer auth and MCP).

A token belongs to one user, carries scopes, expires, and can be revoked.
Only a SHA-256 digest is stored: the secret part is 256 bits of randomness,
so a fast digest is sufficient and keeps per-request verification cheap.
The plain token is returned exactly once, when it is created.

The store also holds each user's browser session version. A session cookie
carries the version it was issued with; ``revoke_sessions`` raises it, which
ends every session of that user (see dtvp/session_services.py and
docs/adr/0004).
"""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import uuid
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .local_store import get_default_database_path
from .sqlite_migration_services import run_sqlite_migrations

ACCESS_TOKEN_MIGRATION_NAMESPACE = "access_tokens"
TOKEN_PREFIX = "dtvp_pat_"
SCOPE_READ = "read"
SCOPE_WRITE = "write"
VALID_SCOPES = (SCOPE_READ, SCOPE_WRITE)
DEFAULT_EXPIRY_DAYS = 90
MAX_EXPIRY_DAYS = 365
MAX_NAME_LENGTH = 100
MAX_ACTIVE_TOKENS_PER_USER = 20
LAST_USED_WRITE_INTERVAL = timedelta(minutes=1)
AUDIT_DETAIL_LIMIT = 2000
ENABLED_VALUES = {"1", "true", "yes", "on", "enabled"}


class AccessTokenError(ValueError):
    """A token request violates a validation rule or limit."""


@dataclass(frozen=True)
class AccessToken:
    token_id: str
    username: str
    name: str
    scopes: tuple[str, ...]
    created_at: str
    expires_at: str
    last_used_at: str | None
    revoked_at: str | None

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes

    def public(self) -> dict[str, Any]:
        return {
            "id": self.token_id,
            "name": self.name,
            "scopes": list(self.scopes),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "last_used_at": self.last_used_at,
            "revoked_at": self.revoked_at,
        }


def access_tokens_enabled() -> bool:
    return (
        os.getenv("DTVP_ACCESS_TOKENS_ENABLED", "false").strip().lower()
        in ENABLED_VALUES
    )


def get_access_tokens_path() -> str:
    configured_path = os.getenv("DTVP_ACCESS_TOKENS_PATH", "").strip()
    if configured_path:
        return configured_path
    # Tokens and their audit log live in the one local database.
    return get_default_database_path()


def get_access_token_migrations_path() -> Path:
    return Path(__file__).resolve().parent / "migrations" / "access_tokens"


def looks_like_access_token(value: str) -> bool:
    return value.startswith(TOKEN_PREFIX)


def forwardable_bearer(authorization: str | None) -> str | None:
    """The bearer value of a request that may be passed on to Dependency-Track.

    A DTVP access token authenticates the caller to DTVP only and is never
    forwarded, however the header is spaced.
    """
    scheme, _, value = str(authorization or "").partition(" ")
    value = value.strip()
    if scheme != "Bearer" or not value or looks_like_access_token(value):
        return None
    return value


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _normalize_scopes(scopes: Any) -> tuple[str, ...]:
    if not isinstance(scopes, (list, tuple, set, frozenset)) or not scopes:
        raise AccessTokenError("At least one scope is required")
    requested = {str(scope).strip().lower() for scope in scopes}
    unknown = sorted(requested - set(VALID_SCOPES))
    if unknown:
        raise AccessTokenError(f"Unknown scope: {', '.join(unknown)}")
    # Writing without reading is not a meaningful grant.
    requested.add(SCOPE_READ)
    return tuple(scope for scope in VALID_SCOPES if scope in requested)


class AccessTokenStore:
    def __init__(self, path: str | None = None, logger: Any = None) -> None:
        self._configured_path = path
        self.logger = logger
        self._lock = threading.RLock()
        self._initialized_path: str | None = None

    @property
    def path(self) -> str:
        return self._configured_path or get_access_tokens_path()

    def reset(self, path: str | None = None) -> None:
        with self._lock:
            self._configured_path = path
            self._initialized_path = None

    def _connect(self) -> sqlite3.Connection:
        path = self.path
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        connection = sqlite3.connect(path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        if self._initialized_path != path:
            run_sqlite_migrations(
                connection,
                namespace=ACCESS_TOKEN_MIGRATION_NAMESPACE,
                migrations_path=get_access_token_migrations_path(),
                logger=self.logger,
            )
            self._initialized_path = path
        return connection

    @staticmethod
    def _record(row: sqlite3.Row) -> AccessToken:
        return AccessToken(
            token_id=row["token_id"],
            username=row["username"],
            name=row["name"],
            scopes=tuple(str(row["scopes"]).split()),
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            last_used_at=row["last_used_at"],
            revoked_at=row["revoked_at"],
        )

    def create(
        self,
        *,
        username: str,
        name: str,
        scopes: Any,
        expires_in_days: int = DEFAULT_EXPIRY_DAYS,
        now: datetime | None = None,
    ) -> tuple[AccessToken, str]:
        """Create a token and return its record with the one-time plain value."""
        username = str(username or "").strip()
        if not username:
            raise AccessTokenError("A token needs an owner")
        name = " ".join(str(name or "").split())
        if not name:
            raise AccessTokenError("A token name is required")
        if len(name) > MAX_NAME_LENGTH:
            raise AccessTokenError(
                f"Token names are limited to {MAX_NAME_LENGTH} characters"
            )
        normalized_scopes = _normalize_scopes(scopes)
        if (
            isinstance(expires_in_days, bool)
            or not isinstance(expires_in_days, int)
            or not 1 <= expires_in_days <= MAX_EXPIRY_DAYS
        ):
            raise AccessTokenError(
                f"Expiry must be between 1 and {MAX_EXPIRY_DAYS} days"
            )

        current = now or datetime.now(UTC)
        token_id = uuid.uuid4().hex[:16]
        plain = f"{TOKEN_PREFIX}{token_id}_{secrets.token_urlsafe(32)}"
        record = AccessToken(
            token_id=token_id,
            username=username,
            name=name,
            scopes=normalized_scopes,
            created_at=_iso(current),
            expires_at=_iso(current + timedelta(days=expires_in_days)),
            last_used_at=None,
            revoked_at=None,
        )
        with self._lock, closing(self._connect()) as connection, connection:
            active = connection.execute(
                """
                SELECT COUNT(*) FROM access_tokens
                WHERE username = ? AND revoked_at IS NULL AND expires_at > ?
                """,
                (username, record.created_at),
            ).fetchone()[0]
            if active >= MAX_ACTIVE_TOKENS_PER_USER:
                raise AccessTokenError(
                    f"At most {MAX_ACTIVE_TOKENS_PER_USER} active tokens per user; "
                    "revoke one first"
                )
            connection.execute(
                """
                INSERT INTO access_tokens (
                    token_id, username, name, token_hash, scopes,
                    created_at, expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.token_id,
                    record.username,
                    record.name,
                    _hash_token(plain),
                    " ".join(record.scopes),
                    record.created_at,
                    record.expires_at,
                ),
            )
        return record, plain

    def list_for_user(self, username: str) -> list[AccessToken]:
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT * FROM access_tokens
                WHERE username = ?
                ORDER BY created_at DESC, token_id
                """,
                (username,),
            ).fetchall()
        return [self._record(row) for row in rows]

    def revoke(
        self,
        *,
        username: str,
        token_id: str,
        now: datetime | None = None,
    ) -> bool:
        """Revoke one of the user's tokens. Returns False when it is not theirs."""
        with self._lock, closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """
                UPDATE access_tokens
                SET revoked_at = COALESCE(revoked_at, ?)
                WHERE token_id = ? AND username = ?
                """,
                (_iso(now or datetime.now(UTC)), token_id, username),
            )
            return cursor.rowcount > 0

    def verify(self, token: str, *, now: datetime | None = None) -> AccessToken | None:
        """Return the token record when the plain value is valid and usable."""
        if not isinstance(token, str) or not looks_like_access_token(token):
            return None
        digest = _hash_token(token)
        current = now or datetime.now(UTC)
        with self._lock, closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT * FROM access_tokens WHERE token_hash = ?",
                (digest,),
            ).fetchone()
            if row is None or not hmac.compare_digest(row["token_hash"], digest):
                return None
            if row["revoked_at"] is not None:
                return None
            if datetime.fromisoformat(row["expires_at"]) <= current:
                return None
            last_used = row["last_used_at"]
            if (
                last_used is None
                or current - datetime.fromisoformat(last_used)
                >= LAST_USED_WRITE_INTERVAL
            ):
                connection.execute(
                    "UPDATE access_tokens SET last_used_at = ? WHERE token_id = ?",
                    (_iso(current), row["token_id"]),
                )
            return self._record(row)

    def session_version(self, username: str) -> int:
        """The user's current browser session version; 0 until first revoked."""
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT version FROM session_versions WHERE username = ?",
                (username,),
            ).fetchone()
        return int(row["version"]) if row is not None else 0

    def revoke_sessions(self, username: str, *, now: datetime | None = None) -> int:
        """End every browser session of the user and return the new version."""
        with self._lock, closing(self._connect()) as connection, connection:
            rows = connection.execute(
                """
                INSERT INTO session_versions (username, version, revoked_at)
                VALUES (?, 1, ?)
                ON CONFLICT(username) DO UPDATE
                SET version = version + 1, revoked_at = excluded.revoked_at
                RETURNING version
                """,
                (username, _iso(now or datetime.now(UTC))),
            ).fetchall()
        return int(rows[0]["version"])

    def record_audit(
        self,
        *,
        token: AccessToken,
        agent: str,
        action: str,
        outcome: str,
        target: Any = None,
        detail: str = "",
        now: datetime | None = None,
    ) -> None:
        with self._lock, closing(self._connect()) as connection, connection:
            connection.execute(
                """
                INSERT INTO access_token_audit (
                    occurred_at, username, token_id, agent, action,
                    outcome, target_json, detail
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _iso(now or datetime.now(UTC)),
                    token.username,
                    token.token_id,
                    str(agent or "")[:MAX_NAME_LENGTH],
                    action,
                    outcome,
                    json.dumps(target if target is not None else {}, sort_keys=True),
                    str(detail or "")[:AUDIT_DETAIL_LIMIT],
                ),
            )

    def list_audit(
        self,
        *,
        username: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        query = "SELECT * FROM access_token_audit"
        params: list[Any] = []
        if username is not None:
            query += " WHERE username = ?"
            params.append(username)
        query += " ORDER BY audit_id DESC LIMIT ?"
        params.append(limit)
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(query, params).fetchall()
        return [
            {
                "id": row["audit_id"],
                "occurred_at": row["occurred_at"],
                "username": row["username"],
                "token_id": row["token_id"],
                "agent": row["agent"],
                "action": row["action"],
                "outcome": row["outcome"],
                "target": json.loads(row["target_json"]),
                "detail": row["detail"],
            }
            for row in rows
        ]


access_token_store = AccessTokenStore()
