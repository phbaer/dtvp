"""Saved views, short links and default views of the project review.

ADR 0015. A view is a filter state of the project review: the canonical
query string of its filters, for one project or any project (``None``).

- ``personal`` views belong to their owner;
- ``global`` views are visible to everyone and created and changed by
  reviewers.

Every view is addressed by its code, which is also its short link
(``/v/<code>``); unsaved filters are shared as a full URL. Any signed-in user
can resolve any code (a filter state is not a secret). Codes do not expire.
A view with a cutoff stores the cutoff basis in effect when it was saved.
Defaults name a view per user or per role, for a project or for all
projects (``""``).
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qsl, urlencode

from .first_seen import normalize_cutoff, normalize_cutoff_basis, normalize_cutoff_mode
from .local_store import get_default_database_path
from .sqlite_migration_services import run_sqlite_migrations

SAVED_VIEWS_MIGRATION_NAMESPACE = "saved_views"

SCOPE_PERSONAL = "personal"
SCOPE_GLOBAL = "global"
NAMED_SCOPES = (SCOPE_PERSONAL, SCOPE_GLOBAL)

SUBJECT_USER = "user"
SUBJECT_ROLE = "role"
ROLES = ("ANALYST", "REVIEWER")
ALL_PROJECTS = ""

# 31 characters without look-alikes (0/o, 1/l/i): about 8.5 * 10^11 codes.
CODE_ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz"
CODE_LENGTH = 8
MAX_NAME_LENGTH = 80
MAX_PROJECT_LENGTH = 255
MAX_QUERY_LENGTH = 4000
MAX_VALUES_PER_PARAMETER = 100
MAX_PERSONAL_VIEWS = 100
MAX_GLOBAL_VIEWS = 200

_LIST = "list"
_TEXT = "text"
_FLAG = "flag"
_TRUE_FALSE = "true_false"

SORT_KEYS = ("rescored-severity", "severity", "score", "rescored", "analysis", "tags", "id")

# The parameters of the project filters (docs/review-workflows.md), and how
# each is checked. Anything else is refused.
FILTER_PARAMETERS: dict[str, Any] = {
    "q": _TEXT,
    "id": _TEXT,
    "component": _TEXT,
    "assignee": _TEXT,
    "versions": _TEXT,
    "lifecycle": _LIST,
    "analysis": _LIST,
    "teams": _LIST,
    "inconsistency_reason": _LIST,
    "original_severity": _LIST,
    "ssvc": _LIST,
    "evidence": _LIST,
    "dependency": _LIST,
    "tmrescore": _LIST,
    "automatic_assessment": _LIST,
    "automatic_assessment_outcome": _LIST,
    "automatic_assessment_rescore": _LIST,
    "awaiting_review": _TRUE_FALSE,
    "changes_requested": _FLAG,
    "mcp_assessments": _FLAG,
    "new_findings": _FLAG,
    "not_rescored": _FLAG,
    "cvss_mismatch": _FLAG,
    "team_assessment": ("ANY", "MISSING", "DOCUMENTED"),
    "order": ("asc", "desc"),
    "sort": SORT_KEYS,
    "cutoff": normalize_cutoff,
    "cutoff_mode": normalize_cutoff_mode,
    "cutoff_basis": normalize_cutoff_basis,
}


class SavedViewError(ValueError):
    """A request violates a rule; ``status`` is the HTTP status to answer."""

    def __init__(self, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.status = status


def get_saved_views_path() -> str:
    return get_default_database_path()


def get_saved_view_migrations_path() -> Path:
    return Path(__file__).resolve().parent / "migrations" / "saved_views"


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _is_reviewer(role: str) -> bool:
    return str(role or "").upper() == "REVIEWER"


def canonical_query(query: Any) -> str:
    """The canonical form of a filter query string: known parameters only,
    each value checked, list values sorted, parameters in name order.
    ``SavedViewError`` names what is wrong."""
    text = str(query or "").strip()
    if text.startswith("?"):
        text = text[1:]
    if len(text) > MAX_QUERY_LENGTH:
        raise SavedViewError(f"The filter query is limited to {MAX_QUERY_LENGTH} characters")
    try:
        pairs = parse_qsl(text, keep_blank_values=True, strict_parsing=bool(text))
    except ValueError as exc:
        raise SavedViewError("The filter query is not a query string") from exc
    values: dict[str, list[str]] = {}
    for key, value in pairs:
        values.setdefault(key, []).append(value.strip())
    unknown = sorted(set(values) - set(FILTER_PARAMETERS))
    if unknown:
        raise SavedViewError(f"Unknown filter parameter: {', '.join(unknown)}")
    result: list[tuple[str, str]] = []
    for key in sorted(values):
        rule = FILTER_PARAMETERS[key]
        items = [item for item in values[key] if item]
        if not items:
            continue
        if rule == _LIST:
            if len(items) > MAX_VALUES_PER_PARAMETER:
                raise SavedViewError(f"Too many values for {key}")
            result.extend((key, item) for item in sorted(set(items)))
            continue
        if len(items) > 1:
            raise SavedViewError(f"{key} takes one value")
        item = items[0]
        if rule == _TEXT:
            canonical = item
        elif rule == _FLAG:
            if item not in ("true", "false"):
                raise SavedViewError(f"{key} must be true or false")
            if item == "false":
                continue
            canonical = item
        elif rule == _TRUE_FALSE:
            if item not in ("true", "false"):
                raise SavedViewError(f"{key} must be true or false")
            canonical = item
        elif isinstance(rule, tuple):
            upper = {option.upper(): option for option in rule}
            if item.upper() not in upper:
                raise SavedViewError(f"{key} must be one of {', '.join(rule)}")
            canonical = upper[item.upper()]
        else:
            try:
                canonical = rule(item)
            except ValueError as exc:
                raise SavedViewError(str(exc)) from exc
            if not canonical:
                continue
        result.append((key, canonical))
    return urlencode(result)


def with_cutoff_basis(query: str, default_basis: str) -> str:
    """A canonical query with a cutoff keeps the basis in effect, so the view
    shows the same when the instance default changes."""
    pairs = parse_qsl(query, keep_blank_values=True)
    keys = {key for key, _ in pairs}
    if "cutoff" not in keys or "cutoff_basis" in keys:
        return query
    return canonical_query(urlencode([*pairs, ("cutoff_basis", default_basis)]))


def _clean_name(name: Any) -> str:
    text = " ".join(str(name or "").split())
    if not text:
        raise SavedViewError("A view needs a name")
    if len(text) > MAX_NAME_LENGTH:
        raise SavedViewError(f"View names are limited to {MAX_NAME_LENGTH} characters")
    return text


def _clean_project(project: Any) -> Optional[str]:
    text = str(project or "").strip()
    if len(text) > MAX_PROJECT_LENGTH:
        raise SavedViewError(f"Project names are limited to {MAX_PROJECT_LENGTH} characters")
    return text or None


def normalize_code(code: Any) -> str:
    return str(code or "").strip().lower()


def new_code() -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))


@dataclass(frozen=True)
class SavedView:
    code: str
    scope: str
    name: str
    project: Optional[str]
    query: str
    owner: str
    created_at: str
    updated_at: str
    updated_by: str

    def public(self, user: str = "", role: str = "") -> dict[str, Any]:
        return {
            "code": self.code,
            "scope": self.scope,
            "name": self.name,
            "project": self.project,
            "query": self.query,
            "owner": self.owner,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "updated_by": self.updated_by,
            "editable": can_edit(self, user, role),
        }


def can_edit(view: SavedView, user: str, role: str) -> bool:
    if view.scope == SCOPE_PERSONAL:
        return view.owner == user
    return view.scope == SCOPE_GLOBAL and _is_reviewer(role)


def _visible(view: SavedView, user: str) -> bool:
    return view.scope == SCOPE_GLOBAL or (
        view.scope == SCOPE_PERSONAL and view.owner == user
    )


class SavedViewStore:
    def __init__(self, path: str | None = None, logger: Any = None) -> None:
        self._configured_path = path
        self.logger = logger
        self._lock = threading.RLock()
        self._initialized_path: str | None = None

    @property
    def path(self) -> str:
        return self._configured_path or get_saved_views_path()

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
                namespace=SAVED_VIEWS_MIGRATION_NAMESPACE,
                migrations_path=get_saved_view_migrations_path(),
                logger=self.logger,
            )
            self._initialized_path = path
        return connection

    @staticmethod
    def _record(row: sqlite3.Row) -> SavedView:
        return SavedView(
            code=row["code"],
            scope=row["scope"],
            name=row["name"],
            project=row["project"],
            query=row["query"],
            owner=row["owner"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            updated_by=row["updated_by"],
        )

    def _get(self, connection: sqlite3.Connection, code: str) -> Optional[SavedView]:
        row = connection.execute(
            "SELECT * FROM saved_views WHERE code = ?", (normalize_code(code),)
        ).fetchone()
        return self._record(row) if row is not None else None

    def _insert(self, connection: sqlite3.Connection, view: SavedView) -> SavedView:
        for _ in range(10):
            code = new_code()
            try:
                connection.execute(
                    """
                    INSERT INTO saved_views (
                        code, scope, name, project, query, owner,
                        created_at, updated_at, updated_by
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        code, view.scope, view.name, view.project, view.query,
                        view.owner, view.created_at, view.updated_at, view.updated_by,
                    ),
                )
            except sqlite3.IntegrityError:
                if self._get(connection, code) is None:
                    raise
                continue
            return SavedView(**{**view.__dict__, "code": code})
        raise SavedViewError("No free code was found; try again", status=503)

    def _check_name_free(
        self,
        connection: sqlite3.Connection,
        *,
        scope: str,
        owner: str,
        project: Optional[str],
        name: str,
        except_code: str = "",
    ) -> None:
        rows = connection.execute(
            """
            SELECT code, name FROM saved_views
            WHERE scope = ? AND (scope = 'global' OR owner = ?)
              AND COALESCE(project, '') = ?
            """,
            (scope, owner, project or ""),
        ).fetchall()
        if any(
            row["code"] != except_code and str(row["name"] or "").casefold() == name.casefold()
            for row in rows
        ):
            raise SavedViewError(f"A {scope} view named {name!r} exists already", status=409)

    # -- reading -----------------------------------------------------------

    def get(self, code: str) -> Optional[SavedView]:
        with self._lock, closing(self._connect()) as connection:
            return self._get(connection, code)

    def list_for(self, user: str, project: Optional[str] = None) -> list[SavedView]:
        """The named views a user sees: their personal views and the global
        ones; with a project, those for it and for any project."""
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT * FROM saved_views
                WHERE (scope = 'global' OR (scope = 'personal' AND owner = ?))
                  AND (? IS NULL OR project IS NULL OR project = ?)
                ORDER BY scope DESC, LOWER(name), code
                """,
                (user, project, project),
            ).fetchall()
        return [self._record(row) for row in rows]

    def defaults_for(self, user: str, role: str, project: Optional[str]) -> dict[str, Any]:
        """The defaults that apply to a user on a project and the effective
        one: the user's for the project, for all projects, the role's for
        the project, for all projects; else the built-in default."""
        role = str(role or "").upper()
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT d.subject_kind, d.subject, d.project, d.code
                FROM saved_view_defaults d JOIN saved_views v ON v.code = d.code
                WHERE ((d.subject_kind = 'user' AND d.subject = ?)
                       OR d.subject_kind = 'role')
                  AND d.project IN ('', ?)
                """,
                (user, project or ""),
            ).fetchall()
            found: dict[tuple[str, str, str], str] = {
                (row["subject_kind"], row["subject"], row["project"]): row["code"]
                for row in rows
            }
            levels = [
                ("user_project", (SUBJECT_USER, user, project or None)),
                ("user_all", (SUBJECT_USER, user, ALL_PROJECTS)),
                ("role_project", (SUBJECT_ROLE, role, project or None)),
                ("role_all", (SUBJECT_ROLE, role, ALL_PROJECTS)),
            ]
            result: dict[str, Any] = {}
            effective: dict[str, Any] = {"source": "builtin", "code": None, "query": None}
            for name, (kind, subject, scope_project) in levels:
                code = (
                    found.get((kind, subject, scope_project))
                    if scope_project is not None
                    else None
                )
                result[name] = code
                if code and effective["code"] is None:
                    view = self._get(connection, code)
                    if view is not None and (
                        kind == SUBJECT_ROLE or _visible(view, user)
                    ):
                        effective = {
                            "source": "user" if kind == SUBJECT_USER else "role",
                            "code": view.code,
                            "query": view.query,
                            "name": view.name,
                        }
            result["roles"] = {
                role_name: {
                    "project": found.get((SUBJECT_ROLE, role_name, project or "")) if project else None,
                    "all": found.get((SUBJECT_ROLE, role_name, ALL_PROJECTS)),
                }
                for role_name in ROLES
            }
            result["effective"] = effective
            return result

    # -- writing -----------------------------------------------------------

    def create(
        self,
        *,
        user: str,
        role: str,
        name: Any,
        scope: str,
        project: Any,
        query: Any,
        default_cutoff_basis: str = "",
        now: datetime | None = None,
    ) -> SavedView:
        if scope not in NAMED_SCOPES:
            raise SavedViewError("scope must be personal or global")
        if scope == SCOPE_GLOBAL and not _is_reviewer(role):
            raise SavedViewError("Only reviewers create global views", status=403)
        clean_name = _clean_name(name)
        clean_project = _clean_project(project)
        canonical = canonical_query(query)
        if default_cutoff_basis:
            canonical = with_cutoff_basis(canonical, default_cutoff_basis)
        at = _iso(now or _now())
        with self._lock, closing(self._connect()) as connection, connection:
            if scope == SCOPE_GLOBAL:
                count = connection.execute(
                    "SELECT COUNT(*) FROM saved_views WHERE scope = 'global'"
                ).fetchone()[0]
                limit = MAX_GLOBAL_VIEWS
            else:
                count = connection.execute(
                    "SELECT COUNT(*) FROM saved_views WHERE scope = 'personal' AND owner = ?",
                    (user,),
                ).fetchone()[0]
                limit = MAX_PERSONAL_VIEWS
            if count >= limit:
                raise SavedViewError(
                    f"At most {limit} {scope} views; delete one first", status=409
                )
            self._check_name_free(
                connection, scope=scope, owner=user, project=clean_project, name=clean_name,
            )
            return self._insert(
                connection,
                SavedView(
                    code="", scope=scope, name=clean_name, project=clean_project,
                    query=canonical, owner=user, created_at=at, updated_at=at,
                    updated_by=user,
                ),
            )

    def update(
        self,
        *,
        user: str,
        role: str,
        code: str,
        changes: dict[str, Any],
        default_cutoff_basis: str = "",
        now: datetime | None = None,
    ) -> SavedView:
        """Rename, change the filters or the project of a view, or share a
        personal view globally (``scope: "global"``, reviewers)."""
        with self._lock, closing(self._connect()) as connection, connection:
            view = self._get(connection, code)
            if view is None or not _visible(view, user):
                raise SavedViewError("View not found", status=404)
            target_scope = changes.get("scope", view.scope)
            if view.scope == SCOPE_PERSONAL and target_scope == SCOPE_GLOBAL:
                if view.owner != user or not _is_reviewer(role):
                    raise SavedViewError("Only reviewers share their views globally", status=403)
            elif target_scope != view.scope:
                raise SavedViewError("A global view stays global")
            elif not can_edit(view, user, role):
                raise SavedViewError(
                    "Only reviewers change global views" if view.scope == SCOPE_GLOBAL
                    else "Only its owner changes a personal view",
                    status=403,
                )
            name = _clean_name(changes["name"]) if "name" in changes else view.name
            project = _clean_project(changes["project"]) if "project" in changes else view.project
            query = canonical_query(changes["query"]) if "query" in changes else view.query
            if "query" in changes and default_cutoff_basis:
                query = with_cutoff_basis(query, default_cutoff_basis)
            if target_scope == SCOPE_GLOBAL and view.scope != SCOPE_GLOBAL:
                count = connection.execute(
                    "SELECT COUNT(*) FROM saved_views WHERE scope = 'global'"
                ).fetchone()[0]
                if count >= MAX_GLOBAL_VIEWS:
                    raise SavedViewError(f"At most {MAX_GLOBAL_VIEWS} global views", status=409)
            self._check_name_free(
                connection, scope=target_scope, owner=view.owner, project=project,
                name=str(name), except_code=view.code,
            )
            at = _iso(now or _now())
            connection.execute(
                """
                UPDATE saved_views
                SET scope = ?, name = ?, project = ?, query = ?,
                    updated_at = ?, updated_by = ?
                WHERE code = ?
                """,
                (target_scope, name, project, query, at, user, view.code),
            )
            return self._get(connection, view.code)  # type: ignore[return-value]

    def delete(self, *, user: str, role: str, code: str) -> None:
        with self._lock, closing(self._connect()) as connection, connection:
            view = self._get(connection, code)
            if view is None or not _visible(view, user):
                raise SavedViewError("View not found", status=404)
            if not can_edit(view, user, role):
                raise SavedViewError("You cannot delete this view", status=403)
            connection.execute("DELETE FROM saved_view_defaults WHERE code = ?", (view.code,))
            connection.execute("DELETE FROM saved_views WHERE code = ?", (view.code,))

    def set_default(
        self,
        *,
        user: str,
        role: str,
        target: str,
        target_role: Optional[str],
        project: Any,
        code: Optional[str],
        now: datetime | None = None,
    ) -> None:
        """Set or clear (``code`` empty) a default view: the user's own
        (``target="user"``), or a role's (``target="role"``, reviewers, a
        global view)."""
        clean_project = _clean_project(project) or ALL_PROJECTS
        if target == SUBJECT_USER:
            subject = user
        elif target == SUBJECT_ROLE:
            if not _is_reviewer(role):
                raise SavedViewError("Only reviewers set role defaults", status=403)
            subject = str(target_role or "").upper()
            if subject not in ROLES:
                raise SavedViewError(f"role must be one of {', '.join(ROLES)}")
        else:
            raise SavedViewError("target must be user or role")
        at = _iso(now or _now())
        with self._lock, closing(self._connect()) as connection, connection:
            if not code:
                connection.execute(
                    """
                    DELETE FROM saved_view_defaults
                    WHERE subject_kind = ? AND subject = ? AND project = ?
                    """,
                    (target, subject, clean_project),
                )
                return
            view = self._get(connection, code)
            if view is None or not _visible(view, user):
                raise SavedViewError("View not found", status=404)
            if target == SUBJECT_ROLE and view.scope != SCOPE_GLOBAL:
                raise SavedViewError("A role default must be a global view")
            if view.project is not None and view.project != (clean_project or None):
                raise SavedViewError("The view belongs to another project")
            connection.execute(
                """
                INSERT INTO saved_view_defaults (
                    subject_kind, subject, project, code, updated_at, updated_by
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT (subject_kind, subject, project) DO UPDATE SET
                    code = excluded.code,
                    updated_at = excluded.updated_at,
                    updated_by = excluded.updated_by
                """,
                (target, subject, clean_project, view.code, at, user),
            )


saved_view_store = SavedViewStore()
