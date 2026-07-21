import hashlib
import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .vulnerability_backend import backend_scoped_file


GROUPED_VULN_SUMMARY_INDEX_SCHEMA_VERSION = 3


def get_grouped_vuln_summary_index_path() -> str:
    configured_path = os.getenv("DTVP_GROUPED_VULN_SUMMARY_INDEX_PATH", "").strip()
    if configured_path:
        return backend_scoped_file(configured_path)

    dt_cache_path = Path(os.getenv("DTVP_DT_CACHE_PATH", "data/dt_cache"))
    return backend_scoped_file(
        str(dt_cache_path.parent / "grouped_vuln_summary_index.sqlite")
    )


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _version_fingerprints(versions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "uuid": version.get("uuid"),
            "name": version.get("name"),
            "version": version.get("version"),
            "lastBomImport": version.get("lastBomImport"),
            "lastInheritedRiskScore": version.get("lastInheritedRiskScore"),
            "lastRiskScore": version.get("lastRiskScore"),
        }
        for version in versions
    ]


def build_grouped_vuln_summary_cache_key(
    *,
    name: str,
    cve: str | None,
    versions: list[dict[str, Any]],
    team_mapping: dict[str, Any],
    cache_revision: Any,
) -> str:
    payload = {
        "schema": GROUPED_VULN_SUMMARY_INDEX_SCHEMA_VERSION,
        "name": name or "",
        "cve": str(cve or "").upper(),
        "versions": _version_fingerprints(versions),
        "team_mapping": team_mapping,
        "cache_revision": cache_revision,
    }
    return hashlib.sha256(_stable_json(payload).encode("utf-8")).hexdigest()


class GroupedVulnSummaryIndex:
    def __init__(
        self,
        *,
        path_provider: Callable[[], str] = get_grouped_vuln_summary_index_path,
        max_entries_provider: Callable[[], int] = lambda: 64,
        logger: Any = None,
    ):
        self.path_provider = path_provider
        self.max_entries_provider = max_entries_provider
        self.logger = logger

    def _connect(self) -> sqlite3.Connection:
        path = self.path_provider()
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        connection = sqlite3.connect(path, timeout=5)
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            os.chmod(path, 0o600)
        except OSError:
            if self.logger:
                self.logger.warning(
                    "Could not restrict grouped summary database permissions: %s",
                    path,
                )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS grouped_vuln_summary_index (
                cache_key TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                scope_json TEXT NOT NULL,
                summaries_json TEXT NOT NULL,
                statistics_json TEXT NOT NULL,
                total_versions INTEGER NOT NULL
            )
            """
        )
        connection.commit()
        return connection

    def load(self, cache_key: str) -> dict[str, Any] | None:
        try:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    """
                    SELECT created_at, scope_json, summaries_json, statistics_json,
                           total_versions
                    FROM grouped_vuln_summary_index
                    WHERE cache_key = ?
                    """,
                    (cache_key,),
                ).fetchone()
        except Exception as exc:
            if self.logger:
                self.logger.warning(
                    "Failed to load grouped vulnerability summary index: %s",
                    exc,
                )
            return None

        if not row:
            return None

        created_at, scope_json, summaries_json, statistics_json, total_versions = row
        try:
            return {
                "created_at": created_at,
                "scope": json.loads(scope_json),
                "result": json.loads(summaries_json),
                "statistics_rollup": json.loads(statistics_json),
                "total_versions": int(total_versions),
            }
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            if self.logger:
                self.logger.warning(
                    "Failed to decode grouped vulnerability summary index entry: %s",
                    exc,
                )
            return None

    def save(
        self,
        cache_key: str,
        *,
        scope: dict[str, Any],
        summaries: list[dict[str, Any]],
        statistics_rollup: dict[str, Any],
        total_versions: int,
    ) -> None:
        created_at = datetime.now(timezone.utc).isoformat()
        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT OR REPLACE INTO grouped_vuln_summary_index (
                            cache_key,
                            created_at,
                            scope_json,
                            summaries_json,
                            statistics_json,
                            total_versions
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            cache_key,
                            created_at,
                            _stable_json(scope),
                            _stable_json(summaries),
                            _stable_json(statistics_rollup),
                            int(total_versions),
                        ),
                    )
                    self._prune(connection)
        except Exception as exc:
            if self.logger:
                self.logger.warning(
                    "Failed to save grouped vulnerability summary index: %s",
                    exc,
                )

    def _prune(self, connection: sqlite3.Connection) -> None:
        max_entries = max(1, int(self.max_entries_provider()))
        connection.execute(
            """
            DELETE FROM grouped_vuln_summary_index
            WHERE cache_key IN (
                SELECT cache_key
                FROM grouped_vuln_summary_index
                ORDER BY created_at DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (max_entries,),
        )
