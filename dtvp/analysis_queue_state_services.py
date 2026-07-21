import json
import os
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from .analysis_queue_runtime import AnalysisQueueItem
from .sqlite_migration_services import run_sqlite_migrations


ANALYSIS_QUEUE_MIGRATION_NAMESPACE = "analysis_queue"


def get_analysis_queue_state_path() -> str:
    configured_path = os.getenv("DTVP_ANALYSIS_QUEUE_STATE_PATH", "").strip()
    if configured_path:
        return configured_path
    return os.path.join(os.getcwd(), "data", "analysis_queue.sqlite")


def get_analysis_queue_migrations_path() -> Path:
    return Path(__file__).resolve().parent / "migrations" / "analysis_queue"


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class AnalysisQueueStateStore:
    """Persist an exact queue snapshot in a small SQLite database."""

    path_provider: Callable[[], str] = get_analysis_queue_state_path
    logger: Any = None
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False)

    def _connect(self) -> sqlite3.Connection:
        path = self.path_provider()
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        connection = sqlite3.connect(path, timeout=5)
        connection.execute("PRAGMA busy_timeout = 5000")
        run_sqlite_migrations(
            connection,
            namespace=ANALYSIS_QUEUE_MIGRATION_NAMESPACE,
            migrations_path=get_analysis_queue_migrations_path(),
            logger=self.logger,
        )
        try:
            os.chmod(path, 0o600)
        except OSError:
            if self.logger:
                self.logger.warning(
                    "Could not restrict analysis queue database permissions: %s",
                    path,
                )
        return connection

    def load(
        self,
    ) -> tuple[dict[str, AnalysisQueueItem], list[str]]:
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT queue_id, in_order, payload_json
                FROM analysis_queue_items
                ORDER BY sequence ASC
                """
            ).fetchall()

        items: dict[str, AnalysisQueueItem] = {}
        order: list[str] = []
        for queue_id, in_order, payload_json in rows:
            try:
                payload = json.loads(payload_json)
                item = AnalysisQueueItem.model_validate(payload)
                if item.queue_id != queue_id:
                    raise ValueError("queue ID does not match persisted key")
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                if self.logger:
                    self.logger.warning(
                        "Ignoring invalid persisted analysis queue item %s: %s",
                        queue_id,
                        exc,
                    )
                continue
            items[item.queue_id] = item
            if in_order:
                order.append(item.queue_id)
        return items, order

    def save(
        self,
        items: dict[str, AnalysisQueueItem],
        order: list[str],
    ) -> None:
        ordered_ids = [queue_id for queue_id in order if queue_id in items]
        ordered_set = set(ordered_ids)
        remaining_ids = sorted(queue_id for queue_id in items if queue_id not in ordered_set)
        rows = []
        updated_at = _utc_now_iso()
        for sequence, queue_id in enumerate(ordered_ids + remaining_ids):
            item = items[queue_id]
            rows.append(
                (
                    queue_id,
                    sequence,
                    1 if queue_id in ordered_set else 0,
                    item.model_dump_json(),
                    updated_at,
                )
            )

        with self._lock, closing(self._connect()) as connection:
            with connection:
                connection.execute("DELETE FROM analysis_queue_items")
                connection.executemany(
                    """
                    INSERT INTO analysis_queue_items (
                        queue_id,
                        sequence,
                        in_order,
                        payload_json,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    rows,
                )
