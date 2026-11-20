import json
import os
from dataclasses import dataclass
from typing import Any, Callable

from .file_io_services import atomic_write_bytes


@dataclass(frozen=True)
class TMRescoreCacheServiceDeps:
    logger: Any
    normalize_tmrescore_snapshot: Callable[[dict[str, Any]], dict[str, Any]]
    shared_cache: dict[str, dict[str, Any]]


def get_tmrescore_cache_path() -> str:
    configured_path = os.getenv("DTVP_TMRESCORE_CACHE_PATH", "").strip()
    if configured_path:
        return configured_path
    return os.path.join(os.getcwd(), "data", "tmrescore_proposals.json")


def load_tmrescore_project_cache(
    deps: TMRescoreCacheServiceDeps,
) -> dict[str, dict[str, Any]]:
    cache_path = get_tmrescore_cache_path()
    if not os.path.exists(cache_path):
        return {}

    try:
        with open(cache_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as exc:
        deps.logger.warning(
            "Failed to load tmrescore cache from %s: %s", cache_path, exc
        )
        return {}

    if not isinstance(payload, dict):
        return {}

    return {
        project_name: deps.normalize_tmrescore_snapshot(snapshot)
        for project_name, snapshot in payload.items()
        if isinstance(snapshot, dict)
    }


def serialize_tmrescore_cache(cache: dict[str, dict[str, Any]]) -> bytes:
    """The stored form of the proposals file; a restore writes it the same way."""
    return json.dumps(cache, indent=2, sort_keys=True).encode("utf-8")


def save_tmrescore_project_cache(cache: dict[str, dict[str, Any]]) -> None:
    atomic_write_bytes(get_tmrescore_cache_path(), serialize_tmrescore_cache(cache))


def persist_tmrescore_project_snapshot(
    deps: TMRescoreCacheServiceDeps,
    project_name: str,
    snapshot: dict[str, Any],
) -> None:
    normalized_snapshot = deps.normalize_tmrescore_snapshot(snapshot)
    deps.shared_cache[project_name] = normalized_snapshot
    save_tmrescore_project_cache(deps.shared_cache)
