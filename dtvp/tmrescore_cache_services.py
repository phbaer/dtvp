import json
import os
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class TMRescoreCacheServiceDeps:
    logger: Any
    normalize_tmrescore_snapshot: Callable[[dict[str, Any]], dict[str, Any]]
    shared_cache: dict[str, dict[str, Any]]


def get_tmrescore_cache_path() -> str:
    configured_path = (
        os.getenv("DTVP_VSCORER_CACHE_PATH", "").strip()
        or os.getenv("DTVP_TMRESCORE_CACHE_PATH", "").strip()
    )
    if configured_path:
        return configured_path
    cache_dir = os.path.join(os.getcwd(), "data")
    vscorer_cache_path = os.path.join(cache_dir, "vscorer_proposals.json")
    legacy_cache_path = os.path.join(cache_dir, "tmrescore_proposals.json")
    if os.path.exists(legacy_cache_path) and not os.path.exists(vscorer_cache_path):
        return legacy_cache_path
    return vscorer_cache_path


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


def save_tmrescore_project_cache(cache: dict[str, dict[str, Any]]) -> None:
    cache_path = get_tmrescore_cache_path()
    cache_dir = os.path.dirname(cache_path)
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)

    temp_path = f"{cache_path}.tmp"
    with open(temp_path, "w", encoding="utf-8") as handle:
        json.dump(cache, handle, indent=2, sort_keys=True)
    os.replace(temp_path, cache_path)


def persist_tmrescore_project_snapshot(
    deps: TMRescoreCacheServiceDeps,
    project_name: str,
    snapshot: dict[str, Any],
) -> None:
    normalized_snapshot = deps.normalize_tmrescore_snapshot(snapshot)
    deps.shared_cache[project_name] = normalized_snapshot
    save_tmrescore_project_cache(deps.shared_cache)
