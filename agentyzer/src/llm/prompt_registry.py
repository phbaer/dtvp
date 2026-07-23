from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

import yaml

from src.configuration import AgentyzerRuntimeSettings

_REPO_ROOT = Path(__file__).resolve().parents[2]
_BUNDLED_CONFIG_DIR = _REPO_ROOT / "config"
_BUNDLED_PROMPTS_DIR = _BUNDLED_CONFIG_DIR / "prompts"

# Test hooks and optional runtime overrides.
_CONFIG_DIR: str | Path | None = AgentyzerRuntimeSettings.from_env().config_dir or None
_PROMPTS_DIR: str | Path | None = None

_REQUIRED_PROMPT_KEYS: Dict[str, tuple[str, ...]] = {
    "common": ("web_research_addendum", "research_continuation_instruction"),
    "code_reachability": ("system", "analysis_protocol", "response_contract"),
    "deep_analysis": ("system", "analysis_protocol", "response_contract"),
    "transitive_analysis": ("system", "analysis_protocol", "response_contract"),
    "verdict": (
        "system",
        "analysis_protocol",
        "response_contract",
        "reasoning_contract",
    ),
    "advisory_relevance": ("system", "instructions", "input_preamble"),
    "benchmark_comparison": ("system", "input_preamble"),
}

_PROMPT_KEY_ALIASES: Dict[str, Dict[str, str]] = {
    "code_reachability": {"analysis_protocol": "few_shot"},
    "deep_analysis": {"analysis_protocol": "few_shot"},
    "transitive_analysis": {"analysis_protocol": "few_shot"},
    "verdict": {"analysis_protocol": "few_shot"},
}


def _candidate_config_dirs() -> tuple[Path, ...]:
    candidates: list[Path] = []
    if _CONFIG_DIR:
        candidates.append(Path(_CONFIG_DIR))
    candidates.append(Path("config"))
    candidates.append(_BUNDLED_CONFIG_DIR)

    unique_candidates: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve(strict=False)
        if resolved in seen:
            continue
        seen.add(resolved)
        unique_candidates.append(resolved)
    return tuple(unique_candidates)


@lru_cache(maxsize=1)
def get_config_dir() -> Path:
    for candidate in _candidate_config_dirs():
        if candidate.exists():
            return candidate

    if _CONFIG_DIR:
        return Path(_CONFIG_DIR).resolve(strict=False)
    return _BUNDLED_CONFIG_DIR.resolve(strict=False)


def _override_prompts_dir() -> Path | None:
    if _PROMPTS_DIR is not None:
        return Path(_PROMPTS_DIR).resolve(strict=False)
    if _CONFIG_DIR is None:
        return None
    return (Path(_CONFIG_DIR).resolve(strict=False) / "prompts").resolve(
        strict=False
    )


def _default_prompts_dir() -> Path:
    return _BUNDLED_PROMPTS_DIR.resolve(strict=False)


def _prompt_bundle_path(name: str) -> Path:
    file_name = f"{name}.yaml"

    override_dir = _override_prompts_dir()
    if override_dir is not None:
        override_path = override_dir / file_name
        if override_path.exists():
            return override_path

    default_path = _default_prompts_dir() / file_name
    if default_path.exists():
        return default_path

    searched = []
    if override_dir is not None:
        searched.append(str(override_dir / file_name))
    searched.append(str(default_path))
    raise FileNotFoundError(f"Prompt bundle not found: {', '.join(searched)}")


def _validate_prompt_bundle(name: str, data: Dict[str, Any]) -> Dict[str, Any]:
    aliases = _PROMPT_KEY_ALIASES.get(name, {})
    for key, fallback_key in aliases.items():
        if isinstance(data.get(key), str) and data[key].strip():
            continue
        fallback_value = data.get(fallback_key)
        if isinstance(fallback_value, str) and fallback_value.strip():
            data[key] = fallback_value

    required_keys = _REQUIRED_PROMPT_KEYS.get(name, ())
    missing = [
        key
        for key in required_keys
        if not isinstance(data.get(key), str) or not data[key].strip()
    ]
    if missing:
        required = ", ".join(required_keys)
        missing_text = ", ".join(missing)
        raise ValueError(
            f"Prompt bundle '{name}' is missing required non-empty string keys: "
            f"{missing_text}. Required keys: {required}"
        )
    return data


@lru_cache(maxsize=None)
def load_prompt_bundle(name: str) -> Dict[str, Any]:
    """Load a prompt bundle from override prompts or bundled defaults."""
    path = _prompt_bundle_path(name)

    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    if not isinstance(data, dict):
        raise ValueError(f"Prompt bundle must be a mapping: {path}")
    return _validate_prompt_bundle(name, data)


@lru_cache(maxsize=None)
def get_prompt_value(bundle: str, key: str) -> str:
    """Return a single string value from a named prompt bundle."""
    data = load_prompt_bundle(bundle)
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Prompt key '{key}' missing or empty in bundle '{bundle}'")
    return value


def clear_prompt_cache() -> None:
    """Clear cached prompt bundles and values."""
    get_config_dir.cache_clear()
    load_prompt_bundle.cache_clear()
    get_prompt_value.cache_clear()


def validate_all_prompt_bundles() -> None:
    """Eagerly validate all known prompt bundles.

    This is intended for startup-time checks so prompt config problems fail
    before the first analysis request executes.
    """
    for bundle_name in sorted(_REQUIRED_PROMPT_KEYS):
        load_prompt_bundle(bundle_name)


def list_prompt_bundles(
    *,
    include_values: bool = False,
    system_only: bool = True,
) -> Dict[str, Any]:
    """Return prompt bundle metadata and, optionally, prompt text."""
    bundles = []
    for bundle_name in sorted(_REQUIRED_PROMPT_KEYS):
        data = load_prompt_bundle(bundle_name)
        required_keys = _REQUIRED_PROMPT_KEYS.get(bundle_name, ())
        keys = [
            key
            for key in sorted(data)
            if not system_only or key in {"system"}
        ]
        entry: Dict[str, Any] = {
            "bundle": bundle_name,
            "required_keys": list(required_keys),
            "keys": keys,
        }
        if include_values:
            entry["values"] = {
                key: data[key]
                for key in keys
                if isinstance(data.get(key), str)
            }
        bundles.append(entry)

    return {
        "schema_version": "agentyzer.prompts/v1",
        "config_dir": str(get_config_dir()),
        "system_only": system_only,
        "include_values": include_values,
        "bundles": bundles,
    }
