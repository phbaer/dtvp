"""Typed runtime configuration shared across Agentyzer subsystems."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping


Environment = Mapping[str, str]
TRUE_VALUES = frozenset({"1", "true", "yes", "on", "enabled"})


def _source(environment: Environment | None) -> Environment:
    return os.environ if environment is None else environment


def environment_text(
    environment: Environment,
    name: str,
    default: str = "",
    *,
    legacy_name: str | None = None,
) -> str:
    """Read a canonical setting, falling back to a deprecated alias."""
    value = environment.get(name)
    if value is None and legacy_name is not None:
        value = environment.get(legacy_name)
    return (default if value is None else value).strip()


def _text(environment: Environment, name: str, default: str = "") -> str:
    return environment_text(environment, name, default)


def _integer(
    environment: Environment,
    name: str,
    default: int,
    *,
    minimum: int,
) -> int:
    try:
        return max(minimum, int(environment.get(name, str(default))))
    except (TypeError, ValueError):
        return default


def _boolean(environment: Environment, name: str) -> bool:
    return _text(environment, name).casefold() in TRUE_VALUES


@dataclass(frozen=True, slots=True)
class AgentyzerRuntimeSettings:
    environment: str = "production"
    repos_dir: str = "repos"
    config_dir: str = ""
    log_level: str = "INFO"
    max_concurrent_jobs: int = 1
    worktree_retention_seconds: int = 86400
    instance_lock_path: str = ""
    allow_unauthenticated: bool = False
    allow_external_focus_path: bool = False

    @classmethod
    def from_env(
        cls,
        environment: Environment | None = None,
    ) -> "AgentyzerRuntimeSettings":
        source = _source(environment)
        return cls(
            environment=_text(
                source, "AGENTYZER_ENVIRONMENT", "production"
            ).lower(),
            repos_dir=_text(source, "AGENTYZER_REPOS_DIR", "repos"),
            config_dir=_text(source, "AGENTYZER_CONFIG_DIR"),
            log_level=environment_text(
                source,
                "AGENTYZER_LOG_LEVEL",
                "INFO",
                legacy_name="LOG_LEVEL",
            ).upper(),
            max_concurrent_jobs=_integer(
                source,
                "AGENTYZER_MAX_CONCURRENT_JOBS",
                1,
                minimum=1,
            ),
            worktree_retention_seconds=_integer(
                source,
                "AGENTYZER_WORKTREE_RETENTION_SECONDS",
                86400,
                minimum=300,
            ),
            instance_lock_path=_text(source, "AGENTYZER_INSTANCE_LOCK_PATH"),
            allow_unauthenticated=_boolean(
                source, "AGENTYZER_ALLOW_UNAUTHENTICATED"
            ),
            allow_external_focus_path=_boolean(
                source, "AGENTYZER_ALLOW_EXTERNAL_FOCUS_PATH"
            ),
        )


@dataclass(frozen=True, slots=True)
class JobStoreSettings:
    path: str = ""
    retention_seconds: int = 604800
    max_records: int = 1000
    minimum_free_bytes: int = 128 * 1024 * 1024

    @classmethod
    def from_env(cls, environment: Environment | None = None) -> "JobStoreSettings":
        source = _source(environment)
        return cls(
            path=_text(source, "AGENTYZER_JOB_STORE_PATH"),
            retention_seconds=_integer(
                source,
                "AGENTYZER_JOB_RETENTION_SECONDS",
                604800,
                minimum=0,
            ),
            max_records=_integer(
                source,
                "AGENTYZER_JOB_MAX_RECORDS",
                1000,
                minimum=1,
            ),
            minimum_free_bytes=_integer(
                source,
                "AGENTYZER_STORAGE_MIN_FREE_BYTES",
                128 * 1024 * 1024,
                minimum=0,
            ),
        )
