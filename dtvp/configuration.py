"""Typed ownership of DTVP runtime configuration and defaults.

Integration-specific credentials remain in their existing Pydantic settings
classes. This module owns cross-cutting runtime, storage, and UI settings so
callers do not repeat parsing rules or silently diverge on defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping


Environment = Mapping[str, str]
TRUE_VALUES = frozenset({"1", "true", "yes", "on", "enabled"})
FALSE_VALUES = frozenset({"0", "false", "no", "off", "disabled"})


def _source(environment: Environment | None) -> Environment:
    return os.environ if environment is None else environment


def _text(
    environment: Environment,
    name: str,
    default: str = "",
    *,
    strip: bool = True,
) -> str:
    value = environment.get(name, default)
    return value.strip() if strip else value


def _integer(
    environment: Environment,
    name: str,
    default: int,
    *,
    minimum: int = 0,
) -> int:
    try:
        return max(minimum, int(environment.get(name, str(default))))
    except (TypeError, ValueError):
        return default


def _boolean(environment: Environment, name: str, default: bool = False) -> bool:
    raw = _text(environment, name, "true" if default else "false").lower()
    if raw in TRUE_VALUES:
        return True
    if raw in FALSE_VALUES:
        return False
    return default


def _csv(environment: Environment, name: str) -> tuple[str, ...]:
    return tuple(
        item.strip()
        for item in environment.get(name, "").split(",")
        if item.strip()
    )


@dataclass(frozen=True, slots=True)
class RateLimitSettings:
    window_seconds: int = 60
    authentication: int = 30
    expensive: int = 20
    mutation: int = 120

    @classmethod
    def from_env(cls, environment: Environment | None = None) -> "RateLimitSettings":
        source = _source(environment)
        return cls(
            window_seconds=_integer(
                source, "DTVP_RATE_LIMIT_WINDOW_SECONDS", 60, minimum=1
            ),
            authentication=_integer(
                source, "DTVP_AUTH_RATE_LIMIT", 30, minimum=1
            ),
            expensive=_integer(
                source, "DTVP_EXPENSIVE_RATE_LIMIT", 20, minimum=1
            ),
            mutation=_integer(
                source, "DTVP_MUTATION_RATE_LIMIT", 120, minimum=1
            ),
        )


@dataclass(frozen=True, slots=True)
class AutoAnalysisRuntimeSettings:
    sweep_seconds: int = 900

    @classmethod
    def from_env(
        cls,
        environment: Environment | None = None,
    ) -> "AutoAnalysisRuntimeSettings":
        source = _source(environment)
        return cls(
            sweep_seconds=_integer(
                source,
                "DTVP_AUTO_CODE_ANALYSIS_SWEEP_SECONDS",
                900,
                minimum=60,
            )
        )


@dataclass(frozen=True, slots=True)
class ProjectArchiveSettings:
    path: str = "data/project_archives"
    expanded_enabled: bool = False
    expanded_path: str = "data/project_archives_git"
    snapshot_enabled: bool = False
    interval_seconds: int = 86400
    retention_count: int = 30
    include_names: tuple[str, ...] = ()
    max_files: int = 10_000
    max_member_bytes: int = 100 * 1024 * 1024
    max_uncompressed_bytes: int = 500 * 1024 * 1024
    max_compression_ratio: int = 200

    @classmethod
    def from_env(
        cls,
        environment: Environment | None = None,
    ) -> "ProjectArchiveSettings":
        source = _source(environment)
        return cls(
            path=_text(source, "DTVP_PROJECT_ARCHIVE_PATH", "data/project_archives"),
            expanded_enabled=_boolean(
                source, "DTVP_PROJECT_ARCHIVE_EXPANDED_ENABLED"
            ),
            expanded_path=_text(
                source,
                "DTVP_PROJECT_ARCHIVE_EXPANDED_PATH",
                "data/project_archives_git",
            ),
            snapshot_enabled=_boolean(
                source, "DTVP_PROJECT_ARCHIVE_SNAPSHOT_ENABLED"
            ),
            interval_seconds=_integer(
                source,
                "DTVP_PROJECT_ARCHIVE_INTERVAL_SECONDS",
                86400,
                minimum=60,
            ),
            retention_count=_integer(
                source,
                "DTVP_PROJECT_ARCHIVE_RETENTION_COUNT",
                30,
                minimum=1,
            ),
            include_names=_csv(source, "DTVP_PROJECT_ARCHIVE_INCLUDE"),
            max_files=_integer(
                source,
                "DTVP_PROJECT_ARCHIVE_MAX_FILES",
                10_000,
                minimum=1,
            ),
            max_member_bytes=_integer(
                source,
                "DTVP_PROJECT_ARCHIVE_MAX_MEMBER_BYTES",
                100 * 1024 * 1024,
                minimum=1,
            ),
            max_uncompressed_bytes=_integer(
                source,
                "DTVP_PROJECT_ARCHIVE_MAX_UNCOMPRESSED_BYTES",
                500 * 1024 * 1024,
                minimum=1,
            ),
            max_compression_ratio=_integer(
                source,
                "DTVP_PROJECT_ARCHIVE_MAX_COMPRESSION_RATIO",
                200,
                minimum=1,
            ),
        )


@dataclass(frozen=True, slots=True)
class CodeAnalysisStoreSettings:
    results_path: str = ""
    max_records: int = 2000
    retention_days: int = 0
    store_guidance: bool = True
    freshness_days: int = 0
    queue_state_path: str = ""

    @classmethod
    def from_env(
        cls,
        environment: Environment | None = None,
    ) -> "CodeAnalysisStoreSettings":
        source = _source(environment)
        return cls(
            results_path=_text(source, "DTVP_CODE_ANALYSIS_RESULTS_PATH"),
            max_records=_integer(
                source,
                "DTVP_CODE_ANALYSIS_RESULTS_MAX_RECORDS",
                2000,
                minimum=1,
            ),
            retention_days=_integer(
                source,
                "DTVP_CODE_ANALYSIS_RESULTS_RETENTION_DAYS",
                0,
                minimum=0,
            ),
            store_guidance=_boolean(
                source,
                "DTVP_CODE_ANALYSIS_RESULTS_STORE_GUIDANCE",
                default=True,
            ),
            freshness_days=_integer(
                source,
                "DTVP_CODE_ANALYSIS_RESULT_FRESHNESS_DAYS",
                0,
                minimum=0,
            ),
            queue_state_path=_text(source, "DTVP_ANALYSIS_QUEUE_STATE_PATH"),
        )


@dataclass(frozen=True, slots=True)
class DurableStorageSettings:
    backup_status_path: str = "data/backup_status.json"
    backup_max_age_seconds: int = 0
    minimum_free_bytes: int = 128 * 1024 * 1024
    dt_cache_path: str = "data/backend_cache"
    dt_cache_refresh_seconds: int = 60
    grouped_summary_index_path: str = ""
    grouped_summary_index_max_entries: int = 64
    tmrescore_cache_path: str = ""
    team_mapping_path: str = "data/team_mapping.json"
    user_roles_path: str = "data/user_roles.json"
    rescore_rules_path: str = "data/rescore_rules.json"
    auto_analysis_guidance_path: str = "data/auto_analysis_guidance.json"

    @classmethod
    def from_env(
        cls,
        environment: Environment | None = None,
    ) -> "DurableStorageSettings":
        source = _source(environment)
        return cls(
            backup_status_path=_text(
                source, "DTVP_BACKUP_STATUS_PATH", "data/backup_status.json"
            ),
            backup_max_age_seconds=_integer(
                source, "DTVP_BACKUP_MAX_AGE_SECONDS", 0, minimum=0
            ),
            minimum_free_bytes=_integer(
                source,
                "DTVP_STORAGE_MIN_FREE_BYTES",
                128 * 1024 * 1024,
                minimum=0,
            ),
            dt_cache_path=_text(
                source,
                "DTVP_VULNERABILITY_BACKEND_CACHE_PATH",
                _text(source, "DTVP_DT_CACHE_PATH", "data/backend_cache"),
            ),
            dt_cache_refresh_seconds=_integer(
                source,
                "DTVP_VULNERABILITY_BACKEND_CACHE_REFRESH_SECONDS",
                _integer(
                    source,
                    "DTVP_DT_CACHE_REFRESH_SECONDS",
                    60,
                    minimum=1,
                ),
                minimum=1,
            ),
            grouped_summary_index_path=_text(
                source, "DTVP_GROUPED_VULN_SUMMARY_INDEX_PATH"
            ),
            grouped_summary_index_max_entries=_integer(
                source,
                "DTVP_GROUPED_VULN_SUMMARY_INDEX_MAX_ENTRIES",
                64,
                minimum=1,
            ),
            tmrescore_cache_path=_text(source, "DTVP_TMRESCORE_CACHE_PATH"),
            team_mapping_path=_text(
                source, "TEAM_MAPPING_PATH", "data/team_mapping.json"
            ),
            user_roles_path=_text(
                source, "USER_ROLES_PATH", "data/user_roles.json"
            ),
            rescore_rules_path=_text(
                source, "RESCORE_RULES_PATH", "data/rescore_rules.json"
            ),
            auto_analysis_guidance_path=_text(
                source,
                "DTVP_AUTO_ANALYSIS_GUIDANCE_PATH",
                "data/auto_analysis_guidance.json",
            ),
        )


@dataclass(frozen=True, slots=True)
class UiRuntimeSettings:
    default_project_filter: str = ""
    attribution_age_filter_days: str = "7d,14d,28d"
    jira_create_url: str = ""

    @classmethod
    def from_env(cls, environment: Environment | None = None) -> "UiRuntimeSettings":
        source = _source(environment)
        return cls(
            default_project_filter=_text(source, "DTVP_DEFAULT_PROJECT_FILTER"),
            attribution_age_filter_days=_text(
                source,
                "DTVP_ATTRIBUTION_AGE_FILTER_DAYS",
                "7d,14d,28d",
            ),
            jira_create_url=_text(source, "DTVP_JIRA_CREATE_URL"),
        )


@dataclass(frozen=True, slots=True)
class TaskRuntimeSettings:
    grouped_vuln_ttl_seconds: int = 3600
    tmrescore_ttl_seconds: int = 3600
    analysis_queue_ttl_seconds: int = 3600
    analysis_queue_capacity: int = 1

    @classmethod
    def from_env(cls, environment: Environment | None = None) -> "TaskRuntimeSettings":
        source = _source(environment)
        return cls(
            grouped_vuln_ttl_seconds=_integer(
                source,
                "DTVP_GROUPED_VULN_TASK_TTL_SECONDS",
                3600,
                minimum=60,
            ),
            tmrescore_ttl_seconds=_integer(
                source,
                "DTVP_TMRESCORE_TASK_TTL_SECONDS",
                3600,
                minimum=60,
            ),
            analysis_queue_ttl_seconds=_integer(
                source,
                "DTVP_ANALYSIS_QUEUE_TTL_SECONDS",
                3600,
                minimum=60,
            ),
            analysis_queue_capacity=_integer(
                source,
                "DTVP_ANALYSIS_QUEUE_CAPACITY",
                1,
                minimum=1,
            ),
        )
