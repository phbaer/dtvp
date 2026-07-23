from dtvp.configuration import (
    AutoAnalysisRuntimeSettings,
    CodeAnalysisStoreSettings,
    DurableStorageSettings,
    ProjectArchiveSettings,
    RateLimitSettings,
    TaskRuntimeSettings,
    UiRuntimeSettings,
)


def test_runtime_configuration_defaults_are_owned_centrally():
    environment: dict[str, str] = {}

    assert RateLimitSettings.from_env(environment) == RateLimitSettings()
    assert AutoAnalysisRuntimeSettings.from_env(environment) == AutoAnalysisRuntimeSettings()
    assert ProjectArchiveSettings.from_env(environment) == ProjectArchiveSettings()
    assert CodeAnalysisStoreSettings.from_env(environment) == CodeAnalysisStoreSettings()
    assert DurableStorageSettings.from_env(environment) == DurableStorageSettings()
    assert TaskRuntimeSettings.from_env(environment) == TaskRuntimeSettings()
    assert UiRuntimeSettings.from_env(environment) == UiRuntimeSettings()


def test_invalid_numbers_fall_back_and_valid_numbers_respect_floors():
    rate_limits = RateLimitSettings.from_env(
        {
            "DTVP_RATE_LIMIT_WINDOW_SECONDS": "invalid",
            "DTVP_AUTH_RATE_LIMIT": "0",
            "DTVP_EXPENSIVE_RATE_LIMIT": "-3",
            "DTVP_MUTATION_RATE_LIMIT": "42",
        }
    )
    tasks = TaskRuntimeSettings.from_env(
        {
            "DTVP_GROUPED_VULN_TASK_TTL_SECONDS": "5",
            "DTVP_TMRESCORE_TASK_TTL_SECONDS": "invalid",
            "DTVP_ANALYSIS_QUEUE_CAPACITY": "0",
        }
    )

    assert rate_limits == RateLimitSettings(
        window_seconds=60,
        authentication=1,
        expensive=1,
        mutation=42,
    )
    assert tasks.grouped_vuln_ttl_seconds == 60
    assert tasks.tmrescore_ttl_seconds == 3600
    assert tasks.analysis_queue_capacity == 1


def test_boolean_csv_and_path_settings_are_normalized():
    archive = ProjectArchiveSettings.from_env(
        {
            "DTVP_PROJECT_ARCHIVE_EXPANDED_ENABLED": "YES",
            "DTVP_PROJECT_ARCHIVE_SNAPSHOT_ENABLED": "not-a-boolean",
            "DTVP_PROJECT_ARCHIVE_INCLUDE": " Alpha, ,Beta ",
        }
    )
    store = CodeAnalysisStoreSettings.from_env(
        {
            "DTVP_CODE_ANALYSIS_RESULTS_STORE_GUIDANCE": "off",
            "DTVP_CODE_ANALYSIS_RESULTS_PATH": "  /tmp/results.sqlite  ",
        }
    )

    assert archive.expanded_enabled is True
    assert archive.snapshot_enabled is False
    assert archive.include_names == ("Alpha", "Beta")
    assert store.store_guidance is False
    assert store.results_path == "/tmp/results.sqlite"
