from src.configuration import AgentyzerRuntimeSettings, JobStoreSettings


def test_agentyzer_runtime_defaults_are_centralized():
    environment: dict[str, str] = {}

    assert AgentyzerRuntimeSettings.from_env(environment) == AgentyzerRuntimeSettings()
    assert JobStoreSettings.from_env(environment) == JobStoreSettings()


def test_agentyzer_runtime_settings_normalize_values():
    settings = AgentyzerRuntimeSettings.from_env(
        {
            "AGENTYZER_ENVIRONMENT": " TEST ",
            "AGENTYZER_REPOS_DIR": " /srv/repos ",
            "LOG_LEVEL": "debug",
            "AGENTYZER_MAX_CONCURRENT_JOBS": "0",
            "AGENTYZER_WORKTREE_RETENTION_SECONDS": "5",
            "AGENTYZER_ALLOW_UNAUTHENTICATED": "yes",
            "AGENTYZER_ALLOW_EXTERNAL_FOCUS_PATH": "on",
        }
    )

    assert settings.environment == "test"
    assert settings.repos_dir == "/srv/repos"
    assert settings.log_level == "DEBUG"
    assert settings.max_concurrent_jobs == 1
    assert settings.worktree_retention_seconds == 300
    assert settings.allow_unauthenticated is True
    assert settings.allow_external_focus_path is True


def test_agentyzer_invalid_storage_numbers_use_defaults():
    settings = JobStoreSettings.from_env(
        {
            "AGENTYZER_JOB_RETENTION_SECONDS": "invalid",
            "AGENTYZER_JOB_MAX_RECORDS": "-4",
            "AGENTYZER_STORAGE_MIN_FREE_BYTES": "invalid",
        }
    )

    assert settings.retention_seconds == 604800
    assert settings.max_records == 1
    assert settings.minimum_free_bytes == 128 * 1024 * 1024
