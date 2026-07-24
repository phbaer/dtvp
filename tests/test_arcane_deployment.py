from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
ARCANE_ROOT = ROOT / "deploy" / "arcane"


def _compose() -> dict:
    return yaml.safe_load((ARCANE_ROOT / "compose.yml").read_text(encoding="utf-8"))


def _env_names(name: str) -> set[str]:
    names = set()
    for line in (ARCANE_ROOT / name).read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            names.add(stripped.split("=", 1)[0])
    return names


def test_arcane_project_is_image_only_and_backend_neutral():
    compose = _compose()
    services = compose["services"]

    assert set(services) == {"dtvp", "agentyzer"}
    assert all("build" not in service for service in services.values())
    assert services["dtvp"]["image"].startswith("${DTVP_IMAGE")
    assert services["agentyzer"]["image"].startswith("${AGENTYZER_IMAGE")

    source = (ARCANE_ROOT / "compose.yml").read_text(encoding="utf-8").lower()
    assert "dependency-track" not in source
    assert "postgres" not in source
    assert "/var/run/docker.sock" not in source


def test_arcane_project_separates_durable_and_disposable_state():
    compose = _compose()
    services = compose["services"]

    assert services["dtvp"]["volumes"] == ["dtvp-data:/app/data"]
    assert "agentyzer-repos:/app/repos" in services["agentyzer"]["volumes"]
    assert set(compose["volumes"]) == {"dtvp-data", "agentyzer-repos"}

    readme = (ARCANE_ROOT / "README.md").read_text(encoding="utf-8")
    assert "`dtvp-data` is durable" in readme
    assert "`agentyzer-repos`" in readme
    assert "disposable" in readme
    assert "Do not back up `agentyzer-repos`" in readme


def test_arcane_project_separates_service_environment_and_secret_files():
    compose = _compose()
    dtvp = compose["services"]["dtvp"]
    agentyzer = compose["services"]["agentyzer"]

    assert dtvp["env_file"] == ["./dtvp.env"]
    assert agentyzer["env_file"] == ["./agentyzer.env"]
    assert set(dtvp["environment"]) == {
        "DTVP_VULNERABILITY_BACKEND_API_KEY",
        "DTVP_VULNERABILITY_BACKEND_API_KEY_FILE",
        "DTVP_VULNERABILITY_BACKEND_IMPORT_API_KEY",
        "DTVP_VULNERABILITY_BACKEND_IMPORT_API_KEY_FILE",
        "DTVP_SESSION_SECRET_KEY",
        "DTVP_SESSION_SECRET_KEY_FILE",
        "DTVP_SESSION_PREVIOUS_SECRET_KEY",
        "DTVP_SESSION_PREVIOUS_SECRET_KEY_FILE",
        "DTVP_OIDC_CLIENT_SECRET",
        "DTVP_OIDC_CLIENT_SECRET_FILE",
        "DTVP_CODE_ANALYSIS_SERVICE_TOKEN",
        "DTVP_CODE_ANALYSIS_SERVICE_TOKEN_FILE",
        "DTVP_CODE_ANALYSIS_ADMIN_TOKEN",
        "DTVP_CODE_ANALYSIS_ADMIN_TOKEN_FILE",
    }
    assert set(agentyzer["environment"]) == {
        "AGENTYZER_SERVICE_TOKEN",
        "AGENTYZER_SERVICE_TOKEN_FILE",
        "AGENTYZER_ADMIN_TOKEN",
        "AGENTYZER_ADMIN_TOKEN_FILE",
        "AGENTYZER_OPENWEBUI_API_KEY",
        "AGENTYZER_OPENWEBUI_API_KEY_FILE",
    }
    assert dtvp["environment"]["DTVP_VULNERABILITY_BACKEND_API_KEY"] == ""
    assert (
        dtvp["environment"]["DTVP_VULNERABILITY_BACKEND_API_KEY_FILE"]
        == "/run/secrets/dtvp_vulnerability_backend_api_key"
    )
    assert "DTVP_BACKUP_MAX_AGE_SECONDS" in _env_names("dtvp.env")
    assert {
        "dtvp_vulnerability_backend_api_key",
        "dtvp_session_secret_key",
        "dtvp_session_previous_secret_key",
        "dtvp_oidc_client_secret",
        "agentyzer_service_token",
        "agentyzer_admin_token",
    }.issubset(set(dtvp["secrets"]))

    for definition in compose["secrets"].values():
        assert set(definition) == {"environment"}


def test_arcane_service_env_files_are_non_secret_and_prefixed():
    dtvp_names = _env_names("dtvp.env")
    agentyzer_names = _env_names("agentyzer.env")

    assert dtvp_names
    assert all(name.startswith("DTVP_") for name in dtvp_names)
    assert all(name.startswith("AGENTYZER_") for name in agentyzer_names)
    assert not any(
        marker in name
        for name in dtvp_names | agentyzer_names
        for marker in ("SECRET", "API_KEY", "SERVICE_TOKEN", "ADMIN_TOKEN")
    )


def test_arcane_project_contains_manual_and_git_managed_inputs():
    assert (ARCANE_ROOT / ".env.dist").is_file()
    assert (ARCANE_ROOT / "dtvp.env").is_file()
    assert (ARCANE_ROOT / "agentyzer.env").is_file()
    assert yaml.safe_load((ARCANE_ROOT / "repos.yaml").read_text(encoding="utf-8")) == {
        "components": {}
    }

    readme = (ARCANE_ROOT / "README.md").read_text(encoding="utf-8")
    assert "## Manual Arcane project" in readme
    assert "## Git-managed Arcane project" in readme
    assert "deploy/arcane/compose.yml" in readme


def test_packaged_compose_uses_canonical_agentyzer_environment_names():
    compose = yaml.safe_load((ROOT / "compose.yml").read_text(encoding="utf-8"))
    environment = compose["services"]["agentyzer"]["environment"]

    assert "AGENTYZER_LLM_BACKEND" in environment
    assert "AGENTYZER_OLLAMA_HOST" in environment
    assert "AGENTYZER_OPENWEBUI_HOST" in environment
    assert "AGENTYZER_LOG_LEVEL" in environment
    assert not {
        "LLM_BACKEND",
        "OLLAMA_HOST",
        "OLLAMA_MODEL",
        "OPENWEBUI_HOST",
        "OPENWEBUI_MODEL",
        "OPENWEBUI_API_KEY",
        "LOG_LEVEL",
    } & set(environment)
