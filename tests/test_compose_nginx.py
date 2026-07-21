from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_compose_nginx_uses_configured_dtvp_context_path():
    compose = (ROOT / "compose.yml").read_text()
    template = (ROOT / "nginx.conf.template").read_text()

    assert "DTVP_CONTEXT_PATH: ${DTVP_CONTEXT_PATH:-/dtvp}" in compose
    assert '"${DTVP_HTTP_PORT:-80}:80"' in compose
    assert "./nginx.conf:" not in compose
    assert "./nginx.conf.template:/etc/nginx/templates/default.conf.template:ro" in compose
    assert "location ${DTVP_CONTEXT_PATH}/" in template
    assert "location /dtvp/" not in template
    assert "client_max_body_size 105m;" in template


def test_compose_uses_dependency_track_internal_api_port():
    compose = (ROOT / "compose.yml").read_text()
    template = (ROOT / "nginx.conf.template").read_text()

    assert "DTVP_DT_API_URL: ${DTVP_DT_API_URL:-http://dtrack-apiserver:8080}" in compose
    assert "proxy_pass http://dtrack-apiserver:8080/api/;" in template
    assert "dtrack-apiserver:8081" not in compose
    assert "dtrack-apiserver:8081" not in template


def test_compose_hardens_application_containers():
    compose = (ROOT / "compose.yml").read_text()

    assert 'user: "${DTVP_RUNTIME_UID:-1000}:${DTVP_RUNTIME_GID:-1000}"' in compose
    assert compose.count("read_only: true") >= 7
    assert compose.count("no-new-privileges:true") >= 7
    assert compose.count("cap_drop:") >= 7
    assert compose.count("pids_limit:") >= 7
    assert "env_file:" not in compose
    assert "ALPINE_DATABASE_PASSWORD=dtrack" not in compose
    assert "POSTGRES_PASSWORD=dtrack" not in compose
    assert "DTRACK_DB_PASSWORD:?Set DTRACK_DB_PASSWORD" in compose
    assert 'condition: service_healthy' in compose
    assert 'context + "/readyz"' in compose
    assert 'connection.request("GET", "/readyz"' in compose


def test_compose_pins_images_and_segments_trust_zones():
    compose = (ROOT / "compose.yml").read_text()

    assert compose.count("@sha256:") >= 5
    assert (
        "dependencytrack/apiserver:4.14.2@sha256:"
        "1ba4f004e1ec4800ec0e0175b0f1cf361a68f6ac3db9274a32d0a47cd4038f51"
    ) in compose
    assert (
        "dependencytrack/frontend:4.14.2@sha256:"
        "00560b57a6cfdec3c02a6e02be80fce97029241a9c653e8b83c0b670dff1f3ca"
    ) in compose
    assert "internal: true" in compose
    for network in (
        "application",
        "analysis",
        "data",
        "dtvp-outbound",
        "dtrack-outbound",
        "agentyzer-outbound",
        "archive-outbound",
    ):
        assert f"{network}:" in compose


def test_compose_secret_overlays_keep_credentials_out_of_service_environment():
    overlay = (ROOT / "compose.secrets.yml").read_text()
    import_overlay = (ROOT / "compose.archive-import-secret.yml").read_text()

    assert "POSTGRES_PASSWORD_FILE: /run/secrets/dtrack_database_password" in overlay
    assert "ALPINE_DATABASE_PASSWORD_FILE: /run/secrets/dtrack_database_password" in overlay
    assert "exec java" not in overlay
    assert "DTVP_DT_API_KEY_FILE: /run/secrets/dtvp_dt_api_key" in overlay
    assert "DTVP_SESSION_SECRET_KEY_FILE: /run/secrets/dtvp_session_secret_key" in overlay
    assert "AGENTYZER_SERVICE_TOKEN_FILE: /run/secrets/agentyzer_service_token" in overlay
    assert "environment: DTRACK_DB_PASSWORD" in overlay
    assert "environment: DTVP_DT_IMPORT_API_KEY" in import_overlay


def test_agentyzer_and_archive_credentials_are_not_exposed_by_default():
    compose = (ROOT / "compose.yml").read_text()
    debug_overlay = (ROOT / "compose.agentyzer-debug.yml").read_text()

    assert '"127.0.0.1:${AGENTYZER_PORT:-8095}:8000"' not in compose
    assert '"127.0.0.1:${AGENTYZER_PORT:-8095}:8000"' in debug_overlay
    assert "./secrets:/ssh:ro" not in compose
    assert "source: archive_git_ssh_key" in compose
    assert "source: archive_git_known_hosts" in compose
    assert 'git check-ref-format "refs/heads/$${DTVP_ARCHIVE_GIT_BRANCH}"' in compose


def test_archive_helper_fails_closed_on_remote_errors():
    compose = (ROOT / "compose.yml").read_text()

    assert "git fetch origin" not in compose or "git fetch --prune origin" in compose
    assert "git pull --ff-only" not in compose
    assert "|| true" not in compose
    assert "Archive Git remote differs" in compose


def test_private_ca_overlay_uses_build_secrets():
    overlay = (ROOT / "compose.ca-certs.yml").read_text()

    assert overlay.count("- ca-certs") == 2
    assert "file: ${DTVP_CA_CERTS_FILE}" in overlay
