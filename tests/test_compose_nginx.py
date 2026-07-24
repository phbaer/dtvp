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


def test_default_compose_is_backend_neutral_and_demo_owns_dependency_track():
    compose = (ROOT / "compose.yml").read_text()
    template = (ROOT / "nginx.conf.template").read_text()
    demo_compose = (ROOT / "demo" / "dependency-track" / "compose.yml").read_text()
    demo_template = (
        ROOT / "demo" / "dependency-track" / "nginx.conf.template"
    ).read_text()

    assert "DTVP_VULNERABILITY_BACKEND_API_URL:" in compose
    assert "DTVP_DT_" not in compose
    assert "dependency-track" not in compose.lower()
    assert "dependency-track" not in template.lower()
    assert "demo-dependency-track-api:" in demo_compose
    assert "demo-dependency-track-frontend:" in demo_compose
    assert "demo-dependency-track-database:" in demo_compose
    assert "DTVP_VULNERABILITY_BACKEND_TYPE: dependency-track" in demo_compose
    assert (
        "proxy_pass http://demo-dependency-track-api:8080/api/;"
        in demo_template
    )


def test_compose_hardens_application_containers():
    compose = (ROOT / "compose.yml").read_text()

    assert 'user: "${DTVP_RUNTIME_UID:-1000}:${DTVP_RUNTIME_GID:-1000}"' in compose
    assert compose.count("read_only: true") >= 6
    assert compose.count("no-new-privileges:true") >= 6
    assert compose.count("cap_drop:") >= 6
    assert compose.count("pids_limit:") >= 6
    assert "env_file:" not in compose
    assert 'condition: service_healthy' in compose
    assert 'context + "/readyz"' in compose
    assert 'connection.request("GET", "/readyz"' in compose


def test_compose_pins_images_and_segments_trust_zones():
    compose = (ROOT / "compose.yml").read_text()
    demo = (ROOT / "demo" / "dependency-track" / "compose.yml").read_text()

    assert compose.count("@sha256:") >= 3
    assert "dependencytrack/" not in compose
    assert "postgres:" not in compose
    assert (
        "dependencytrack/apiserver:4.14.2@sha256:"
        "1ba4f004e1ec4800ec0e0175b0f1cf361a68f6ac3db9274a32d0a47cd4038f51"
    ) in demo
    assert (
        "dependencytrack/frontend:4.14.2@sha256:"
        "00560b57a6cfdec3c02a6e02be80fce97029241a9c653e8b83c0b670dff1f3ca"
    ) in demo
    assert "internal: true" in compose
    for network in (
        "application",
        "analysis",
        "dtvp-outbound",
        "agentyzer-outbound",
        "archive-outbound",
    ):
        assert f"{network}:" in compose


def test_compose_secret_overlays_keep_credentials_out_of_service_environment():
    overlay = (ROOT / "compose.secrets.yml").read_text()
    demo_overlay = (
        ROOT / "demo" / "dependency-track" / "compose.secrets.yml"
    ).read_text()
    import_overlay = (ROOT / "compose.archive-import-secret.yml").read_text()
    rotation_overlay = (ROOT / "compose.agentyzer-token-rotation.yml").read_text()
    session_rotation_overlay = (ROOT / "compose.session-key-rotation.yml").read_text()

    assert "exec java" not in overlay
    assert (
        "DTVP_VULNERABILITY_BACKEND_API_KEY_FILE: "
        "/run/secrets/dtvp_vulnerability_backend_api_key"
    ) in overlay
    assert "DTVP_SESSION_SECRET_KEY_FILE: /run/secrets/dtvp_session_secret_key" in overlay
    assert "AGENTYZER_SERVICE_TOKEN_FILE: /run/secrets/agentyzer_service_token" in overlay
    assert "DTVP_BACKUP_DATABASE_PASSWORD" not in overlay
    assert "dependency_track_database_password" not in overlay
    assert "environment: DTVP_VULNERABILITY_BACKEND_IMPORT_API_KEY" in import_overlay
    assert "environment: DTVP_DEMO_DEPENDENCY_TRACK_DATABASE_PASSWORD" in demo_overlay
    assert "AGENTYZER_SERVICE_TOKEN_PREVIOUS_FILE: \"\"" in overlay
    assert "AGENTYZER_ADMIN_TOKEN_PREVIOUS_FILE: \"\"" in overlay
    assert (
        "AGENTYZER_SERVICE_TOKEN_PREVIOUS_FILE: "
        "/run/secrets/agentyzer_service_token_previous"
    ) in rotation_overlay
    assert "environment: AGENTYZER_ADMIN_TOKEN_PREVIOUS" in rotation_overlay
    assert "DTVP_SESSION_PREVIOUS_SECRET_KEY_FILE: \"\"" in overlay
    assert (
        "DTVP_SESSION_PREVIOUS_SECRET_KEY_FILE: "
        "/run/secrets/dtvp_session_previous_secret_key"
    ) in session_rotation_overlay


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

    assert overlay.count("- ca-certs") == 3
    assert "file: ${DTVP_CA_CERTS_FILE}" in overlay
