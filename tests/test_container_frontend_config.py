from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_docker_image_keeps_frontend_shell_immutable():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "COPY --from=frontend-build /app/frontend/dist ./frontend/dist" in dockerfile
    assert "index.html.template" not in dockerfile


def test_runtime_config_is_not_interpolated_by_the_shell():
    start_script = (ROOT / "start.sh").read_text(encoding="utf-8")
    index_html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")

    assert "INDEX_TEMPLATE" not in start_script
    assert "${DTVP_FRONTEND_URL}" not in start_script
    assert 'exec /app/.venv/bin/uvicorn dtvp.boot:app' in start_script
    assert '<script src="/runtime-config.js"></script>' in index_html
    assert "window.__env__ =" not in index_html


def test_application_images_run_as_non_root_users():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    agentyzer_dockerfile = (ROOT / "agentyzer" / "Dockerfile").read_text(
        encoding="utf-8"
    )

    assert "USER 10001:10001" in dockerfile
    assert "USER 10001:10001" in agentyzer_dockerfile
    assert "ghcr.io/astral-sh/uv:latest" not in dockerfile
    assert "FROM node:24-alpine@sha256:" in dockerfile
    assert dockerfile.count("@sha256:") >= 3
    assert 'CMD ["/app/.venv/bin/uvicorn"' in agentyzer_dockerfile
    assert "type=secret,id=ca-certs" in dockerfile
    assert "type=secret,id=ca-certs" in agentyzer_dockerfile


def test_docker_contexts_exclude_runtime_secrets_and_repository_metadata():
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    agentyzer_dockerignore = (ROOT / "agentyzer" / ".dockerignore").read_text(
        encoding="utf-8"
    )
    agentyzer_dockerfile = (ROOT / "agentyzer" / "Dockerfile").read_text(
        encoding="utf-8"
    )

    assert dockerignore.startswith("**\n")
    assert "frontend/**\n" in dockerignore
    assert "data/**\n" in dockerignore
    assert "sbom/**\n" in dockerignore
    assert "!.env" not in dockerignore
    assert "!.git" not in dockerignore
    assert agentyzer_dockerignore.startswith("**\n")
    assert "config/**\n" in agentyzer_dockerignore
    assert "!config/repos.yaml" not in agentyzer_dockerignore
    assert "COPY config/repos.container.yaml ./config/repos.yaml" in agentyzer_dockerfile
