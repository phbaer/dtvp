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
