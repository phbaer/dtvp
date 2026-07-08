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


def test_compose_uses_dependency_track_internal_api_port():
    compose = (ROOT / "compose.yml").read_text()
    template = (ROOT / "nginx.conf.template").read_text()

    assert "DTVP_DT_API_URL: ${DTVP_DT_API_URL:-http://dtrack-apiserver:8080}" in compose
    assert "proxy_pass http://dtrack-apiserver:8080/api/;" in template
    assert "dtrack-apiserver:8081" not in compose
    assert "dtrack-apiserver:8081" not in template
