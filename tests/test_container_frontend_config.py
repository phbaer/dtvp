from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_docker_image_keeps_frontend_index_template():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert (
        "RUN cp ./frontend/dist/index.html ./frontend/dist/index.html.template"
        in dockerfile
    )


def test_start_script_renders_frontend_from_template():
    start_script = (ROOT / "start.sh").read_text(encoding="utf-8")

    assert 'INDEX_TEMPLATE="/app/frontend/dist/index.html.template"' in start_script
    assert '"${INDEX_TEMPLATE}" > "${INDEX_TARGET}.tmp"' in start_script
    assert 's|\\${DTVP_DEV_DISABLE_AUTH}|${DTVP_DEV_DISABLE_AUTH}|g' in start_script
    assert "Rendering index.html in place is not restart-safe" in start_script
