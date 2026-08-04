from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_compose_defaults_to_fail_closed_free_threaded_image():
    compose = (ROOT / "compose.yml").read_text(encoding="utf-8")

    assert "dockerfile: Dockerfile.free-threaded" in compose
    assert 'DTVP_REQUIRE_FREE_THREADED: "true"' in compose


def test_compose_gil_override_is_an_explicit_fallback():
    override = (ROOT / "compose.gil.yml").read_text(encoding="utf-8")

    assert "dockerfile: Dockerfile" in override
    assert 'DTVP_REQUIRE_FREE_THREADED: "false"' in override


def test_pipeline_publishes_free_threaded_primary_and_gil_fallback_tags():
    workflow = (ROOT / ".github/workflows/build-publish.yml").read_text(
        encoding="utf-8"
    )

    assert "Build and Push DTVP (free-threaded default)" in workflow
    assert "file: Dockerfile.free-threaded" in workflow
    assert "dtvp:latest-freethreaded" in workflow
    assert "dtvp:dev-freethreaded" in workflow
    assert "Build and Push DTVP (GIL fallback)" in workflow
    assert "dtvp:latest-gil" in workflow
    assert "dtvp:dev-gil" in workflow
