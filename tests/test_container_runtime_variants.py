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


def test_pipeline_publishes_only_the_free_threaded_dtvp_image():
    workflow = (ROOT / ".github/workflows/build-publish.yml").read_text(
        encoding="utf-8"
    )

    assert "Build and Push DTVP (free-threaded)" in workflow
    assert "file: Dockerfile.free-threaded" in workflow
    assert "Build and Push DTVP (GIL fallback)" not in workflow
    assert "file: Dockerfile\n" not in workflow
    assert "-freethreaded" not in workflow
    assert "-gil" not in workflow


def test_image_publication_waits_for_all_test_suites_and_avoids_redundant_setup():
    workflow = (ROOT / ".github/workflows/build-publish.yml").read_text(
        encoding="utf-8"
    )

    assert "needs: [test-backend, test-frontend, test-e2e]" in workflow
    assert "test-agentyzer:" not in workflow
    assert workflow.count("uses: actions/setup-node@v6") == 3
    assert workflow.count("node-version: 24") == 3
    assert "docker/setup-qemu-action" not in workflow
    assert "docker-buildx-plugin" not in workflow
    assert "docker-compose-plugin" not in workflow
    assert "uv add --dev cyclonedx-bom" not in workflow
    assert "npm install --save-dev" not in workflow
    assert "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in workflow


def test_compose_uses_a_standalone_agentyzer_image():
    compose = (ROOT / "compose.yml").read_text(encoding="utf-8")

    assert "image: ${AGENTYZER_IMAGE:-agentyzer:dev}" in compose
    assert "context: ./agentyzer" not in compose
