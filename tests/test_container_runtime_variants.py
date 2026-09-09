from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_compose_defaults_to_fail_closed_free_threaded_image():
    compose = (ROOT / "compose.yml").read_text(encoding="utf-8")

    assert "dockerfile: Dockerfile.free-threaded" in compose
    assert 'DTVP_REQUIRE_FREE_THREADED: "true"' in compose


def test_free_threaded_image_has_immutable_inputs_and_non_root_default():
    dockerfile = (ROOT / "Dockerfile.free-threaded").read_text(encoding="utf-8")

    assert "ARG PYTHON_IMAGE=python:3.14-alpine@sha256:" in dockerfile
    assert "ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.11.31@sha256:" in dockerfile
    assert "FROM node:24-alpine@sha256:" in dockerfile
    assert "node:lts-alpine" not in dockerfile
    assert "UV_VERSION" not in dockerfile
    assert dockerfile.count("@sha256:") >= 3
    assert dockerfile.count("type=secret,id=ca-certs") == 2
    assert "NODE_EXTRA_CA_CERTS=/tmp/ca-certs.crt npm ci" in dockerfile
    assert "UV_SYSTEM_CERTS=true" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt" in dockerfile


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
    assert "/dtvp:pr-{2}-gil" in workflow
    assert "dtvp:latest-gil" in workflow
    assert "dtvp:dev-gil" in workflow


def test_image_publication_uses_shared_test_gates_and_pinned_tooling():
    workflow = (ROOT / ".github/workflows/build-publish.yml").read_text(
        encoding="utf-8"
    )

    assert "needs: [test-backend, test-frontend, test-agentyzer, test-e2e]" in workflow
    assert "uses: actions/setup-node@" not in workflow
    assert "node-version:" not in workflow
    assert "docker/setup-qemu-action@" in workflow
    assert "docker-buildx-plugin" in workflow
    assert "docker-compose-plugin" in workflow
    assert "uv add --dev cyclonedx-bom" not in workflow
    assert "npm install --save-dev" not in workflow
    assert "cancel-in-progress: true" in workflow


def test_agentyzer_build_context_excludes_the_ci_virtual_environment():
    dockerignore = (ROOT / "agentyzer" / ".dockerignore").read_text(encoding="utf-8")

    assert dockerignore.splitlines()[0] == "**"
    assert "!.venv" not in dockerignore.splitlines()
