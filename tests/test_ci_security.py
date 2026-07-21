import json
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]


def test_pull_requests_cannot_publish_or_receive_registry_credentials():
    workflow = (ROOT / ".github" / "workflows" / "build-publish.yml").read_text(
        encoding="utf-8"
    )

    assert "types: [opened, synchronize, reopened]" in workflow
    assert workflow.count("head.repo.full_name == github.repository") == 4
    assert "github.event_name == 'pull_request' && format" not in workflow
    assert "delete-pr-images:" not in workflow
    assert "GIT_AUTH_TOKEN=" not in workflow


def test_ci_uses_locked_dependencies_and_read_only_default_permissions():
    workflow = (ROOT / ".github" / "workflows" / "build-publish.yml").read_text(
        encoding="utf-8"
    )
    sbom_script = (ROOT / "scripts" / "generate-sboms.sh").read_text(
        encoding="utf-8"
    )

    assert "permissions:\n  contents: read" in workflow
    assert "uv add " not in workflow + sbom_script
    assert "npm install --save-dev" not in workflow + sbom_script
    assert "./scripts/generate-sboms.sh" in workflow
    assert "npm ci --ignore-scripts" in sbom_script
    assert "npm run generate --" in sbom_script
    assert 'NODE_TLS_REJECT_UNAUTHORIZED:-}' in sbom_script
    assert "@cyclonedx/cyclonedx-npm" not in workflow
    assert "actions/upload-artifact@v" not in workflow
    assert "needs: [test-backend, test-frontend, test-agentyzer, test-e2e]" in workflow


def test_ci_actions_are_pinned_to_immutable_commits():
    workflow = (ROOT / ".github" / "workflows" / "build-publish.yml").read_text(
        encoding="utf-8"
    )

    action_lines = [line.strip() for line in workflow.splitlines() if "uses:" in line]
    assert action_lines
    for line in action_lines:
        reference = line.split("@", 1)[1].split()[0]
        assert len(reference) == 40
        assert all(character in "0123456789abcdef" for character in reference)


def test_npm_lockfiles_do_not_embed_environment_specific_registries():
    for relative_path in (
        "frontend/package-lock.json",
        "frontend/sbom-tool/package-lock.json",
    ):
        lock = json.loads((ROOT / relative_path).read_text(encoding="utf-8"))
        resolved_hosts = {
            urlparse(package["resolved"]).hostname
            for package in lock["packages"].values()
            if package.get("resolved", "").startswith("https://")
        }
        assert resolved_hosts <= {"registry.npmjs.org"}
