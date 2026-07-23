import json
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]


def test_pull_requests_cannot_publish_or_receive_registry_credentials():
    workflow = (ROOT / ".github" / "workflows" / "build-publish.yml").read_text(
        encoding="utf-8"
    )

    assert "types: [opened, synchronize, reopened]" in workflow
    assert workflow.count("head.repo.full_name == github.repository") == 5
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
    assert '"$repository_dir/scripts/check-node-tls.sh"' in sbom_script
    assert "@cyclonedx/cyclonedx-npm" not in workflow
    forgejo_upload_artifact = (
        "https://data.forgejo.org/actions/upload-artifact@"
        "c6a3b2bd78b3985e4b2f15397fec357f0fd808de"
    )
    assert workflow.count(forgejo_upload_artifact) == 4
    assert "https://data.forgejo.org/forgejo/upload-artifact@" not in workflow
    assert "uses: actions/upload-artifact@" not in workflow
    assert "needs: [test-backend, test-frontend, test-agentyzer, test-e2e]" in workflow
    assert workflow.count("needs: [scan-images]") == 2


def test_ci_gates_dependencies_and_images_before_publishing():
    workflow = (ROOT / ".github" / "workflows" / "build-publish.yml").read_text(
        encoding="utf-8"
    )

    assert "pip-audit --local --progress-spinner=off" in workflow
    assert "--vulnerability-service=osv --timeout=30" in workflow
    assert "bandit -ll -ii -c pyproject.toml -r dtvp agentyzer/src" in workflow
    assert workflow.count("npm audit --audit-level=high") == 2
    assert "./scripts/check-node-tls.sh" in workflow
    trivy_ref = (
        "aquasecurity/trivy-action@"
        "ed142fd0673e97e23eac54620cfb913e5ce36c25"
    )
    assert workflow.count(trivy_ref) == 2
    assert workflow.count("ignore-unfixed: false") == 2
    assert workflow.count("severity: HIGH,CRITICAL") == 2
    assert workflow.index("scan-images:") < workflow.index("build-push-images:")


def test_ci_attaches_build_evidence_and_signs_release_digests():
    workflow = (ROOT / ".github" / "workflows" / "build-publish.yml").read_text(
        encoding="utf-8"
    )

    assert workflow.count("provenance: mode=max") == 2
    assert workflow.count("sbom: true") == 2
    assert "id: build_dtvp" in workflow
    assert "id: build_agentyzer" in workflow
    assert (
        "sigstore/cosign-installer@"
        "6f9f17788090df1f26f669e9d70d6ae9567deba6"
    ) in workflow
    assert "COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}" in workflow
    assert "COSIGN_PASSWORD: ${{ secrets.COSIGN_PASSWORD }}" in workflow
    assert "--key env://COSIGN_PRIVATE_KEY" in workflow
    assert "dtvp@${DTVP_IMAGE_DIGEST}" in workflow
    assert "agentyzer@${AGENTYZER_IMAGE_DIGEST}" in workflow
    assert workflow.count("cosign verify --key /tmp/dtvp-cosign.pub") == 2
    assert "--key ${{ secrets.COSIGN_PRIVATE_KEY }}" not in workflow


def test_node_network_tools_reject_disabled_tls_verification():
    guard = (ROOT / "scripts" / "check-node-tls.sh").read_text(encoding="utf-8")
    sbom_script = (ROOT / "scripts" / "generate-sboms.sh").read_text(
        encoding="utf-8"
    )

    assert 'NODE_TLS_REJECT_UNAUTHORIZED:-}' in guard
    assert 'NODE_TLS_REJECT_UNAUTHORIZED:-}' not in sbom_script
    assert '"$repository_dir/scripts/check-node-tls.sh"' in sbom_script


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
