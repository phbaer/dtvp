"""Customer acceptance tooling must expose unknowns and never manufacture sign-off."""

import copy
import json

import httpx
import pytest

from dtvp.storage import canonical, digest
from scripts.knowledge_acceptance import EXTERNAL_GATES, FORMAT, verify


@pytest.fixture
def supplied(tmp_path):
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [{"bom-ref": "legacy", "type": "library", "name": "Legacy C binary"}],
    }
    raw = json.dumps(document).encode()
    (tmp_path / "legacy.json").write_bytes(raw)
    manifest = {
        "format": FORMAT,
        "scenario": "Supplier nightly acceptance",
        "fixtures": [
            {
                "id": "legacy",
                "path": "legacy.json",
                "sha256": digest(raw),
                "producer": "supplier-C-build",
                "product_line": "device",
                "version": "7.1.1",
                "part_id": "firmware",
                "coverage": {
                    "packages": "partial",
                    "dependencies": "unknown",
                    "licenses": "unknown",
                },
                "expected": {"components": 1, "findings": 0, "format": "cyclonedx-json"},
            }
        ],
    }
    return tmp_path, manifest, raw


def by_gate(report, name):
    return next(row for row in report["gates"] if row["gate"] == name)


def test_missing_package_coordinates_and_unknown_coverage_are_reported_without_clearance(supplied):
    root, manifest, _ = supplied
    report = verify(manifest, root)
    assert report["verification"] == "configured_checks_passed"
    assert report["acceptance"] == "not_granted"
    fixture = by_gate(report, "fixture:legacy")
    assert fixture["status"] == "pass"
    assert fixture["missing_purl"] == fixture["missing_version"] == 1
    assert fixture["producer_declared_coverage"]["dependencies"] == "unknown"
    assert all(by_gate(report, name)["status"] == "not_run" for name in EXTERNAL_GATES)
    assert by_gate(report, "deployment")["status"] == "not_run"


@pytest.mark.parametrize(
    "change", ["checksum", "parse", "expectation", "coverage", "escape", "symlink"]
)
def test_supplied_bytes_and_explicit_expectations_fail_closed(supplied, tmp_path, change):
    root, manifest, _ = supplied
    row = manifest["fixtures"][0]
    if change == "checksum":
        row["sha256"] = "0" * 64
    elif change == "parse":
        raw = b'{"unsupported":true}'
        (root / row["path"]).write_bytes(raw)
        row["sha256"] = digest(raw)
    elif change == "expectation":
        row["expected"]["components"] = 2
    elif change == "coverage":
        row["coverage"].pop("licenses")
    elif change == "escape":
        row["path"] = "../legacy.json"
    else:
        (root / "link").symlink_to(root.parent)
        row["path"] = "link/outside.json"
    report = verify(manifest, root)
    assert report["verification"] == "failed"
    assert by_gate(report, "fixture:legacy")["status"] == "fail"
    assert report["acceptance"] == "not_granted"


def pinned(manifest):
    before, after = "a" * 64, "b" * 64
    second = copy.deepcopy(manifest["fixtures"][0])
    second.update(id="legacy-patch", version="7.1.2")
    manifest["fixtures"].append(second)
    manifest["deployment"] = {
        "project_id": "product",
        "states": [
            {"state": before, "version": "7.1.1", "fixtures": ["legacy"]},
            {"state": after, "version": "7.1.2", "fixtures": ["legacy-patch"]},
        ],
        "comparisons": [{"before": before, "after": after, "expect_changes": True}],
    }
    return before, after


@pytest.mark.parametrize(
    "failure", [None, "scope", "digest", "original", "comparison", "redirect", "malformed"]
)
def test_pinned_deployment_checks_scopes_exact_sources_and_comparison_without_writes(
    supplied, failure
):
    root, manifest, raw = supplied
    before, after = pinned(manifest)
    calls = []

    def server(request):
        calls.append((request.method, request.url.path))
        assert request.method == "GET"
        if failure == "redirect":
            return httpx.Response(302, headers={"location": "https://third-party.invalid/steal"})
        if request.url.path.endswith("/evidence-summary"):
            state = request.url.path.split("/")[-2]
            summary = {
                "format": "dtvp.pipeline-evidence-summary/1",
                "state": state,
                "project_id": "other" if failure == "scope" else "product",
                "version": "7.1.1" if state == before else "7.1.2",
            }
            if failure == "malformed":
                return httpx.Response(200, json=[])
            summary["summary_digest"] = (
                digest(canonical(summary)) if failure != "digest" else "0" * 64
            )
            return httpx.Response(200, json=summary)
        if "/artifacts/" in request.url.path:
            return httpx.Response(
                200, content=raw if failure != "original" else b"different source"
            )
        assert request.url.path.endswith("/compare/details")
        assert request.url.params["before"] == before and request.url.params["after"] == after
        return httpx.Response(
            200,
            json={
                "project_id": "product",
                "before": before,
                "after": after,
                "before_version": "7.1.1",
                "after_version": "7.1.2",
                "total": 0 if failure == "comparison" else 3,
            },
        )

    with httpx.Client(
        base_url="http://local.test", transport=httpx.MockTransport(server)
    ) as client:
        report = verify(manifest, root, client=client)
    assert report["verification"] == ("failed" if failure else "configured_checks_passed")
    assert report["acceptance"] == "not_granted"
    assert not any("third-party" in path for _, path in calls)
    if failure is None:
        assert by_gate(report, "state:" + before)["verified_originals"] == ["legacy"]
        assert by_gate(report, "comparison:0")["total_changes"] == 3


def test_deployment_without_client_explicitly_leaves_every_remote_gate_open(supplied):
    root, manifest, _ = supplied
    before, after = pinned(manifest)
    report = verify(manifest, root)
    assert all(
        by_gate(report, name)["status"] == "not_run"
        for name in ("state:" + before, "state:" + after, "comparison:0")
    )


@pytest.mark.parametrize("conclusion", ["pass", "fail"])
def test_hashed_external_review_is_an_attestation_not_an_independent_acceptance(
    conclusion, supplied
):
    root, manifest, _ = supplied
    evidence = b"Reviewed customer document parity results; held outside DTVP."
    (root / "parity.txt").write_bytes(evidence)
    manifest["attestations"] = [
        {
            "gate": "generator_document_parity",
            "conclusion": conclusion,
            "path": "parity.txt",
            "sha256": digest(evidence),
            "reviewer": "Quality reviewer",
            "reviewed_at": "2026-10-16T12:00:00+02:00",
            "fixture_ids": ["legacy"],
        }
    ]
    report = verify(manifest, root)
    row = by_gate(report, "generator_document_parity")
    assert row["status"] == "not_run"
    assert row["evidence_verification"] == "pass"
    assert row["assurance"] == "supplied_attestation_only"
    assert row["declared_conclusion"] == conclusion
    assert report["verification"] == (
        "failed" if conclusion == "fail" else "configured_checks_passed"
    )
    assert report["acceptance"] == "not_granted"


@pytest.mark.parametrize("change", ["timezone", "scope", "checksum"])
def test_external_attestations_require_explicit_fixture_scope_timestamp_and_exact_bytes(
    change, supplied
):
    root, manifest, raw = supplied
    row = {
        "gate": "consumer_round_trips",
        "conclusion": "pass",
        "path": "legacy.json",
        "sha256": digest(raw),
        "reviewer": "Reviewer",
        "reviewed_at": "2026-10-16T12:00:00Z",
        "fixture_ids": ["legacy"],
    }
    if change == "timezone":
        row["reviewed_at"] = "2026-10-16T12:00:00"
    elif change == "scope":
        row["fixture_ids"] = ["unrelated"]
    else:
        row["sha256"] = "0" * 64
    manifest["attestations"] = [row]
    report = verify(manifest, root)
    assert by_gate(report, "consumer_round_trips")["status"] == "fail"


def test_fixture_and_product_version_scope_must_agree(supplied):
    root, manifest, _ = supplied
    pinned(manifest)
    manifest["deployment"]["states"][0]["version"] = "8.0.0"
    with pytest.raises(ValueError, match="version scopes differ"):
        verify(manifest, root)


def test_comparisons_are_restricted_to_one_product_line(supplied):
    root, manifest, _ = supplied
    second = copy.deepcopy(manifest["fixtures"][0])
    second.update(id="other", product_line="unrelated")
    manifest["fixtures"].append(second)
    with pytest.raises(ValueError, match="one product line"):
        verify(manifest, root)


def test_supplied_fixture_is_verified_against_real_native_retained_bytes(supplied, analyst):
    root, manifest, raw = supplied
    project = analyst.get("/api/v2/projects").json()[0]["id"]
    response = analyst.post(
        f"/api/v3/projects/{project}/versions/7.1.1/files",
        data={
            "metadata": json.dumps(
                {
                    "request_id": "acceptance-source",
                    "expected": None,
                    "source": "supplied-fixture",
                    "build_number": 1,
                    "occurred_at": "2026-10-16T12:00:00Z",
                    "completeness": "complete",
                }
            )
        },
        files={"file": ("legacy.json", raw, "application/json")},
    )
    assert response.status_code == 201, response.text
    state = response.json()["updates"][0]["target"]
    manifest["deployment"] = {
        "project_id": project,
        "states": [{"state": state, "version": "7.1.1", "fixtures": ["legacy"]}],
        "comparisons": [{"before": state, "after": state, "expect_changes": False}],
    }
    report = verify(manifest, root, client=analyst)
    assert report["verification"] == "configured_checks_passed", report
    assert by_gate(report, "state:" + state)["verified_originals"] == ["legacy"]
    assert by_gate(report, "comparison:0")["total_changes"] == 0
    assert report["acceptance"] == "not_granted"
