"""Create an isolated synthetic advisory-delta playground through HTTP only."""

import argparse
import json
from datetime import UTC, datetime
from uuid import uuid4

import httpx

NAME = "[SYNTHETIC] Advisory evolution playground"
VERSION = "7.1.1"
TAG = "synthetic-before-advisory-update"
IDENTIFIER = "CVE-2099-49001"


def response(value):
    value.raise_for_status()
    return value.json()


def document():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "bom-ref": "app",
                "name": "Synthetic application",
                "type": "application",
                "version": VERSION,
            }
        },
        "components": [
            {"bom-ref": "library", "name": "Synthetic library", "type": "library", "version": "1.0"}
        ],
        "dependencies": [
            {"ref": "app", "dependsOn": ["library"]},
            {"ref": "library", "dependsOn": []},
        ],
        "vulnerabilities": [
            {
                "id": IDENTIFIER,
                "source": {"name": "Synthetic SBOM producer"},
                "description": "Invented observation for playground interactions only.",
                "ratings": [{"score": 7.5}],
                "affects": [{"ref": "library"}],
            }
        ],
    }


def feed(publisher, description, score):
    return {
        "format": "dtvp.advisory-feed/1",
        "id": "synthetic-catalog",
        "publisher": publisher,
        "advisories": [
            {
                "advisory": {
                    "id": IDENTIFIER,
                    "description": description,
                    "ratings": [{"score": score}],
                },
                "raw": {"synthetic": True, "coverage": "invented known-ID claim only"},
            }
        ],
    }


def seed(client):
    response(client.post("/api/v2/playground/login", json={"persona": "administrator"}))
    client.headers["X-CSRF-Token"] = client.cookies["dtvp_csrf"]
    if response(client.get("/api/v2/me")).get("playground") is not True:
        raise ValueError("Refusing writes: server is not an isolated playground")
    existing = response(client.get("/api/v2/catalog/projects", params={"q": NAME, "limit": 100}))
    project = next((item for item in existing["items"] if item["name"] == NAME), None)
    if project:
        return {
            "synthetic": True,
            "project_id": project["id"],
            "skipped": True,
            "reason": "Existing exact-name project preserved, including any partial or interactive edits. Use a fresh isolated playground for reseeding.",
        }
    teams = response(client.get("/api/v2/workspaces"))
    platform = next(item["id"] for item in teams if item["name"] == "Platform")
    project = response(
        client.post("/api/v2/projects", json={"workspace_id": platform, "name": NAME})
    )
    path = f"/api/v3/projects/{project['id']}"
    original = response(
        client.post(
            path + f"/versions/{VERSION}/imports",
            json={
                "request_id": str(uuid4()),
                "expected": None,
                "source": "synthetic/pipeline",
                "build_number": 1,
                "occurred_at": datetime.now(UTC).isoformat(),
                "completeness": "complete",
                "sbom": document(),
            },
        )
    )
    if original.get("projection") != "current":
        raise RuntimeError(
            "Import committed but projection pending; existing project will be preserved on rerun"
        )

    def head():
        return response(client.get(path + f"/versions/{VERSION}/inventory"))["state"]

    def evidence():
        return response(client.get(path + "/evidence"))["evidence_state"]

    def publish(source, revision, value):
        result = response(
            client.post(
                path + "/evidence/imports",
                json={
                    "request_id": str(uuid4()),
                    "expected_evidence": evidence(),
                    "expected_versions": {VERSION: head()},
                    "source": source,
                    "revision": revision,
                    "document": value,
                },
            )
        )
        if result.get("projection") != "current":
            raise RuntimeError(
                "Evidence committed but projection pending; no automatic repeat or repin"
            )

    publish(
        "synthetic/provider-A",
        1,
        feed("Synthetic provider A", "Original invented provider statement", 9.8),
    )
    historical = head()
    response(
        client.post(
            path + "/tags", json={"request_id": str(uuid4()), "name": TAG, "state": historical}
        )
    )
    publish(
        "synthetic/provider-A",
        2,
        feed(
            "Synthetic provider A",
            "Changed invented statement; zero is a source claim, not clearance",
            0,
        ),
    )
    publish(
        "synthetic/provider-B",
        1,
        feed("Synthetic provider B", "Contradictory invented provider statement", 9.8),
    )
    current_evidence = evidence()
    report = response(
        client.post(
            path + "/compare/intelligence",
            json={"inventory_state": historical, "evidence_state": current_evidence},
        )
    )
    if report["statistics"]["by_status"] != {"added": 1, "changed": 1}:
        raise RuntimeError(
            "Unexpected comparison; inspect retained inputs without resetting this project"
        )
    bundle = response(client.get(path + f"/states/{head()}/bundle"))
    original_claims = [
        item
        for item in bundle["source_observations"]
        if item.get("identifier") == IDENTIFIER
        and not item["observation_id"].startswith("external-evidence:")
    ]
    if (
        len(original_claims) != 1
        or original_claims[0]["advisory"]["ratings"][0]["score"] != 7.5
        or any(
            bundle[key] for key in ("retained_assessments", "retained_reviews", "retained_scoring")
        )
    ):
        raise RuntimeError("Unexpected source or human-decision changes; inspect retained state")
    return {
        "synthetic": True,
        "project_id": project["id"],
        "version": VERSION,
        "workspace_url": f"{str(client.base_url).rstrip('/')}/?page=Knowledge&k_project={project['id']}&k_version={VERSION}",
        "historical_inventory_state": historical,
        "selected_evidence_state": current_evidence,
        "report_digest": report["report_digest"],
        "statistics": report["statistics"],
        "instructions": "Open Advisory intelligence refresh → Compare retained inventory with advisory evidence. Capture inputs, choose retained inventory state above and the captured evidence reference, then compare.",
        "limits": "All data invented. The original SBOM rating remains 7.5. Provider zero/contradiction does not establish remediation, applicability, independent corroboration or approval. Ownership/discovery/license coverage remain unknown. No external provider requests or human decisions created.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8900")
    args = parser.parse_args()
    with httpx.Client(base_url=args.url, timeout=120, follow_redirects=False) as client:
        print(json.dumps(seed(client), indent=2))


if __name__ == "__main__":
    main()
