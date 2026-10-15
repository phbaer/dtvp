"""Exercise contextual team ownership in a dedicated isolated-playground project.

All composition and collection evidence here is synthetic. The scenario never
resets data or changes policy on another project. Requires the playground API.
"""

import argparse
import hashlib
import json
from datetime import UTC, datetime, timedelta

import httpx

PROJECT_NAME = "Ownership Playground"
VERSIONS = ("7.1.1", "7.1.2")


def checked(response):
    response.raise_for_status()
    return response.json()


def request_id(payload):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "ownership-demo-" + hashlib.sha256(raw).hexdigest()


def publication(response):
    result = checked(response)
    if result.get("projection") != "current":
        raise RuntimeError("Publication committed; projection pending. Check API logs.")
    return result


def document(version):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": "product",
                "name": "ownership-product",
                "version": version,
            }
        },
        "components": [
            {
                "type": "application" if ref in {"B", "C"} else "library",
                "bom-ref": ref,
                "name": name,
                "group": "demo",
                "version": "1.0.0",
            }
            for ref, name in (("B", "app-b"), ("C", "app-c"), ("A", "shared-a"), ("X", "leaf-x"))
        ],
        "dependencies": [
            {"ref": "product", "dependsOn": ["B", "C"]},
            {"ref": "B", "dependsOn": ["A", "X"]},
            {"ref": "C", "dependsOn": ["A"]},
            {"ref": "A", "dependsOn": ["X"]},
            {"ref": "X", "dependsOn": []},
        ],
    }


def import_version(client, project_path, version):
    path = f"{project_path}/versions/{version}"
    response = client.get(f"{path}/inventory")
    current = None if response.status_code == 404 else checked(response)
    if current and current.get("projection_current") is False:
        raise RuntimeError("Projection is behind the journal. Check API logs.")
    build = current["baseline"]["build_number"] + 1 if current else 1
    payload = {
        "expected": current["state"] if current else None,
        "source": "playground/ownership-demo",
        "build_number": build,
        "occurred_at": (datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=build)).isoformat(),
        "completeness": "complete",
        "sbom": document(version),
        "context": {
            "subject_kind": "build",
            "target": "ownership-demo",
            "configuration": "synthetic",
            "pipeline_run": f"synthetic-{version}-{build}",
            "collector": "ownership-demo",
            "method": "build",
            "package_coverage": "reported_complete",
            "dependency_coverage": "reported_complete",
            "limitations": ["Synthetic graph; not a real scan or release."],
        },
    }
    payload["request_id"] = request_id(payload)
    publication(client.post(f"{path}/imports", json=payload))
    print(f"  Imported {version}, synthetic build {build}")


def configure(client, project_path, platform, operations, *, reassign=False):
    current = checked(client.get(f"{project_path}/ownership"))
    payload = {
        "expected_policy": current["policy_state"],
        "expected_versions": current["versions"],
        "rules": [
            {
                "selector": "cs::demo:shared-a",
                "team_id": operations if reassign else platform,
                "aliases": ["Shared library team", "Team A"],
            },
            {"selector": "demo:app-b", "team_id": operations, "aliases": ["Team B"]},
            {
                "selector": "demo:app-c",
                "team_id": operations,
                "aliases": ["Team C"],
                "versions": list(VERSIONS),
            },
        ],
        "context_roots": {version: ["B", "C"] for version in VERSIONS},
    }
    payload["request_id"] = request_id(payload)
    publication(client.put(f"{project_path}/ownership", json=payload))


def show_contexts(client, project_path, version, expected_team):
    path = f"{project_path}/versions/{version}/contexts"
    data = checked(client.get(path, params={"limit": 200}))
    if not data["projection_current"] or data["next_offset"] is not None:
        raise RuntimeError("Expected the entire current synthetic context set")
    leaves = [item for item in data["items"] if item["component_ref"] == "X"]
    if (
        len(leaves) != 2
        or {item["root_ref"] for item in leaves} != {"B", "C"}
        or len({item["id"] for item in leaves}) != 2
        or any(item["team_id"] != expected_team or item["status"] != "resolved" for item in leaves)
        or any(item["owner_boundaries"] != ["A"] for item in leaves)
    ):
        raise RuntimeError("Expected Team A to cover X separately in B and C, including B's bypass")
    for item in leaves:
        print(
            f"  {version}: root {item['root_ref']} -> leaf X; owner {item['team_id']}; "
            f"context {item['id']}"
        )
    return data["state"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8900")
    args = parser.parse_args()
    with httpx.Client(base_url=args.url, timeout=30) as client:
        checked(client.post("/api/v2/playground/login", json={"persona": "administrator"}))
        client.headers["X-CSRF-Token"] = client.cookies["dtvp_csrf"]
        teams = {item["name"]: item["id"] for item in checked(client.get("/api/v2/workspaces"))}
        if not {"Platform", "Operations"} <= teams.keys():
            raise RuntimeError("Start the isolated seeded playground with Platform/Operations teams")
        projects = checked(client.get("/api/v2/projects"))
        candidates = [
            item for item in projects
            if item["name"] == PROJECT_NAME and item["workspace_id"] == teams["Platform"]
        ]
        if len(candidates) > 1:
            raise RuntimeError("Multiple Ownership Playground projects; select a clean playground")
        project = candidates[0] if candidates else checked(
            client.post(
                "/api/v2/projects", json={"workspace_id": teams["Platform"], "name": PROJECT_NAME}
            )
        )
        project_path = f"/api/v3/projects/{project['id']}"
        print(f"Synthetic ownership demo; only dedicated project {project['id']} is updated.")
        for version in VERSIONS:
            import_version(client, project_path, version)
        configure(client, project_path, teams["Platform"], teams["Operations"])
        print("Platform owns shared A and leaf X; Operations owns consuming roots B/C:")
        before = {
            version: show_contexts(client, project_path, version, teams["Platform"])
            for version in VERSIONS
        }
        configure(client, project_path, teams["Platform"], teams["Operations"], reassign=True)
        print("Reassigned shared A to Operations; contexts remain distinct:")
        for version in VERSIONS:
            after = show_contexts(client, project_path, version, teams["Operations"])
            diff = checked(client.get(
                f"{project_path}/compare", params={"before": before[version], "after": after}
            ))
            if not diff["changes"].get("ownership", {}).get("changed"):
                raise RuntimeError("Expected a pinned ownership delta after reassignment")
            print(f"  {version} retained previous state {before[version]}; current state {after}")
        print("Aliases identify one owner; independent consuming trees retain separate contexts.")
        print("No assessments are created by this demo. Prior states and decisions are retained.")


if __name__ == "__main__":
    main()
