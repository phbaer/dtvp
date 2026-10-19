"""Exercise native multi-SBOM assembly in the isolated HTTP playground.

Uses dedicated ``assembly-demo`` state; never resets existing playground data.
All documents, observation dates and coverage claims below are synthetic.
"""

import argparse
import hashlib
import json
from datetime import UTC, datetime, timedelta

import httpx

from dtvp.api_contract import API_PREFIX

VERSION = "assembly-demo"


def request_id(payload):
    """The same operation/input gets the same retry receipt."""
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "assembly-demo-" + hashlib.sha256(raw).hexdigest()


def checked(response):
    response.raise_for_status()
    return response.json()


def publication(response):
    result = checked(response)
    if result.get("projection") != "current":
        raise RuntimeError("Publication committed; projection pending. Check API logs.")
    return result["updates"][0]["target"]


def inventory(client, path):
    response = client.get(path)
    if response.status_code == 404:
        return None
    result = checked(response)
    if result.get("projection_current") is False:
        raise RuntimeError("Projection is behind the journal. Check API logs.")
    return result


def document(part_id, *, updated=False):
    """Repeated local refs deliberately exercise per-part namespacing."""
    version = "2.0.0" if updated else "1.0.0"
    components = [
        {
            "type": "library",
            "bom-ref": "shared",
            "name": "assembly-demo-shared",
            "version": version,
            "purl": f"pkg:generic/assembly-demo-shared@{version}",
            "licenses": [{"license": {"id": "MIT"}}],
        }
    ]
    if part_id == "backend" and not updated:
        components.append(
            {"type": "library", "bom-ref": "removed", "name": "demo-old-helper", "version": "1"}
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": "root",
                "name": f"assembly-demo-{part_id}",
                "version": version,
            }
        },
        "components": components,
        "dependencies": [
            {"ref": "root", "dependsOn": [item["bom-ref"] for item in components]},
            *[{"ref": item["bom-ref"], "dependsOn": []} for item in components],
        ],
    }


def import_part(client, path, project_path, part_id, *, updated=False):
    part_path = f"{path}/parts/{part_id}"
    current = inventory(client, part_path)
    build = current["baseline"]["build_number"] + 1 if current else 1
    raw = (json.dumps(document(part_id, updated=updated), indent=2) + "\n").encode()
    metadata = {
        "expected": current["state"] if current else None,
        "source": f"playground/assembly/{part_id}",
        "build_number": build,
        # Deterministic synthetic observation time; these are not real pipeline runs.
        "occurred_at": (datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=build)).isoformat(),
        "completeness": "complete",
        "context": {
            "subject_kind": "build",
            "target": f"assembly-demo-{part_id}",
            "platform": "synthetic-linux",
            "configuration": "demo",
            "pipeline_run": f"synthetic-{part_id}-{build}",
            "collector": "assembly-demo",
            "method": "build",
            "package_coverage": "reported_complete",
            "dependency_coverage": "reported_complete",
            "license_coverage": "unknown",
            "limitations": ["Synthetic demonstration; not a real scan or release."],
        },
    }
    metadata["request_id"] = request_id({**metadata, "sha256": hashlib.sha256(raw).hexdigest()})
    state = publication(
        client.post(
            f"{part_path}/files",
            data={"metadata": json.dumps(metadata)},
            files={"file": (f"{part_id}.cdx.json", raw, "application/json")},
        )
    )
    original = client.get(f"{project_path}/states/{state}/source")
    original.raise_for_status()
    if original.content != raw:
        raise RuntimeError(f"Original bytes changed for part {part_id}")
    if original.headers.get("x-content-sha256") != hashlib.sha256(raw).hexdigest():
        raise RuntimeError(f"Original digest mismatch for part {part_id}")
    print(f"  {part_id}: build {build}, state {state}; original bytes verified")
    return state


def assemble(client, path, project_path, parts, *, reused=False):
    current = inventory(client, f"{path}/inventory")
    payload = {
        "expected": current["state"] if current else None,
        "parts": [
            {"part_id": part_id, "required": True, "state": state}
            for part_id, state in sorted(parts.items())
        ],
        "removed_parts": [],
        "coherence": {
            "status": "producer_declared",
            "build_id": "synthetic-integration-" + request_id(parts)[-16:],
            "rationale": (
                "Synthetic integration pipeline selected a new backend and explicitly reused "
                "the unchanged frontend artifact. This is a producer declaration, not verification."
                if reused
                else "Synthetic integration pipeline selected both parts for one build. "
                "This is a producer declaration, not verification."
            ),
        },
    }
    payload["request_id"] = request_id(payload)
    state = publication(client.post(f"{path}/assembly", json=payload))
    manifest = checked(client.get(f"{project_path}/states/{state}/assembly"))["manifest"]
    selected = {part["part_id"]: part["state"] for part in manifest["parts"]}
    if selected != parts:
        raise RuntimeError("Assembly manifest differs from selected source states")
    print(f"Assembly: {state}")
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8900")
    args = parser.parse_args()
    with httpx.Client(base_url=args.url, timeout=30) as client:
        checked(client.post(f"{API_PREFIX}/playground/login", json={"persona": "analyst"}))
        client.headers["X-CSRF-Token"] = client.cookies["dtvp_csrf"]
        projects = checked(client.get(f"{API_PREFIX}/projects"))
        project = next((item for item in projects if item["name"] == "Demo Gateway"), None)
        if project is None:
            raise RuntimeError("Demo Gateway missing; start the isolated seeded playground first")
        project_path = f"{API_PREFIX}/projects/{project['id']}"
        path = f"{project_path}/versions/{VERSION}"
        print("Synthetic assembly demo; only dedicated assembly-demo state is updated.")
        backend = import_part(client, path, project_path, "backend")
        old_backend = backend
        frontend = import_part(client, path, project_path, "frontend")
        before = assemble(client, path, project_path, {"backend": backend, "frontend": frontend})
        backend = import_part(client, path, project_path, "backend", updated=True)
        after = assemble(
            client, path, project_path, {"backend": backend, "frontend": frontend}, reused=True
        )
        diff = checked(
            client.get(f"{project_path}/compare", params={"before": before, "after": after})
        )
        part_delta = diff["assembly"]
        if (
            {part["part_id"] for part in part_delta["changed"]} != {"backend"}
            or part_delta["added"]
            or part_delta["removed"]
        ):
            raise RuntimeError("Expected only the backend part to change")
        if not diff["changes"]["inventory"]["removed"]:
            raise RuntimeError("Nightly delta did not retain the removed-helper difference")
        print("Nightly delta (backend updated/helper removed; frontend state unchanged):")
        print(json.dumps(diff, indent=2))
        original = client.get(f"{project_path}/states/{old_backend}/source")
        original.raise_for_status()
        expected = (json.dumps(document("backend"), indent=2) + "\n").encode()
        if original.content != expected:
            raise RuntimeError("Previous backend original changed after nightly replacement")
        print("Pinned original source files remain retrievable for every selected part state.")


if __name__ == "__main__":
    main()
