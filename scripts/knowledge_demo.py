"""Exercise the journal-backed API in an already running isolated playground."""

import argparse
import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx

from dtvp.api_contract import API_PREFIX

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8900")
    parser.add_argument(
        "--files", action="store_true", help="Upload and verify original SBOM files"
    )
    args = parser.parse_args()
    bom = json.loads((ROOT / "playground/fixtures/release.cdx.json").read_text())
    changed = copy.deepcopy(bom)
    # Remove one real dependency; retained tags/history must still contain it.
    changed["components"] = [c for c in changed["components"] if c["bom-ref"] != "utility"]
    changed["dependencies"] = [
        {**edge, "dependsOn": [r for r in edge.get("dependsOn", []) if r != "utility"]}
        for edge in changed["dependencies"]
        if edge["ref"] != "utility"
    ]
    with httpx.Client(base_url=args.url, timeout=30) as client:
        response = client.post(f"{API_PREFIX}/playground/login", json={"persona": "analyst"})
        response.raise_for_status()
        client.headers["X-CSRF-Token"] = client.cookies["dtvp_csrf"]
        response = client.get(f"{API_PREFIX}/projects")
        response.raise_for_status()
        project_id = response.json()[0]["id"]
        states = []
        for version, document in (("7.1.1", bom), ("7.1.2", changed)):
            path = f"{API_PREFIX}/projects/{project_id}/versions/{version}"
            current = client.get(f"{path}/inventory")
            if current.status_code == 404:
                previous, build = None, 1
            else:
                current.raise_for_status()
                previous = current.json()["state"]
                build = current.json()["baseline"]["build_number"] + 1
            metadata = {
                "request_id": str(uuid4()),
                "expected": previous,
                "source": "playground/knowledge",
                "build_number": build,
                "occurred_at": datetime.now(UTC).isoformat(),
                "completeness": "complete",
                "sbom": document,
                "predecessor": states[0] if previous is None and states else None,
            }
            if args.files:
                metadata.pop("sbom")
                raw = (json.dumps(document, indent=2) + "\n").encode()
                response = client.post(
                    f"{path}/files",
                    data={"metadata": json.dumps(metadata)},
                    files={"file": ("demo.cdx.json", raw, "application/json")},
                )
            else:
                response = client.post(f"{path}/imports", json=metadata)
            response.raise_for_status()
            result = response.json()
            if result["projection"] != "current":
                raise RuntimeError("Import committed; projection is pending. Check API logs.")
            states.append(result["updates"][0]["target"])
            print(f"{version}: build {build}, state {states[-1]}")
            if args.files:
                original = client.get(f"{API_PREFIX}/projects/{project_id}/states/{states[-1]}/source")
                original.raise_for_status()
                if original.content != raw:
                    raise RuntimeError("Original-byte verification failed")
                print(f"  Original bytes verified: {original.headers['x-content-sha256']}")
        response = client.post(
            f"{API_PREFIX}/projects/{project_id}/tags",
            json={
                "request_id": str(uuid4()),
                "name": f"demo-7.1.1-{uuid4().hex[:8]}",
                "state": states[0],
            },
        )
        response.raise_for_status()
        response = client.get(
            f"{API_PREFIX}/projects/{project_id}/compare",
            params={
                "before": states[0],
                "after": states[1],
            },
        )
        response.raise_for_status()
        print(json.dumps(response.json(), indent=2))


if __name__ == "__main__":
    main()
