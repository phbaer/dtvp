"""Add a synthetic, larger native dataset to an isolated running playground.

Uses HTTP APIs only. Existing exact fixture project names are skipped entirely;
interactive work is never reset. Run one seeder at a time. No real advisories,
matching, provider analysis, discovery verification or approvals are produced.
"""

import argparse
import json
from datetime import UTC, datetime
from uuid import uuid4

import httpx

from dtvp.api_contract import API_PREFIX

VERSIONS = ("7.1.1", "7.1.2")
ROOTS = ("scale-platform", "scale-operations")
LIMITATIONS = [
    "Synthetic software and CVE-2099 identifiers, not real vulnerability analysis.",
    "Package, dependency and license discovery coverage remain unknown; imported graph/license claims are fixture data only.",
    "No source/provider/build verification, human assessments, approvals or published scores are manufactured.",
]


def document(packages, vulnerabilities, version):
    """Complete synthetic document, including explicit unknown identity/license samples."""
    changed = version == VERSIONS[1]
    refs = [f"package-{index:04}" for index in range(packages)]
    if changed:
        refs[-1] = "package-added"
    components = [
        {"bom-ref": ref, "type": "application", "name": ref, "version": "1"} for ref in ROOTS
    ]
    for index, ref in enumerate(refs):
        component = {
            "bom-ref": ref,
            "type": "library",
            "name": "scale-shared-core" if index == 0 else f"synthetic-library-{ref}",
            "description": "Synthetic playground package; not a claim about real software.",
        }
        if index % 10 != 2:
            component["version"] = "1.1.0" if changed and index == 1 else "1.0.0"
            component["purl"] = (
                f"pkg:generic/dtvp-synthetic/{component['name']}@{component['version']}"
            )
        if index % 3 == 0:
            component["licenses"] = [{"expression": "MIT"}]
        elif index % 3 == 1:
            component["licenses"] = [{"expression": "Apache-2.0"}]
        components.append(component)
    shared_end = max(2, packages // 3)
    platform_end = shared_end + (packages - shared_end) // 2
    shared, platform, operations = (
        refs[:shared_end],
        refs[shared_end:platform_end],
        refs[platform_end:],
    )
    edges = [
        {"ref": "product", "dependsOn": list(ROOTS)},
        {"ref": ROOTS[0], "dependsOn": [shared[0], platform[0]]},
        {"ref": ROOTS[1], "dependsOn": [shared[0], operations[0]]},
        {"ref": shared[0], "dependsOn": shared[1:]},
        {"ref": platform[0], "dependsOn": platform[1:]},
        {"ref": operations[0], "dependsOn": operations[1:]},
    ]
    findings = []
    vectors = [
        (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        (0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    ]
    for index in range(vulnerabilities):
        # Replace its synthetic advisory too: retain a previous-version-only
        # claim while keeping the requested finding count on both versions.
        selected = (
            packages - 1 if index == vulnerabilities - 1 else index * packages // vulnerabilities
        )
        score, vector = vectors[index % len(vectors)]
        advisory = {
            "id": f"CVE-2099-{(20000 if changed and selected == packages - 1 else 10000) + index}",
            "source": {"name": "DTVP synthetic scale fixture"},
            "description": f"Synthetic issue {index + 1}. Not a real advisory; assess only for playground practice. Discovery, build identity and license coverage are unknown.",
            "affects": [{"ref": refs[selected]}],
        }
        # Some source severity facts intentionally remain unknown.
        if index % 7 != 6:
            advisory["ratings"] = [{"method": "CVSSv31", "score": score, "vector": vector}]
        findings.append(advisory)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "bom-ref": "product",
                "type": "application",
                "name": "Synthetic scale product",
                "version": version,
            }
        },
        "components": components,
        "dependencies": edges,
        "vulnerabilities": findings,
        "properties": [
            {"name": "dtvp:synthetic", "value": "true"},
            {"name": "dtvp:limitations", "value": "; ".join(LIMITATIONS)},
        ],
    }


def checked(response):
    response.raise_for_status()
    return response.json()


def committed(response):
    value = checked(response)
    if value.get("committed") is not True or value.get("projection") != "current":
        raise RuntimeError(
            "Seed publication/projection uncertain. Stop and inspect the existing synthetic project; reruns skip it rather than resetting or repinning."
        )
    return value


def seed(client, *, products=3, packages=250, vulnerabilities=50):
    """Works with httpx.Client or an isolated FastAPI TestClient; no storage access."""
    for name, value, low, high in (
        ("products", products, 1, 20),
        ("packages", packages, 6, 2000),
        ("vulnerabilities", vulnerabilities, 1, 250),
    ):
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"{name} must be an integer between {low} and {high}")
    checked(client.post(f"{API_PREFIX}/playground/login", json={"persona": "administrator"}))
    token = client.cookies.get("dtvp_csrf")
    if not token:
        raise RuntimeError("Playground login did not provide a CSRF token")
    client.headers["X-CSRF-Token"] = token
    me = checked(client.get(f"{API_PREFIX}/me"))
    if me.get("playground") is not True:
        raise RuntimeError(
            "Synthetic scale seeding requires a verified playground; no project writes were attempted"
        )
    teams = {row["name"]: row["id"] for row in checked(client.get(f"{API_PREFIX}/workspaces"))}
    if not {"Platform", "Operations"}.issubset(teams):
        raise RuntimeError("Playground Platform and Operations teams are required")
    existing = {row["name"]: row["id"] for row in checked(client.get(f"{API_PREFIX}/projects"))}
    result = {"synthetic": True, "limitations": list(LIMITATIONS), "created": [], "skipped": []}
    for index in range(products):
        name = f"[SYNTHETIC] Knowledge Scale Playground {index + 1:02}"
        if name in existing:
            result["skipped"].append({"project_id": existing[name], "name": name})
            continue
        project = checked(
            client.post(f"{API_PREFIX}/projects", json={"name": name, "workspace_id": teams["Platform"]})
        )
        project_id = project["id"]
        existing[name] = project_id
        checked(
            client.put(
                f"{API_PREFIX}/projects/{project_id}/sharing",
                json={
                    "workspace_id": teams["Operations"],
                    "capabilities": ["read", "assess", "approve", "snapshot", "evidence"],
                },
            )
        )
        base = f"{API_PREFIX}/projects/{project_id}"
        states = {}
        for version in VERSIONS:
            raw = (
                json.dumps(
                    document(packages, vulnerabilities, version), ensure_ascii=False, indent=2
                )
                + "\n"
            ).encode()
            fields = {
                "request_id": str(uuid4()),
                "expected": None,
                "predecessor": states.get(VERSIONS[0]),
                "source": "synthetic:knowledge-scale-playground",
                "build_number": 1,
                "occurred_at": datetime.now(UTC).isoformat(),
                "completeness": "complete",
                "context": {
                    "collector": "knowledge_scale_demo.py",
                    "target": "synthetic-playground",
                    "package_coverage": "unknown",
                    "dependency_coverage": "unknown",
                    "license_coverage": "unknown",
                    "limitations": list(LIMITATIONS),
                },
            }
            receipt = committed(
                client.post(
                    f"{base}/versions/{version}/files",
                    data={"metadata": json.dumps(fields)},
                    files={"file": (f"synthetic-{version}.cdx.json", raw, "application/json")},
                )
            )
            states[version] = receipt["updates"][0]["target"]
            original = client.get(f"{base}/states/{states[version]}/source")
            original.raise_for_status()
            if original.content != raw:
                raise RuntimeError("Original synthetic SBOM bytes differ from uploaded document")
        committed(
            client.put(
                f"{base}/ownership",
                json={
                    "request_id": str(uuid4()),
                    "expected_policy": None,
                    "expected_versions": states,
                    "rules": [
                        {"selector": ROOTS[0], "team_id": teams["Platform"]},
                        {"selector": ROOTS[1], "team_id": teams["Operations"]},
                        {
                            "selector": "dtvp-synthetic:scale-shared-core",
                            "team_id": teams["Platform"],
                        },
                    ],
                    "context_roots": {version: list(ROOTS) for version in VERSIONS},
                },
            )
        )
        versions = []
        for version in VERSIONS:
            value = checked(client.get(f"{base}/versions/{version}/workspace", params={"limit": 1}))
            versions.append(
                {
                    "version": version,
                    "state": value["state"],
                    "counts": value["statistics"],
                    "workspace_url": f"/?page=Knowledge&k_project={project_id}&k_version={version}",
                }
            )
        result["created"].append(
            {
                "project_id": project_id,
                "name": name,
                "packages_per_version": packages,
                "versions": versions,
            }
        )
    result["totals"] = {
        "created_products": len(result["created"]),
        "skipped_products": len(result["skipped"]),
        "versions_created": 2 * len(result["created"]),
        "context_findings": sum(
            version["counts"]["totals"]["context_findings"]
            for project in result["created"]
            for version in project["versions"]
        ),
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8900")
    parser.add_argument("--products", type=int, default=3)
    parser.add_argument("--packages", type=int, default=250)
    parser.add_argument("--vulnerabilities", type=int, default=50)
    args = parser.parse_args()
    with httpx.Client(base_url=args.url, timeout=120, follow_redirects=False) as client:
        print(
            json.dumps(
                seed(
                    client,
                    products=args.products,
                    packages=args.packages,
                    vulnerabilities=args.vulnerabilities,
                ),
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
