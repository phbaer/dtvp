"""Exercise synthetic pipeline intake, optional review simulation and frozen exports.

HTTP only. Never resets existing projects or contacts specialist services.
"""

import argparse
import copy
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx

ROOT = Path(__file__).resolve().parent.parent
VERSION = "7.1.1"
BASE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
VECTOR = BASE + "/MAV:P/MAC:H/MPR:H/MUI:R/MC:N/MI:N/MA:N"


def checked(response):
    response.raise_for_status()
    return response.json()


def login(client, persona):
    checked(client.post("/api/v2/playground/login", json={"persona": persona}))
    client.headers["X-CSRF-Token"] = client.cookies["dtvp_csrf"]
    if checked(client.get("/api/v2/me")).get("playground") is not True:
        raise ValueError("Refusing rehearsal writes outside an isolated playground")


def rehearse(client, *, simulate_reviews=False, output=None):
    """Use backend workflows only; return a report and exact consumer artifact bytes."""
    login(client, "administrator")
    teams = checked(client.get("/api/v2/workspaces"))
    platform = next(item["id"] for item in teams if item["name"] == "Platform")
    project = checked(
        client.post(
            "/api/v2/projects",
            json={
                "workspace_id": platform,
                "name": "[SYNTHETIC] Pipeline rehearsal " + uuid4().hex[:12],
            },
        )
    )["id"]
    path = f"/api/v3/projects/{project}"
    product = path + f"/versions/{VERSION}"
    files = {}
    steps = []

    def retain(name, raw):
        if not name or Path(name).name != name or "/" in name or "\\" in name:
            raise ValueError("Unexpected consumer artifact filename")
        files[name] = raw
        if output is not None:
            with (output / name).open("xb") as stream:
                stream.write(raw)

    def record(name, value):
        retain(name + ".json", (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode())
        return value

    record(
        "session",
        {
            "synthetic": True,
            "project_id": project,
            "version": VERSION,
            "server": str(client.base_url),
        },
    )

    def workspace():
        return checked(client.get(product + "/workspace", params={"limit": 200}))

    def publication(endpoint, payload):
        # Keep a recoverable exact declaration before a possibly uncertain publication.
        record(f"request-{len(steps):02d}", {"endpoint": endpoint, "payload": payload})
        result = checked(client.post(endpoint, json=payload))
        steps.append({"endpoint": endpoint, "result": result})
        if result.get("committed") is not True or result.get("projection") != "current":
            raise RuntimeError(
                "Publication uncertain or projection pending; inspect retained project, do not repin/repeat automatically"
            )
        return result["updates"][0]["target"]

    current = checked(client.get(path + "/ownership"))
    checked(
        client.put(
            path + "/ownership",
            json={
                "request_id": str(uuid4()),
                "expected_policy": current["policy_state"],
                "expected_versions": current["versions"],
                "rules": [{"selector": "*", "team_id": platform}],
                "context_roots": {},
            },
        )
    )
    document = json.loads((ROOT / "playground/fixtures/release.cdx.json").read_text())
    ancillary = copy.deepcopy(document)
    ancillary["metadata"]["component"].update(
        name="Synthetic container layer", **{"bom-ref": "container"}
    )
    ancillary["components"] = [
        {
            "type": "library",
            "bom-ref": "runtime",
            "name": "Synthetic runtime",
            "version": "1",
            "licenses": [{"expression": "MIT"}],
        }
    ]
    ancillary["dependencies"] = [
        {"ref": "container", "dependsOn": ["runtime"]},
        {"ref": "runtime", "dependsOn": []},
    ]
    ancillary["vulnerabilities"] = []
    parts = []
    for name, bom in (("application", document), ("container", ancillary)):
        raw = (json.dumps(bom, ensure_ascii=False, indent=2) + "\n").encode()
        retain(name + ".cdx.json", raw)
        metadata = {
            "request_id": str(uuid4()),
            "expected": None,
            "source": "synthetic/" + name,
            "build_number": 1,
            "occurred_at": datetime.now(UTC).isoformat(),
            "completeness": "complete",
        }
        record(name + "-import-metadata", metadata)
        result = checked(
            client.post(
                product + f"/parts/{name}/files",
                data={"metadata": json.dumps(metadata)},
                files={"file": (name + ".json", raw, "application/json")},
            )
        )
        if result.get("committed") is not True or result.get("projection") != "current":
            raise RuntimeError("Source import uncertain; existing rehearsal project retained")
        parts.append(
            {
                "part_id": name,
                "state": result["updates"][0]["target"],
                "required": True,
                "role": "delivery",
            }
        )
    assembly = {
        "request_id": str(uuid4()),
        "expected": None,
        "parts": parts,
        "coherence": {
            "status": "producer_declared",
            "build_id": "synthetic-integration",
            "rationale": "Synthetic inputs selected by this rehearsal; compatibility not verified",
        },
    }
    preview = record(
        "assembly-preview", checked(client.post(product + "/assembly-preview", json=assembly))
    )
    initial = publication(
        product + "/assembly-apply",
        {"assembly": assembly, "preview_digest": preview["preview_digest"]},
    )
    initial_summary = record(
        "before-review", checked(client.get(path + f"/states/{initial}/evidence-summary"))
    )
    current = workspace()
    row = next(item for item in current["items"] if item["vulnerability_id"] == "CVE-2099-20001")
    selected = {
        "version": VERSION,
        "context_id": row["context_id"],
        "vulnerability_id": row["vulnerability_id"],
    }
    prepared = record(
        "vscorer-input",
        checked(
            client.post(
                path + f"/states/{current['state']}/vscorer-input",
                json={
                    "context_id": row["context_id"],
                    "component_ref": row["context"]["component_ref"],
                    "base_selections": {row["vulnerability_id"]: BASE},
                },
            )
        ),
    )
    if not prepared["eligible"]:
        raise RuntimeError("Synthetic VScorer input is unexpectedly unresolved")
    for name, raw in prepared["files"].items():
        retain("vscorer-" + name, raw.encode())
    login(client, "coordinator")

    def score_input():
        return {
            "request_id": str(uuid4()),
            "expected_versions": {VERSION: workspace()["state"]},
            "targets": [selected],
            "base_vector": BASE,
            "vector": VECTOR,
            "rationale": "Synthetic rehearsal only; no deployment or human acceptance claim",
        }

    blocked = record(
        "scoring-before-review", checked(client.post(path + "/scoring/preview", json=score_input()))
    )
    if blocked["eligible"]:
        raise RuntimeError("Scoring unexpectedly allowed before independent review")
    if simulate_reviews:
        login(client, "analyst")
        assessment_id = str(uuid4())
        publication(
            path + f"/assessments/{assessment_id}/submit",
            {
                "request_id": str(uuid4()),
                "expected_versions": {VERSION: workspace()["state"]},
                "expected_revision": None,
                "targets": [selected],
                "state": "not_affected",
                "justification": "protected_at_runtime",
                "rationale": "SYNTHETIC role simulation; no real reachability or approval evidence",
            },
        )
        current = workspace()
        assessed = next(item for item in current["items"] if item["id"] == row["id"])
        login(client, "reviewer")
        publication(
            path + "/reviews",
            {
                "request_id": str(uuid4()),
                "expected_versions": {VERSION: current["state"]},
                "assessment_id": assessment_id,
                "assessment_revision": assessed["coverage"]["assessment"]["revision"],
                "targets": [selected],
                "action": "approve",
                "rationale": "SYNTHETIC independent-role simulation; not real human acceptance",
            },
        )
        login(client, "coordinator")
        proposal = score_input()
        scoring = record(
            "scoring-after-review", checked(client.post(path + "/scoring/preview", json=proposal))
        )
        if not scoring["eligible"]:
            raise RuntimeError("Reviewed synthetic vulnerability unexpectedly blocked")
        publication(path + "/scoring/publish", {**proposal, "preview": scoring["preview"]})
    login(client, "administrator")
    final = workspace()["state"]
    summary = record(
        "evidence-summary", checked(client.get(path + f"/states/{final}/evidence-summary"))
    )
    issuance = record("issuance", checked(client.post(path + f"/states/{final}/exports/bundle")))
    for name, metadata in issuance["files"].items():
        # Same-origin, project-scoped paths only: never forward a session to supplied URLs.
        expected = path + f"/issued-exports/{issuance['receipt_sha256']}/files/"
        if not metadata["url"].startswith(expected) or "/" in name or "\\" in name:
            raise ValueError("Unexpected issued-file path")
        response = client.get(metadata["url"])
        response.raise_for_status()
        if hashlib.sha256(response.content).hexdigest() != metadata["sha256"]:
            raise ValueError("Issued consumer bytes failed checksum verification")
        retain("issued-" + name, response.content)
    if (
        checked(client.post(path + f"/states/{final}/exports/bundle"))["receipt_sha256"]
        != issuance["receipt_sha256"]
    ):
        raise RuntimeError("Repeated frozen export did not retain its identity")
    if checked(client.get(path + f"/states/{initial}/evidence-summary")) != initial_summary:
        raise RuntimeError("Historical evidence summary changed")
    record("publication-receipts", steps)
    report = {
        "format": "dtvp.pipeline-rehearsal/1",
        "synthetic": True,
        "simulated_reviews": simulate_reviews,
        "project_id": project,
        "version": VERSION,
        "initial_state": initial,
        "final_state": final,
        "summary_digest": summary["summary_digest"],
        "issuance_receipt": issuance["receipt_sha256"],
        "verified_consumer_files": len(issuance["files"]),
        "workspace_url": f"/?page=Knowledge&k_project={project}&k_version={VERSION}",
        "acceptance": "synthetic_contract_rehearsal_only",
        "remaining_gates": [
            "real producer completeness and delivered artifact binding",
            "actual VScorer/Agentyzer service round trip and deployed authentication",
            "Generator customer output parity and independent document acceptance",
            "license specialist decisions; rehearsal creates no license clearance",
            "production OIDC, restore and concurrent workload qualification",
        ],
        "files": {
            name: {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
            for name, raw in sorted(files.items())
        },
    }
    return report, files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8900")
    parser.add_argument(
        "--simulate-reviews",
        action="store_true",
        help="Explicitly simulate independent playground roles; never real human approval",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New local directory for exact rehearsal artifacts",
    )
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    with httpx.Client(base_url=args.url, timeout=60, follow_redirects=False) as client:
        report, _ = rehearse(client, simulate_reviews=args.simulate_reviews, output=args.output)
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
