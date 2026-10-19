"""Create synthetic parallel-version integration evidence through HTTP only."""

import argparse
import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx

from dtvp.api_contract import API_PREFIX

ROOT = Path(__file__).resolve().parent.parent
VERSIONS = ("6.15.6", "7.1.1", "7.1.2", "7.2.0")


def checked(response):
    response.raise_for_status()
    return response.json()


def login(client, persona):
    checked(client.post(f"{API_PREFIX}/playground/login", json={"persona": persona}))
    client.headers["X-CSRF-Token"] = client.cookies["dtvp_csrf"]
    if checked(client.get(f"{API_PREFIX}/me")).get("playground") is not True:
        raise ValueError("Refusing writes outside an isolated playground")


def commit(label, parent=None):
    raw = b"tree " + b"0" * 40 + b"\n"
    if parent:
        raw += b"parent " + parent.encode() + b"\n"
    raw += (
        b"author Synthetic <synthetic@example.invalid> 1700000000 +0000\ncommitter Synthetic <synthetic@example.invalid> 1700000000 +0000\n\n"
        + label.encode()
        + b"\n"
    )
    sha = hashlib.sha1(b"commit " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    return sha, base64.b64encode(raw).decode()


def seed(client):
    login(client, "administrator")
    teams = checked(client.get(f"{API_PREFIX}/workspaces"))
    team = next(item["id"] for item in teams if item["name"] == "Platform")
    project = checked(
        client.post(
            f"{API_PREFIX}/projects",
            json={
                "workspace_id": team,
                "name": "[SYNTHETIC] Cascading integrations " + uuid4().hex[:12],
            },
        )
    )["id"]
    path = f"{API_PREFIX}/projects/{project}"
    bom = json.loads((ROOT / "playground/fixtures/release.cdx.json").read_text())
    objects, commits, states, subjects = {}, {}, {}, {}
    parent = None
    for version in VERSIONS:
        identity, raw = commit("Synthetic source " + version, parent)
        objects[identity], commits[version] = raw, identity
        # 6.15.6 deliberately remains a separate source lineage.
        parent = None if version == "6.15.6" else identity
        subjects[version] = (
            "sha256:" + hashlib.sha256(("synthetic-artifact-claim-" + version).encode()).hexdigest()
        )

    def imported(version, *, expected=None, build=1):
        value = checked(
            client.post(
                path + f"/versions/{version}/imports",
                json={
                    "request_id": str(uuid4()),
                    "expected": expected,
                    "source": "synthetic/nightly/" + version,
                    "build_number": build,
                    "occurred_at": datetime.now(UTC).isoformat(),
                    "completeness": "complete",
                    "sbom": bom,
                    "context": {
                        "subject_kind": "build",
                        "subject_digest": subjects[version],
                        "pipeline_run": f"synthetic-{version}-{build}",
                        "analysis_source": {
                            "repository_name": "synthetic/integration-example",
                            "source_commit": commits[version],
                        },
                        "limitations": [
                            "Invented repository, commits, build and artifact claims; no actual software or producer authenticity is verified"
                        ],
                    },
                },
            )
        )
        if value.get("committed") is not True or value.get("projection") != "current":
            raise RuntimeError(
                "Publication uncertain or projection pending; inspect the retained synthetic project"
            )
        return value["updates"][0]["target"]

    for version in VERSIONS:
        states[version] = imported(version)
    events = []
    for source, target in (("7.1.1", "7.1.2"), ("7.1.2", "7.2.0")):
        body = {
            "request_id": str(uuid4()),
            "source": states[source],
            "target": states[target],
            "expected_target": states[target],
            "repository": "synthetic/integration-example",
            "source_commit": commits[source],
            "target_commit": commits[target],
            "target_subject_digest": subjects[target],
            "pipeline_run": f"synthetic-{target}-1",
            "integration_kind": "merge",
            "occurred_at": datetime.now(UTC).isoformat(),
            "rationale": "Synthetic parent-path consistency rehearsal, not authenticated software integration or assessment reuse",
            "git_commit_objects": objects,
        }
        response = checked(client.post(path + "/integration-events", json=body))
        if response.get("committed") is not True or response.get("projection") != "current":
            raise RuntimeError(
                "Integration recording uncertain; do not generate a replacement event"
            )
        states[target] = response["updates"][0]["target"]
        event_id = response["event_id"]
        preview = checked(
            client.post(
                path + f"/integration-events/{event_id}/synchronization-preview",
                json={"target": states[target]},
            )
        )
        if preview["apply_supported"] is not False:
            raise RuntimeError("Synthetic integration unexpectedly permits automatic adoption")
        events.append(
            {
                "source_version": source,
                "target_version": target,
                "event_id": event_id,
                "target_state": states[target],
                "assurance": preview["integration_event"]["git_ancestry"]["verification"],
            }
        )
    before = dict(states)
    identity, raw = commit("Synthetic next nightly", commits["7.2.0"])
    commits["7.2.0"], objects[identity] = identity, raw
    states["7.2.0"] = imported("7.2.0", expected=states["7.2.0"], build=2)
    stale = client.post(
        path + f"/integration-events/{events[-1]['event_id']}/synchronization-preview",
        json={"target": states["7.2.0"]},
    )
    if stale.status_code != 409:
        raise RuntimeError("Changed software unexpectedly reused a stale integration observation")
    for version in VERSIONS:
        current = checked(client.get(path + f"/versions/{version}/inventory"))["state"]
        if current != states[version]:
            raise RuntimeError("Nightly import changed another version's branch")
    return {
        "synthetic": True,
        "project_id": project,
        "events": events,
        "states_before_nightly": before,
        "states_after_nightly": states,
        "stale_integration_rejected": True,
        "workspace_url": f"/?page=Knowledge&k_project={project}&k_version=7.2.0",
        "limitations": [
            "Git commit-object hash/parent consistency only; trees, repository membership, source contents and actual artifact provenance are not verified.",
            "No assessment, review, score or automatic cascading coverage was created.",
            "Each edge requires its own target build and explicit event; later software changes require a new observation.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8900")
    args = parser.parse_args()
    with httpx.Client(base_url=args.url, timeout=60, follow_redirects=False) as client:
        print(json.dumps(seed(client), indent=2))


if __name__ == "__main__":
    main()
