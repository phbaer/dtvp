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

from dtvp.api_contract import API_PREFIX

ROOT = Path(__file__).resolve().parent.parent
VERSION = "7.1.1"
BASE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
VECTOR = BASE + "/MAV:P/MAC:H/MPR:H/MUI:R/MC:N/MI:N/MA:N"


def checked(response):
    response.raise_for_status()
    return response.json()


def login(client, persona):
    checked(client.post(f"{API_PREFIX}/playground/login", json={"persona": persona}))
    client.headers["X-CSRF-Token"] = client.cookies["dtvp_csrf"]
    if checked(client.get(f"{API_PREFIX}/me")).get("playground") is not True:
        raise ValueError("Refusing rehearsal writes outside an isolated playground")


def rehearse(client, *, simulate_reviews=False, keep_observations=False, output=None):
    """Use backend workflows only; return a report and exact consumer artifact bytes."""
    login(client, "administrator")
    teams = checked(client.get(f"{API_PREFIX}/workspaces"))
    platform = next(item["id"] for item in teams if item["name"] == "Platform")
    project = checked(
        client.post(
            f"{API_PREFIX}/projects",
            json={
                "workspace_id": platform,
                "name": "[SYNTHETIC] Pipeline rehearsal " + uuid4().hex[:12],
            },
        )
    )["id"]
    path = f"{API_PREFIX}/projects/{project}"
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

    def publication(endpoint, payload, method="POST"):
        # Keep a recoverable exact declaration before a possibly uncertain publication.
        record(
            f"request-{len(steps):02d}",
            {"endpoint": endpoint, "method": method, "payload": payload},
        )
        result = checked(client.request(method, endpoint, json=payload))
        steps.append({"endpoint": endpoint, "method": method, "result": result})
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
    # CI owns these declared source relationships/model entities; no authenticity claim.
    model = {
        "model_id": "synthetic-architecture",
        "revision": "rehearsal-1",
        "entities": [
            {"entity_id": "network-stack", "name": "Synthetic network stack", "external": False},
            {"entity_id": "parser", "name": "Synthetic parser", "external": False},
        ],
    }
    model_raw = (json.dumps(model, sort_keys=True, indent=2) + "\n").encode()
    retain("synthetic-threat-model.json", model_raw)
    configuration = publication(
        path + "/pipeline-config",
        {
            "request_id": str(uuid4()),
            "expected_policy": None,
            "expected_versions": {},
            "reason": "Synthetic CI-owned part roles and model mappings; not authenticated model evidence",
            "parts": [
                {
                    "part_id": "application",
                    "authority_source": "synthetic/application",
                    "observation_sources": ["synthetic/binary-scan"],
                },
                {
                    "part_id": "container",
                    "authority_source": "synthetic/container",
                    "observation_sources": [],
                },
            ],
            "models": [{**model, "digest_sha256": hashlib.sha256(model_raw).hexdigest()}],
            "mappings": [
                {
                    "mapping_id": "http-placement",
                    "component_selector": "demo-http",
                    "model_id": model["model_id"],
                    "entity_ids": ["network-stack"],
                    "legacy_names": ["Synthetic network stack"],
                },
                {
                    "mapping_id": "parser-placement",
                    "component_selector": "demo-parser",
                    "model_id": model["model_id"],
                    "entity_ids": ["parser"],
                    "legacy_names": ["Synthetic parser"],
                },
            ],
        },
        method="PUT",
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
            "expected_configuration": configuration,
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
        "expected_configuration": configuration,
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
    authority = initial
    authority_inventory = checked(
        client.get(product + "/inventory", params={"expected": authority, "limit": 200})
    )
    observed = copy.deepcopy(document)
    observed["components"][0]["description"] = "Synthetic binary scanner supplemental evidence"
    observed["components"].append(
        {
            "type": "library",
            "bom-ref": "scanner-only",
            "name": "Synthetic scanner-only library",
            "version": "1",
            "purl": "pkg:generic/scanner-only@1",
        }
    )
    observed["dependencies"][0]["dependsOn"].append("scanner-only")
    observed["dependencies"].append({"ref": "scanner-only", "dependsOn": []})
    observation_states, observation_files, selection_states = [], [], []
    source_state = None
    selected_head = authority
    for build in (1, 2):
        observed["components"][0]["licenses"] = [
            {"license": {"id": "Apache-2.0" if build == 1 else "BSD-3-Clause"}}
        ]
        observed["components"][0]["description"] = (
            f"Synthetic scanner supplemental evidence revision {build}"
        )
        raw = (json.dumps(observed, ensure_ascii=False, indent=2) + "\n").encode()
        name = f"observation-{build}.cdx.json"
        retain(name, raw)
        artifact = hashlib.sha256(raw).hexdigest()
        declaration = {
            "format": "dtvp.subject-declaration/1",
            "product_id": project,
            "version": VERSION,
            "part_id": "application",
            "subject_id": "synthetic-processing-delivery",
            "build_id": "synthetic-integration",
            "authority_sbom_sha256": hashlib.sha256(files["application.cdx.json"]).hexdigest(),
            "observation_sbom_sha256": artifact,
        }
        metadata = {
            "request_id": str(uuid4()),
            "source": "synthetic/binary-scan",
            "part_id": "application",
            "expected": source_state,
            "expected_authority": selected_head,
            "expected_configuration": configuration,
            "build_number": build,
            "occurred_at": datetime.now(UTC).isoformat(),
            "subject_declaration": declaration,
        }
        record(f"observation-{build}-import-metadata", metadata)
        response = checked(
            client.post(
                product + "/observation-files",
                data={"metadata": json.dumps(metadata)},
                files={"file": (name, raw, "application/json")},
            )
        )
        if response.get("committed") is not True or response.get("projection") != "current":
            raise RuntimeError("Observation import uncertain; inspect exact retained metadata")
        source_state = response["updates"][0]["target"]
        observation_states.append(source_state)
        observation_files.append((artifact, raw))
        selection = {
            "request_id": str(uuid4()),
            "expected": selected_head,
            "expected_configuration": configuration,
            "sources": [
                {"source": "synthetic/binary-scan", "part_id": "application", "state": source_state}
            ],
        }
        proposal = record(
            f"observation-{build}-preview",
            checked(client.post(product + "/observation-selection/preview", json=selection)),
        )
        kernel = proposal["reports"][0]["report"]
        if kernel["subject_assurance"] != "producer_declared" or not any(
            item["observation_ref"] == "scanner-only" for item in kernel["component_proposals"]
        ):
            raise RuntimeError(
                "Synthetic overlap failed to retain declared assurance or explicit unknown-component proposal"
            )
        selected_head = publication(
            product + "/observation-selection",
            {**selection, "preview_digest": proposal["preview_digest"]},
        )
        selection_states.append(selected_head)
        inventory = checked(
            client.get(product + "/inventory", params={"expected": selected_head, "limit": 200})
        )
        if len(inventory["items"]) != len(authority_inventory["items"]) or any(
            item["component"]["name"] == "Synthetic scanner-only library"
            for item in inventory["items"]
        ):
            raise RuntimeError("Observation silently duplicated or adopted inventory")
        record(
            f"observation-{build}-licenses",
            checked(client.get(path + f"/states/{selected_head}/license-worklist")),
        )
    record(
        "observation-evidence-comparison",
        checked(
            client.get(
                path + "/compare/details",
                params={
                    "before": selection_states[0],
                    "after": selection_states[1],
                    "limit": 200,
                },
            )
        ),
    )
    historical_observation = record(
        "selected-observation-summary",
        checked(client.get(path + f"/states/{selected_head}/evidence-summary")),
    )
    withdrawal = {
        "request_id": str(uuid4()),
        "expected": selected_head,
        "expected_configuration": configuration,
        "sources": [],
        "removal_reason": "Synthetic explicit observation withdrawal; retained history remains available",
    }
    withdrawal_preview = record(
        "observation-withdrawal-preview",
        checked(client.post(product + "/observation-selection/preview", json=withdrawal)),
    )
    if keep_observations:
        initial = selected_head
    else:
        initial = publication(
            product + "/observation-selection",
            {**withdrawal, "preview_digest": withdrawal_preview["preview_digest"]},
        )
        selection_states.append(initial)
    if (
        bool(checked(client.get(product + "/observation-selection"))["selection"]["sources"])
        != keep_observations
    ):
        raise RuntimeError("Observation selection did not retain the requested playground state")
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
    if "pipeline-context.json" not in prepared["files"]:
        raise RuntimeError("VScorer input omitted pinned pipeline mappings")
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
    bundle = json.loads(files["issued-bundle.json"])
    if bundle.get("pipeline_context", {}).get("configuration_state") != configuration:
        raise RuntimeError("Issued native bundle omitted its exact pipeline configuration")
    if (
        checked(client.get(path + f"/states/{selection_states[1]}/evidence-summary"))
        != historical_observation
    ):
        raise RuntimeError("Withdrawing an observation changed retained historical evidence")
    for artifact, raw in observation_files:
        response = client.get(path + f"/states/{initial}/artifacts/{artifact}")
        response.raise_for_status()
        if response.content != raw:
            raise RuntimeError("Observation replacement/withdrawal lost original source bytes")
    record("publication-receipts", steps)
    report = {
        "format": "dtvp.pipeline-rehearsal/1",
        "synthetic": True,
        "simulated_reviews": simulate_reviews,
        "project_id": project,
        "version": VERSION,
        "initial_state": initial,
        "authority_state": authority,
        "pipeline_configuration": configuration,
        "observation_states": observation_states,
        "selection_states": selection_states,
        "overlap": {
            "subject_assurance": "producer_declared",
            "inventory_implicitly_adopted": False,
            "withdrawn": not keep_observations,
            "historical_source_bytes_verified": len(observation_files),
        },
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
        "--keep-observations",
        action="store_true",
        help="Keep selected scanner evidence visible for interactive exploration; withdrawal remains a preview",
    )
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
        report, _ = rehearse(
            client,
            simulate_reviews=args.simulate_reviews,
            keep_observations=args.keep_observations,
            output=args.output,
        )
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
