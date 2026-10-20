"""HTTP presentation of explicit discovery/enrichment plans and exact job requests."""

import json
import sys
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4

from dtvp.api_contract import API_PREFIX

FORMAT = "dtvp.vulnerability-request/1"


def configure_intelligence(add_command):
    for name, description in (
        ("discover", "Discover vulnerability claims for selected SBOM packages using OSV"),
        ("enrich", "Enrich known vulnerability IDs using advisory sources"),
    ):
        command = add_command(name, help=description)
        actions = command.add_subparsers(dest="intelligence_action", required=True)
        plan = actions.add_parser(
            "plan", help="Inspect eligible inputs; optionally capture a request file"
        )
        plan.add_argument("--project", required=True, help="Product ID")
        plan.add_argument("--offset", type=int, default=0)
        plan.add_argument("--json", action="store_true")
        plan.add_argument(
            "--output", help="Write a new exact request file; requires an explicit selection"
        )
        if name == "discover":
            plan.add_argument(
                "--purl",
                action="append",
                default=[],
                help="Exact versioned PURL to query; repeat up to 20",
            )
        else:
            plan.add_argument("--provider", choices=["nvd", "circl", "euvd", "jvn"])
            plan.add_argument(
                "--id",
                action="append",
                default=[],
                help="Exact vulnerability ID to enrich; repeat up to 20",
            )
            plan.add_argument("--q", default="")
        queue = actions.add_parser(
            "queue", help="Submit an unchanged captured request; replay safely after uncertainty"
        )
        queue.add_argument("--project", required=True)
        queue.add_argument("--file", required=True)
        jobs = actions.add_parser(
            "jobs", help="List jobs or inspect one job's progress and capture result"
        )
        jobs.add_argument("--project", required=True)
        jobs.add_argument("--job", help="Exact job ID to inspect")
        jobs.add_argument("--offset", type=int, default=0)
        jobs.add_argument("--json", action="store_true")


def run_intelligence(client, args):
    from dtvp.knowledge.client import read_response

    discovery = args.knowledge_command == "discover"
    root = f"{API_PREFIX}/projects/{quote(args.project, safe='')}"
    jobs = root + ("/osv-jobs" if discovery else "/advisory-jobs")
    if args.intelligence_action == "queue":
        with Path(args.file).open("rb") as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("Request file exceeds 1 MiB")
        capture = json.loads(raw)
        if (
            not isinstance(capture, dict)
            or capture.get("format") != FORMAT
            or capture.get("project_id") != args.project
            or capture.get("operation") != args.knowledge_command
            or not isinstance(capture.get("input"), dict)
        ):
            raise ValueError("Captured request does not match this product and operation")
        print(
            f"Submitting captured {args.knowledge_command} request. If uncertain, rerun with the same file; do not prepare a replacement.",
            file=sys.stderr,
        )
        result = read_response(client.post(jobs, json=capture["input"]))
        print(json.dumps(result, indent=2))
        print(
            f"Next: {args.knowledge_command} jobs --project {args.project} --job {result['id']}. Wait for succeeded/current projection before continuing.",
            file=sys.stderr,
        )
        return
    if args.intelligence_action == "jobs":
        path = jobs + ("/" + quote(args.job, safe="") if args.job else "")
        result = read_response(
            client.get(path, params={"offset": args.offset, "limit": 20} if not args.job else {})
        )
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            for job in [result] if args.job else result["items"]:
                print(
                    f"{job['id']}  {job.get('provider', 'osv')}  {job['status']}  {job.get('error') or ''}".rstrip()
                )
                if job.get("result"):
                    print(json.dumps(job["result"], indent=2))
            if not args.job and result.get("next_offset") is not None:
                print(f"Next offset: {result['next_offset']}")
            print(
                "After completed discovery: enrich plan. After enrichment: workspace, assessment, review; no approval is automatic."
            )
        return
    selected = args.purl if discovery else args.id
    if args.output and (not 1 <= len(selected) <= 20 or len(set(selected)) != len(selected)):
        raise ValueError("Capture requires 1–20 distinct explicit package/ID selections")
    if args.output and not discovery and not args.provider:
        raise ValueError("Enrichment capture requires --provider")
    params = {"offset": args.offset, "limit": 20}
    if not discovery:
        params.update({"q": args.q, **({"provider": args.provider} if args.provider else {})})
    result = read_response(
        client.get(root + ("/osv-matching" if discovery else "/advisory-refresh"), params=params)
    )
    if args.output:
        provider = (
            result
            if discovery
            else next((item for item in result["providers"] if item["id"] == args.provider), {})
        )
        if (
            not provider.get("enabled")
            or ("query" if discovery else "refresh") not in result["capabilities"]
        ):
            raise ValueError("Provider disabled or evidence permission unavailable")
        payload = {
            "request_id": str(uuid4()),
            "expected_versions": result["expected_versions"],
            "expected_evidence": result["expected_evidence"],
            "revision": provider["next_revision"],
            **(
                {"purls": sorted(selected)}
                if discovery
                else {"provider": args.provider, "identifiers": sorted(selected)}
            ),
        }
        capture = {
            "format": FORMAT,
            "project_id": args.project,
            "operation": args.knowledge_command,
            "input": payload,
        }
        # Exclusive creation prevents accidentally replacing an uncertain request.
        with Path(args.output).open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(capture, indent=2) + "\n")
        print(
            f"Captured {len(selected)} selections in {args.output}. Submit with {args.knowledge_command} queue --project {args.project} --file {args.output}.",
            file=sys.stderr,
        )
    if args.json:
        print(json.dumps(result, indent=2))
        return
    if discovery:
        print(
            f"OSV {'enabled' if result['enabled'] else 'disabled'} · {result['total']} eligible package versions"
        )
        print("Coverage: " + json.dumps(result["coverage"], sort_keys=True))
    else:
        for provider in result["providers"]:
            print(
                f"{provider['id']}  {'enabled' if provider['enabled'] else 'disabled'}  {provider['publisher']}"
            )
        print(f"{result['total']} known IDs eligible for the selected provider/filter")
        if not result["total"]:
            print(
                "OSV may report GHSA IDs; CVE aliases are not automatically converted into enrichment targets."
            )
    for value in result["purls" if discovery else "identifiers"]:
        print(value)
    if result.get("next_offset") is not None:
        print(f"Next offset: {result['next_offset']}")
    for limitation in result["limitations"]:
        print("Limit: " + limitation)
