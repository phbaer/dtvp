"""HTTP-only CLI presentation; workflow decisions live in the application."""

import json
import os
import sys
from pathlib import Path

import httpx

WORKSPACE_FILTERS = (
    "source_severity",
    "contextual_severity",
    "applicability",
    "scoring_status",
    "team_review",
    "provider",
    "cvss_version",
    "dependency",
    "source_conflict",
    "component",
)


def configure(parser):
    command = parser.add_parser("knowledge", help="Use the journal-backed HTTP API")
    command.add_argument("--url", default=os.getenv("DTVP_URL", "http://127.0.0.1:8900"))
    command.add_argument("--token-env", default="DTVP_API_TOKEN")
    command.add_argument("--persona", help="Synthetic playground login only")
    commands = command.add_subparsers(dest="knowledge_command", required=True)
    workspace = commands.add_parser("workspace", help="Show contextual findings and review status")
    workspace.add_argument("--project", required=True)
    workspace.add_argument("--version", required=True)
    for option in ("team", "q", "lifecycle", "expected"):
        workspace.add_argument("--" + option, default="")
    for option in WORKSPACE_FILTERS:
        workspace.add_argument("--" + option.replace("_", "-"), default="")
    workspace.add_argument("--offset", type=int, default=0)
    workspace.add_argument("--limit", type=int, default=50)
    workspace.add_argument("--json", action="store_true")
    for name in ("refs", "history", "compare"):
        resource = commands.add_parser(name, help="Read pinned product " + name)
        resource.add_argument("--project", required=True)
        resource.add_argument("--offset", type=int, default=0)
        resource.add_argument("--limit", type=int, default=50)
        resource.add_argument("--json", action="store_true")
        if name == "history":
            resource.add_argument("--version", default="")
        if name == "compare":
            resource.add_argument("--before", required=True)
            resource.add_argument("--after", required=True)
    sync = commands.add_parser(
        "synchronization", help="Preview assessment reuse without applying changes"
    )
    for name in ("project", "source", "target"):
        sync.add_argument("--" + name, required=True)
    sync.add_argument("--basis")
    sync.add_argument("--mapping", help="JSON file mapping exact source/target context IDs")
    sync.add_argument("--offset", type=int, default=0)
    sync.add_argument("--limit", type=int, default=50)
    sync.add_argument("--json", action="store_true")
    request = commands.add_parser("request", help="Read or mutate API resources using JSON")
    request.add_argument("method", choices=["GET", "POST", "PUT"])
    request.add_argument("path", help="Absolute /api/v3/ path; query parameters supported")
    request.add_argument("--body", help="JSON filename, or - for standard input")
    upload = commands.add_parser(
        "import-file", help="Import original SBOM bytes with explicit metadata"
    )
    upload.add_argument("--project", required=True)
    upload.add_argument("--version", required=True)
    upload.add_argument(
        "--part", help="Import a constituent without advancing the product baseline"
    )
    upload.add_argument("--file", required=True)
    upload.add_argument(
        "--metadata", required=True, help="JSON metadata file with request ID and expected head"
    )


def read_response(response):
    if response.is_error:
        try:
            detail = response.json().get("detail", response.reason_phrase)
        except ValueError:
            detail = response.reason_phrase
        raise ValueError(f"HTTP {response.status_code}: {detail}")
    return response.json()


def display_workspace(result):
    counts = result["statistics"]
    print(f"State: {result['state']}")
    print(
        f"Context findings: {counts['totals']['context_findings']} · "
        f"Approved: {counts.get('approved', 0)} · Submitted: {counts.get('submitted', 0)}"
    )
    for row in result["items"]:
        source = [
            rating.get("score")
            for rating in row["source_ratings"]
            if isinstance(rating.get("score"), (int, float))
        ]
        contextual = row.get("published_score")
        source_text = str(max(source)) if source else "unknown"
        score_text = str(contextual["score"]) if contextual else "unscored"
        if contextual and not contextual.get("current"):
            score_text += " (outdated)"
        component = row["component"]
        print(
            f"{row['vulnerability_id']}  {component.get('name') or component['bom-ref']} "
            f"{component.get('version') or ''}  root={row['context']['root_ref']} "
            f"team={result.get('team_labels', {}).get(row['context'].get('team_id'), row['context'].get('team_id') or 'unresolved')} "
            f"state={row['coverage']['status']}  source={source_text} contextual={score_text}"
        )
        for claim in row.get("legacy_evidence", []):
            print(
                f"  imported_dt={claim['status']} applicability={claim.get('proposed_applicability') or 'unknown'} (historical claim, not DTVP approval)"
            )
            for proposal in claim.get("scoring_proposals", []):
                print(
                    f"    legacy_score={proposal.get('claimed_score')} preview_usable={proposal.get('usable_for_preview', False)} (requires coordinator publication)"
                )
        metadata = row.get("curated_metadata")
        if metadata:
            context = metadata["payload"]["annotations"]["cybersecurity"]
            print(
                f"  curated={metadata['status']} criticality={context['criticality']} exposure={context['exposure']}"
            )
        for proposal in row.get("scoring_proposals", []):
            value = proposal.get("proposal") or {}
            status = (
                "eligible"
                if proposal.get("eligible")
                else ", ".join(proposal.get("ineligibility_reasons", []))
            )
            print(
                f"  proposal={proposal['id']} provider={proposal['provider']} "
                f"base={value.get('base_score', 'unknown')} score={value.get('score', 'unknown')} "
                f"status={status} (requires coordinator publication)"
            )
        for analysis in row.get("code_analysis", []):
            print(
                f"  analysis={analysis['id']} provider={analysis['provider']} "
                f"current={analysis['current']} verdict={json.dumps(analysis.get('verdict'))} "
                f"assessment_proposal={analysis['application_eligible']} "
                f"scoring_proposal={analysis['rescoring_eligible']} "
                f"blockers={json.dumps(analysis.get('ineligibility_reasons', []))} "
                "(evidence, requires human assessment)"
            )
    if result.get("next_offset") is not None:
        print(f"Next offset: {result['next_offset']} (pin --expected {result['state']})")


def run(args):
    headers = {}
    token = os.getenv(args.token_env)
    if token:
        headers["Authorization"] = "Bearer " + token
    with httpx.Client(
        base_url=args.url, headers=headers, timeout=60, follow_redirects=False
    ) as client:
        if args.persona:
            if token:
                raise ValueError("Use either a machine credential or a playground persona")
            read_response(client.post("/api/v2/playground/login", json={"persona": args.persona}))
            client.headers["X-CSRF-Token"] = client.cookies["dtvp_csrf"]
        if args.knowledge_command == "import-file":
            from urllib.parse import quote

            metadata = json.loads(Path(args.metadata).read_text())
            if not isinstance(metadata, dict):
                raise ValueError("Import metadata must be a JSON object")
            path = f"/api/v3/projects/{quote(args.project, safe='')}/versions/{quote(args.version, safe='')}"
            if args.part:
                path += f"/parts/{quote(args.part, safe='')}"
            with Path(args.file).open("rb") as source:
                result = read_response(
                    client.post(
                        path + "/files",
                        data={"metadata": json.dumps(metadata)},
                        files={"file": (Path(args.file).name, source, "application/octet-stream")},
                    )
                )
            print(json.dumps(result, indent=2))
            return
        if args.knowledge_command == "synchronization":
            from urllib.parse import quote

            body = {"source": args.source, "target": args.target, "basis": args.basis}
            if args.mapping:
                body["context_mapping"] = json.loads(Path(args.mapping).read_text())
            result = read_response(
                client.post(
                    f"/api/v3/projects/{quote(args.project, safe='')}/synchronization/preview",
                    params={"offset": args.offset, "limit": args.limit},
                    json=body,
                )
            )
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(
                    f"Preview: {result['preview_digest']} · {result['mode']} · Total: {result['total']}"
                )
                for row in result["items"]:
                    print(
                        f"{row['category']} {row.get('vulnerability_id', 'unknown')} "
                        f"{row.get('source_context_id', 'unknown')} -> {row.get('target_context_id', 'unknown')}"
                    )
                print("Read-only: target inventory and human approvals are unchanged.")
                if result.get("next_offset") is not None:
                    print(f"Next offset: {result['next_offset']}")
            return
        if args.knowledge_command in {"refs", "history", "compare"}:
            from urllib.parse import quote

            suffix = (
                "compare/details" if args.knowledge_command == "compare" else args.knowledge_command
            )
            path = f"/api/v3/projects/{quote(args.project, safe='')}/{suffix}"
            params = {"offset": args.offset, "limit": args.limit}
            if args.knowledge_command == "history" and args.version:
                params["version"] = args.version
            if args.knowledge_command == "compare":
                params.update(before=args.before, after=args.after)
            result = read_response(client.get(path, params=params))
            if not args.json:
                print(f"Total: {result['total']}")
                for row in result["items"]:
                    if args.knowledge_command == "compare":
                        print(
                            f"{row['category']} {row['key']}: {', '.join(row['classifications'])}"
                        )
                    else:
                        print(
                            f"{row.get('kind', 'state')} {row.get('name', row.get('version'))} {row['state']}"
                        )
                for limitation in result.get("limitations", []):
                    print("Limit: " + limitation)
                if result.get("next_offset") is not None:
                    print(f"Next offset: {result['next_offset']}")
                return
        elif args.knowledge_command == "workspace":
            from urllib.parse import quote

            path = f"/api/v3/projects/{quote(args.project, safe='')}/versions/{quote(args.version, safe='')}/workspace"
            params = {
                "offset": args.offset,
                "limit": args.limit,
                "q": args.q,
                "lifecycle": args.lifecycle,
            }
            params.update(
                {name: getattr(args, name) for name in WORKSPACE_FILTERS if getattr(args, name)}
            )
            if args.team:
                params["team_id"] = args.team
            if args.expected:
                params["expected"] = args.expected
            result = read_response(client.get(path, params=params))
            if not args.json:
                display_workspace(result)
                return
        else:
            if not args.path.startswith("/api/v3/") or "\\" in args.path:
                raise ValueError("Requests must address /api/v3/ on the configured server")
            options = {}
            if args.body:
                options["json"] = (
                    json.load(sys.stdin)
                    if args.body == "-"
                    else json.loads(Path(args.body).read_text())
                )
            result = read_response(client.request(args.method, args.path, **options))
        print(json.dumps(result, indent=2))
