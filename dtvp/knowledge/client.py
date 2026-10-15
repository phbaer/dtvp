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
    request = commands.add_parser("request", help="Read or mutate API resources using JSON")
    request.add_argument("method", choices=["GET", "POST", "PUT"])
    request.add_argument("path", help="Absolute /api/v3/ path; query parameters supported")
    request.add_argument("--body", help="JSON filename, or - for standard input")


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
            f"team={row['context'].get('team_id') or 'unresolved'} "
            f"state={row['coverage']['status']}  source={source_text} contextual={score_text}"
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
        if args.knowledge_command == "workspace":
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
