"""HTTP-only CLI presentation; workflow decisions live in the application."""

import json
import math
import os
import sys
import textwrap
from pathlib import Path

import httpx

from dtvp.api_contract import API_PREFIX

WORKSPACE_FILTERS = (
    "ssvc_status",
    "ssvc_action",
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
    "criticality",
    "exposure",
    "support_status",
    "metadata_status",
    "agentyzer_evidence",
    "vscorer_evidence",
)


def archive_request(client, archive, endpoint, *, params=None, metadata_header=None):
    """Bounded exact-byte transport only; the server owns archive interpretation."""
    from stat import S_ISREG

    from dtvp.knowledge.legacy_archive import MAX_COMPRESSED

    path = Path(archive)
    metadata = path.stat()
    if not S_ISREG(metadata.st_mode) or metadata.st_size > MAX_COMPRESSED:
        raise ValueError("Legacy archive requires a regular file no larger than 64 MiB")
    headers = {"Content-Type": "application/zip"}
    if metadata_header is not None:
        headers["X-DTVP-Migration"] = metadata_header
    with path.open("rb") as source:
        opened = os.fstat(source.fileno())
        if not S_ISREG(opened.st_mode) or opened.st_size > MAX_COMPRESSED:
            raise ValueError("Opened legacy archive exceeds the regular-file upload bound")

        def chunks():
            total = 0
            while chunk := source.read(64 * 1024):
                total += len(chunk)
                if total > MAX_COMPRESSED:
                    raise ValueError("Legacy archive grew beyond the 64 MiB upload bound")
                yield chunk

        return read_response(
            client.post(endpoint, params=params, headers=headers, content=chunks())
        )


def configure(parser):
    command = parser.add_parser("knowledge", help="Use the journal-backed HTTP API")
    command.add_argument("--url", default=os.getenv("DTVP_URL", "http://127.0.0.1:8900"))
    command.add_argument("--token-env", default="DTVP_API_TOKEN")
    command.add_argument(
        "--session-env",
        help="Environment variable holding an existing administrator session cookie (instead of a bearer token)",
    )
    command.add_argument(
        "--csrf-env", default="DTVP_CSRF_TOKEN", help="CSRF environment variable for --session-env"
    )
    command.add_argument("--persona", help="Synthetic playground login only")
    command.add_argument(
        "--timeout", type=float, default=60, help="HTTP timeout in seconds (default: 60)"
    )
    commands = command.add_subparsers(
        dest="knowledge_command", required=True, metavar="COMMAND", title="main commands"
    )
    advanced = commands.add_parser(
        "advanced", help="Integration, configuration and diagnostic tools"
    )
    specialist = advanced.add_subparsers(
        dest="knowledge_command", required=True, metavar="COMMAND", title="advanced commands"
    )
    primary = {
        "projects",
        "versions",
        "teams",
        "workspace",
        "vulnerability",
        "tree",
        "portfolio",
        "assessment",
        "review",
        "score",
        "import-file",
        "history",
        "compare",
        "licenses",
        "demo",
        "discover",
        "enrich",
    }

    def add_command(name, **kwargs):
        target = commands if name in primary else specialist
        result = target.add_parser(name, **kwargs)
        if target is specialist:
            # Keep existing scripts working without listing legacy spellings in help.
            commands.choices[name] = result
        return result

    from dtvp.knowledge.intelligence_client import configure_intelligence

    configure_intelligence(add_command)

    projects = add_command("projects", help="List accessible projects and their IDs")
    projects.add_argument("--q", default="", help="Search project names")
    projects.add_argument("--workspace", default="", help="Filter by workspace/team ID")
    projects.add_argument("--cursor", default="", help="Continue from the displayed cursor")
    projects.add_argument("--limit", type=int, default=25)
    projects.add_argument("--json", action="store_true")
    versions = add_command("versions", help="List version branches and release tags")
    versions.add_argument("--project", required=True)
    versions.add_argument("--offset", type=int, default=0)
    versions.add_argument("--limit", type=int, default=50)
    versions.add_argument("--json", action="store_true")
    tokens = add_command("tokens", help="Create, list and revoke your CI/consumer access tokens")
    token_commands = tokens.add_subparsers(dest="tokens_command", required=True)
    token_create = token_commands.add_parser(
        "create", help="Issue a scoped token using an administrator session"
    )
    token_create.add_argument("--workspace", required=True, help="Issuing team ID")
    token_create.add_argument("--name", required=True)
    token_create.add_argument(
        "--profile", choices=["ci-import", "ci-evidence", "read-only"], default="ci-import"
    )
    token_create.add_argument("--days", type=int, default=365)
    token_create.add_argument(
        "--project",
        action="append",
        default=[],
        help="Restrict to product ID; repeat for more products",
    )
    token_list = token_commands.add_parser("list", help="List your tokens without exposing secrets")
    token_list.add_argument("--json", action="store_true")
    token_revoke = token_commands.add_parser("revoke", help="Revoke a token immediately")
    token_revoke.add_argument("id", help="Token ID from tokens list")
    teams = add_command("teams", help="List accessible workspaces/teams and their IDs")
    teams.add_argument("--json", action="store_true")
    demo = add_command("demo", help="Load explicit synthetic playground scenario data")
    demo_commands = demo.add_subparsers(dest="demo_command", required=True)
    loader = demo_commands.add_parser(
        "load", help="Load a versioned JSON fixture without resetting work"
    )
    loader.add_argument("--file", required=True, help="Editable dtvp.demo-scenario/1 JSON file")
    assess = add_command("assessment", help="Save or submit an exact scoped assessment")
    assess_commands = assess.add_subparsers(dest="assessment_command", required=True)
    for name in ("draft", "submit"):
        action = assess_commands.add_parser(name)
        action.add_argument("--project", required=True)
        action.add_argument("--id", required=True, help="Logical assessment identifier")
        action.add_argument(
            "--file", required=True, help="Exact AssessmentInput JSON, including pins"
        )
    review = add_command("review", help="Submit exact independent approval/change request")
    review.add_argument("--project", required=True)
    review.add_argument(
        "--file", required=True, help="Exact ReviewInput JSON, including revision and pins"
    )
    score = add_command("score", help="Read policies or explicitly preview/publish scoring")
    score_commands = score.add_subparsers(dest="score_command", required=True)
    for name in ("policy", "preview", "publish"):
        action = score_commands.add_parser(name)
        action.add_argument("--project", required=True)
        action.add_argument(
            "--file",
            required=name != "policy",
            help="Exact JSON request, including current pins and publication preview digest",
        )
        if name != "policy":
            action.add_argument("--rules", action="store_true", help="Use configured rule scoring")
    for name in ("observation-import", "observation-selection", "observation-sources"):
        resource = add_command(name, help="Use pinned observation intake and explicit selection")
        resource.add_argument("--project", required=True)
        resource.add_argument("--version", required=True)
        if name != "observation-sources":
            resource.add_argument("--input", required=True, help="Exact request metadata JSON")
        if name == "observation-import":
            resource.add_argument(
                "--file", required=True, help="Original SBOM bytes (up to 32 MiB)"
            )
        elif name == "observation-selection":
            resource.add_argument(
                "--apply",
                action="store_true",
                help="Publish the explicit selection; default is preview",
            )
        else:
            resource.add_argument("--offset", type=int, default=0)
            resource.add_argument("--limit", type=int, default=50)
    for name in ("pipeline-config", "synchronization-policy"):
        resource = add_command(name, help="Read or explicitly replace pinned configuration")
        resource.add_argument("--project", required=True)
        resource.add_argument("--input", help="Exact PUT request JSON; omitted for read-only GET")
    context = add_command("pipeline-context", help="Read pinned resolved model mappings")
    for name in ("project", "state", "configuration"):
        context.add_argument("--" + name, required=True)
    context.add_argument("--offset", type=int, default=0)
    context.add_argument("--limit", type=int, default=200)
    automatic = add_command(
        "synchronization-jobs", help="Read or explicitly retry/cancel automatic proposals"
    )
    automatic.add_argument("--project", required=True)
    automatic.add_argument("--job")
    automatic.add_argument("--action", choices=("proposal", "retry", "cancel"))
    automatic.add_argument("--offset", type=int, default=0)
    automatic.add_argument("--limit", type=int, default=50)
    identity = add_command("identity-matches", help="Compare pinned component identity candidates")
    identity.add_argument("--project", required=True)
    identity.add_argument("--source", required=True)
    identity.add_argument("--target", required=True)
    identity.add_argument("--offset", type=int, default=0)
    identity.add_argument("--limit", type=int, default=50)
    identity.add_argument("--json", action="store_true")
    workspace = add_command("workspace", help="Show contextual findings and review status")
    workspace.add_argument("--work-scope", choices=("all", "my_teams", "unassigned", "conflicts"))
    workspace.add_argument("--project", required=True)
    workspace.add_argument("--version", required=True)
    for option in ("team", "q", "lifecycle", "expected"):
        workspace.add_argument("--" + option, default="")
    for option in WORKSPACE_FILTERS:
        workspace.add_argument("--" + option.replace("_", "-"), default="")
    workspace.add_argument("--offset", type=int, default=0)
    workspace.add_argument("--limit", type=int, default=50)
    workspace.add_argument("--json", action="store_true")
    workspace.add_argument(
        "--show-context",
        action="store_true",
        help="Print full context IDs for detailed vulnerability inspection",
    )
    finding = add_command(
        "vulnerability", help="Show source, analysis and CPE contributions for one context"
    )
    finding.add_argument("--project", required=True)
    finding.add_argument("--version", required=True)
    finding.add_argument("--context", required=True)
    finding.add_argument("--id", required=True, help="Exact vulnerability identifier")
    finding.add_argument("--expected", help="Pin the expected version head")
    finding.add_argument("--json", action="store_true")
    tree = add_command("tree", help="Print a pinned, bounded dependency tree")
    tree.add_argument("--project", required=True)
    selection = tree.add_mutually_exclusive_group(required=True)
    selection.add_argument(
        "--version", help="Resolve this version once, then read its pinned state"
    )
    selection.add_argument("--state", help="Read an exact retained state")
    tree.add_argument("--root", help="Browse a component's subtree by its source reference")
    tree.add_argument("--depth", type=int, default=3)
    tree.add_argument("--offset", type=int, default=0)
    tree.add_argument("--limit", type=int, default=100)
    tree.add_argument("--json", action="store_true")
    portfolio = add_command("portfolio", help="Show project statistics across current versions")
    portfolio.add_argument("--work-scope", choices=("all", "my_teams", "unassigned", "conflicts"))
    portfolio.add_argument("--project", required=True)
    portfolio.add_argument(
        "--version", action="append", help="Select version; repeat for multiple versions"
    )
    portfolio.add_argument("--expected-heads")
    for option in ("team", "q", "lifecycle"):
        portfolio.add_argument("--" + option, default="")
    for option in WORKSPACE_FILTERS:
        portfolio.add_argument("--" + option.replace("_", "-"), default="")
    portfolio.add_argument("--json", action="store_true")
    for name in ("refs", "history", "compare"):
        resource = add_command(name, help="Read pinned product " + name)
        resource.add_argument("--project", required=True)
        resource.add_argument("--offset", type=int, default=0)
        resource.add_argument("--limit", type=int, default=50)
        resource.add_argument("--json", action="store_true")
        if name == "history":
            resource.add_argument("--version", default="")
        if name == "compare":
            resource.add_argument("--before", required=True)
            resource.add_argument("--after", required=True)
    sync = add_command("synchronization", help="Preview assessment reuse without applying changes")
    for name in ("project", "source", "target"):
        sync.add_argument("--" + name, required=True)
    sync.add_argument("--basis")
    sync.add_argument("--mapping", help="JSON file mapping exact source/target context IDs")
    sync.add_argument("--offset", type=int, default=0)
    sync.add_argument("--limit", type=int, default=50)
    sync.add_argument("--json", action="store_true")
    adopted = add_command(
        "correspondence-draft", help="Preview or explicitly create a linked target draft"
    )
    adopted.add_argument("--project", required=True)
    adopted.add_argument("--input", required=True, help="Exact JSON preview or apply request")
    adopted.add_argument("--apply", action="store_true", help="Publish one new unsubmitted draft")
    coverage = add_command(
        "coverage", help="Compare explicit assessment targets across current versions"
    )
    for name in ("project", "state", "context", "vulnerability"):
        coverage.add_argument("--" + name, required=True)
    coverage.add_argument("--expected-preview")
    coverage.add_argument("--version-from")
    coverage.add_argument("--version-through")
    coverage.add_argument("--include-version", action="append", default=[])
    coverage.add_argument("--exclude-version", action="append", default=[])
    coverage.add_argument("--offset", type=int, default=0)
    coverage.add_argument("--limit", type=int, default=50)
    coverage.add_argument("--json", action="store_true")
    intelligence = add_command(
        "compare-intelligence", help="Compare pinned composition with selected advisory evidence"
    )
    for name in ("project", "state"):
        intelligence.add_argument("--" + name, required=True)
    selection = intelligence.add_mutually_exclusive_group(required=True)
    selection.add_argument("--evidence-state")
    selection.add_argument("--no-evidence", action="store_true")
    intelligence.add_argument("--expected-digest")
    intelligence.add_argument("--offset", type=int, default=0)
    intelligence.add_argument("--limit", type=int, default=50)
    intelligence.add_argument("--json", action="store_true")
    archive = add_command(
        "legacy-archive-preview", help="Inspect an exported v1 ZIP without restoring it"
    )
    archive.add_argument("--project", required=True)
    archive.add_argument("--archive", required=True)
    archive.add_argument("--offset", type=int, default=0)
    archive.add_argument("--limit", type=int, default=25)
    archive.add_argument("--json", action="store_true")
    publication = add_command(
        "legacy-archive-publication",
        help="Preview or explicitly publish one reviewed sanitized v1 version",
    )
    for option in ("project", "version", "archive", "input"):
        publication.add_argument("--" + option, required=True)
    publication.add_argument(
        "--apply", action="store_true", help="Publish the exact reviewed preview explicitly"
    )
    quality = add_command("input-quality", help="Inspect pinned producer input observations")
    for name in ("project", "state"):
        quality.add_argument("--" + name, required=True)
    for name in ("q", "code"):
        quality.add_argument("--" + name, default="")
    quality.add_argument("--offset", type=int, default=0)
    quality.add_argument("--limit", type=int, default=50)
    quality.add_argument("--json", action="store_true")
    licenses = add_command("licenses", help="Browse pinned license evidence and approvals")
    for name in ("project", "state"):
        licenses.add_argument("--" + name, required=True)
    for name in ("q", "evidence-status", "review-status", "approved-disposition"):
        licenses.add_argument("--" + name, default="")
    licenses.add_argument("--offset", type=int, default=0)
    licenses.add_argument("--limit", type=int, default=50)
    licenses.add_argument("--json", action="store_true")
    summary = add_command(
        "evidence-summary", help="Read pinned pipeline evidence counts without a release verdict"
    )
    for name in ("project", "state"):
        summary.add_argument("--" + name, required=True)
    summary.add_argument("--json", action="store_true")
    document = add_command(
        "document-register", help="Register exact generated bytes against issued inputs"
    )
    for name in ("project", "version", "file", "metadata"):
        document.add_argument("--" + name, required=True)
    document.add_argument("--submit", action="store_true", help="Submit for independent review")
    evidence = add_command(
        "evidence-import", help="Preview or import exact VDR/VEX/advisory JSON file bytes"
    )
    for name in ("project", "file", "metadata"):
        evidence.add_argument("--" + name, required=True)
    evidence.add_argument("--preview", action="store_true", help="Read-only semantic scope preview")
    request = add_command("request", help="Read or mutate API resources using JSON")
    request.add_argument("method", choices=["GET", "POST", "PUT"])
    request.add_argument("path", help=f"Absolute {API_PREFIX}/ path; query parameters supported")
    request.add_argument("--body", help="JSON filename, or - for standard input")
    upload = add_command("import-file", help="Import original SBOM bytes with explicit metadata")
    upload.add_argument("--project", required=True, help="Product ID or exact product name")
    upload.add_argument("--workspace", help="Workspace ID for product selection or creation")
    upload.add_argument("--version", required=True)
    upload.add_argument(
        "--part", help="Import a constituent without advancing the product baseline"
    )
    upload.add_argument("--file", required=True)
    upload.add_argument(
        "--metadata",
        help="Optional JSON overrides; defaults use the current source, next sequence and upload time",
    )


def read_response(response):
    if response.status_code == 204:
        return None
    if response.is_error:
        try:
            detail = response.json().get("detail", response.reason_phrase)
        except ValueError:
            detail = response.reason_phrase
        raise ValueError(f"HTTP {response.status_code}: {detail}")
    return response.json()


def display_workspace(result, *, show_context=False):
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
        if show_context:
            print(f"  context={row['context_id']}")
        if (ssvc := row.get("ssvc")) and ssvc.get("status") != "missing":
            print(
                f"  ssvc={ssvc['status']} current={(ssvc.get('current') or {}).get('outcome_label') or 'Incomplete'} "
                f"approved={(ssvc.get('approved') or {}).get('outcome_label') or 'Not approved'}"
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


def display_vulnerability(result):
    """Render the backend's classification without inferring adoption or validity."""

    def plain(value):
        return " ".join("".join(char if char.isprintable() else " " for char in str(value)).split())

    def entries(title, values):
        print(f"\n{title} ({len(values)})")
        if not values:
            print("  None recorded.")
            return
        for item in values:
            label = plain(item["label"])
            label = label if len(label) <= 24 else label[:23] + "…"
            status = plain(item["status"]).replace("_", " ")
            status = status if len(status) <= 20 else status[:19] + "…"
            summary = plain(item["summary"])
            if item.get("adoption", {}).get("status") == "referenced":
                summary += " · Cited in an assessment (not proof of adoption)."
            if item.get("diagnostics"):
                diagnostics = item["diagnostics"]
                summary += " · " + "; ".join(
                    plain(value).replace("_", " ") for value in diagnostics[:2]
                )
                if len(diagnostics) > 2:
                    summary += f" (+{len(diagnostics) - 2} more; --json)"
            prefix = f"  {label:24} {status:20} "
            print(
                textwrap.fill(
                    summary, width=116, initial_indent=prefix, subsequent_indent=" " * len(prefix)
                )
            )

    component = result["component"]
    print(
        f"{plain(result['vulnerability_id'])} · {plain(component.get('name') or component.get('bom-ref', 'Unknown component'))} {plain(component.get('version') or '')}"
    )
    print(f"State: {result['state']}\nContext: {result['context_id']}")
    score = result.get("published_score")
    score_text = str(score["score"]) if score else "Not published"
    if score and score.get("current") is False:
        score_text += " (outdated)"
    print(
        f"Source severity: {plain(result.get('source_severity', 'unknown'))} · Published: {score_text} · Assessment: {plain(result.get('coverage', {}).get('status', 'unknown'))}"
    )
    contributions = result.get("contributions")
    if contributions is None:
        raise ValueError("Server did not supply vulnerability contributions; update the server")
    entries("Vulnerability sources", contributions["vulnerability_sources"])
    entries("Vulnerability analyses", contributions["vulnerability_analyses"])
    cpe = contributions["cpe"]
    print("\nCPE identification")
    present = False
    for key, title in (
        ("declared", "Declared CPEs"),
        ("curated", "Configured mappings"),
        ("accepted", "Accepted CPEs"),
        ("candidates", "CPE candidates"),
    ):
        if cpe[key]:
            entries(title, cpe[key])
            present = True
    if not present:
        print("  No declarations, configured mappings or candidates recorded.")
    for diagnostic in cpe["diagnostics"]:
        print(
            textwrap.fill(plain(diagnostic), width=116, initial_indent="  ", subsequent_indent="  ")
        )
    print("\nEvidence and proposals do not approve assessments; citations do not prove adoption.")
    print("Use --json for full facts, record references, artifact hashes, provenance and limits.")


def display_tree(result):
    print(f"Dependency tree · {result['version']} · State: {result['state']}")
    if result.get("dependency_graph") != "reported":
        print(
            "Declared dependency graph unavailable or incomplete; isolated rows do not imply no dependencies."
        )
    if result["items"] and result["items"][0]["depth"]:
        print("Page starts beneath: " + " → ".join(result["items"][0]["path"][:-1]))
    for row in result["items"]:
        component = row["component"]
        name = component.get("name") or row["component_ref"]
        version = f" @{component['version']}" if component.get("version") else ""
        markers = [key for key in ("cycle", "shared", "missing") if row[key]]
        if row["child_count"] and row["depth"] == result["max_depth"] and not markers:
            markers.append("depth limit; browse --root " + row["component_ref"])
        suffix = " · " + ", ".join(markers) if markers else ""
        print(
            f"{'  ' * row['depth']}{'└─ ' if row['depth'] else ''}{name}{version} "
            f"[{row['component_ref']}] · {row['vulnerability_count']} vulnerabilities{suffix}"
        )
    print(
        f"Rows {result['offset']}..{result['offset'] + len(result['items'])} of {result['total']}"
    )
    if result["next_offset"] is not None:
        print(f"Next offset: {result['next_offset']} (pin --state {result['state']})")
    if result["truncated"]:
        print(f"Traversal limited to {result['row_limit']} rows; browse a specific --root.")
    for limitation in result["limitations"]:
        print(limitation)


def run(args):
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise ValueError("HTTP timeout must be a positive finite number of seconds")
    headers = {}
    token = os.getenv(args.token_env)
    session = os.getenv(args.session_env) if args.session_env else None
    if args.session_env:
        if args.persona or token:
            raise ValueError(
                "Use only one authentication method: session, bearer token or playground persona"
            )
        if not session or not os.getenv(args.csrf_env):
            raise ValueError("Session and CSRF environment variables must both be populated")
        headers["X-CSRF-Token"] = os.environ[args.csrf_env]
    if token:
        headers["Authorization"] = "Bearer " + token
    with httpx.Client(
        base_url=args.url,
        headers=headers,
        cookies={"dtvp_session": session} if session else None,
        timeout=args.timeout,
        follow_redirects=False,
    ) as client:
        if args.persona:
            if token:
                raise ValueError("Use either a machine credential or a playground persona")
            read_response(
                client.post(API_PREFIX + "/playground/login", json={"persona": args.persona})
            )
            client.headers["X-CSRF-Token"] = client.cookies["dtvp_csrf"]
        if args.knowledge_command in {"discover", "enrich"}:
            from dtvp.knowledge.intelligence_client import run_intelligence

            run_intelligence(client, args)
            return
        if args.knowledge_command == "tokens":
            if args.tokens_command == "create":
                if not (session or args.persona):
                    raise ValueError(
                        "Token creation requires an administrator session (--session-env), or a playground --persona; CI tokens cannot mint tokens"
                    )
                if not 1 <= args.days <= 3650:
                    raise ValueError("Token lifetime must be between 1 and 3650 days")
                profiles = {
                    "ci-import": ["read", "write"],
                    "ci-evidence": ["read", "write", "evidence"],
                    "read-only": ["read"],
                }
                print(
                    "Secret returned once on stdout. Do not log it. If the response is lost, list and revoke the unconfirmed token before creating another.",
                    file=sys.stderr,
                )
                result = read_response(
                    client.post(
                        f"{API_PREFIX}/credentials",
                        json={
                            "workspace_id": args.workspace,
                            "name": args.name,
                            "capabilities": profiles[args.profile],
                            "projects": args.project,
                            "hours": args.days * 24,
                        },
                    )
                )
                print(json.dumps(result, indent=2))
            elif args.tokens_command == "revoke":
                from urllib.parse import quote

                read_response(client.delete(f"{API_PREFIX}/credentials/{quote(args.id, safe='')}"))
                print("Token revoked.")
            else:
                result = read_response(client.get(f"{API_PREFIX}/credentials"))
                if args.json:
                    print(json.dumps(result, indent=2))
                else:
                    for credential in result:
                        print(
                            f"{credential['id']}  {credential['name']}  expires={credential['expires_at']}  revoked={credential['revoked']}  capabilities={','.join(credential['capabilities'])}  projects={','.join(credential['projects']) or 'all accessible team products'}"
                        )
                    if not result:
                        print("No tokens.")
            return
        if args.knowledge_command in {"projects", "versions", "teams"}:
            from urllib.parse import quote

            if args.knowledge_command == "projects":
                result = read_response(
                    client.get(
                        API_PREFIX + "/catalog/projects",
                        params={
                            "q": args.q,
                            "workspace_id": args.workspace,
                            "cursor": args.cursor,
                            "limit": args.limit,
                        },
                    )
                )
            elif args.knowledge_command == "versions":
                result = read_response(
                    client.get(
                        f"{API_PREFIX}/projects/{quote(args.project, safe='')}/refs",
                        params={"offset": args.offset, "limit": args.limit},
                    )
                )
            else:
                result = read_response(client.get(API_PREFIX + "/workspaces"))
            if args.json:
                print(json.dumps(result, indent=2))
                return
            items = result if isinstance(result, list) else result["items"]
            if not items:
                print("No results.")
            for item in items:
                if args.knowledge_command == "versions":
                    print(
                        f"{item['name']}  {item['kind']}  version={item['version']}  state={item['state']}"
                    )
                else:
                    print(
                        f"{item['id']}  {item['name']}"
                        + (
                            f"  team={item['workspace']}  versions={item['version_count']}"
                            if args.knowledge_command == "projects"
                            else ""
                        )
                    )
            if isinstance(result, dict):
                if result.get("next_cursor") is not None:
                    print(f"Next cursor: {result['next_cursor']} (continue with --cursor)")
                if result.get("next_offset") is not None:
                    print(f"Next offset: {result['next_offset']} (continue with --offset)")
            return
        if args.knowledge_command == "vulnerability":
            from urllib.parse import quote

            path = f"{API_PREFIX}/projects/{quote(args.project, safe='')}/versions/{quote(args.version, safe='')}/workspace/{quote(args.context, safe='')}/{quote(args.id, safe='')}"
            result = read_response(
                client.get(path, params={"expected": args.expected} if args.expected else {})
            )
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                display_vulnerability(result)
            return
        if args.knowledge_command == "tree":
            from urllib.parse import quote

            base = f"{API_PREFIX}/projects/{quote(args.project, safe='')}"
            state = args.state
            if args.version:
                selection = read_response(
                    client.get(
                        base + f"/versions/{quote(args.version, safe='')}/inventory",
                        params={"limit": 1},
                    )
                )
                state = selection.get("reference_state", selection["state"])
                if not state:
                    raise ValueError("Version has no current journal head")
            params = {"max_depth": args.depth, "offset": args.offset, "limit": args.limit}
            if args.root is not None:
                params["root_ref"] = args.root
            result = read_response(
                client.get(base + f"/states/{quote(state, safe='')}/dependency-tree", params=params)
            )
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                display_tree(result)
            return
        if args.knowledge_command == "demo":
            from dtvp.knowledge.demo_scenarios import MAX_SCENARIO_BYTES

            if not args.persona:
                raise ValueError(
                    "Demo loading requires --persona for a synthetic playground session"
                )
            with Path(args.file).open("rb") as stream:
                raw = stream.read(MAX_SCENARIO_BYTES + 1)
            if len(raw) > MAX_SCENARIO_BYTES:
                raise ValueError("Demo scenario exceeds 32 MiB")
            value = json.loads(raw)
            print(
                json.dumps(
                    read_response(
                        client.post(API_PREFIX + "/playground/knowledge/load", json=value)
                    ),
                    indent=2,
                )
            )
            return
        if args.knowledge_command in {"score", "assessment", "review"}:
            from urllib.parse import quote

            path = f"{API_PREFIX}/projects/{quote(args.project, safe='')}"
            payload = None
            if args.file:
                with Path(args.file).open("rb") as stream:
                    raw = stream.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise ValueError("Workflow request exceeds the CLI 1 MiB transport bound")
                payload = json.loads(raw)
                if not isinstance(payload, dict):
                    raise ValueError("Workflow request must be a JSON object")
            if args.knowledge_command == "assessment":
                path += f"/assessments/{quote(args.id, safe='')}/{args.assessment_command}"
                response = client.post(path, json=payload)
            elif args.knowledge_command == "review":
                response = client.post(path + "/reviews", json=payload)
            elif args.score_command == "policy":
                path += "/scoring-policy"
                response = client.put(path, json=payload) if args.file else client.get(path)
            else:
                path += "/scoring/" + ("rules/" if args.rules else "") + args.score_command
                response = client.post(path, json=payload)
            print(json.dumps(read_response(response), indent=2))
            return
        if args.knowledge_command in {
            "observation-import",
            "observation-selection",
            "observation-sources",
        }:
            from stat import S_ISREG
            from urllib.parse import quote

            path = f"{API_PREFIX}/projects/{quote(args.project, safe='')}/versions/{quote(args.version, safe='')}"
            if args.knowledge_command == "observation-sources":
                response = client.get(
                    path + "/observation-sources",
                    params={"offset": args.offset, "limit": args.limit},
                )
            else:
                metadata = json.loads(Path(args.input).read_text())
                if not isinstance(metadata, dict):
                    raise ValueError("Observation metadata must be a JSON object")
                if args.knowledge_command == "observation-selection":
                    response = client.post(
                        path + "/observation-selection" + ("" if args.apply else "/preview"),
                        json=metadata,
                    )
                else:
                    with Path(args.file).open("rb") as source:
                        if not S_ISREG(os.fstat(source.fileno()).st_mode):
                            raise ValueError("Observation requires a regular SBOM file")
                        raw = source.read(32 * 1024 * 1024 + 1)
                    if len(raw) > 32 * 1024 * 1024:
                        raise ValueError("Observation exceeds the CLI 32 MiB transport bound")
                    response = client.post(
                        path + "/observation-files",
                        data={"metadata": json.dumps(metadata)},
                        files={"file": (Path(args.file).name, raw, "application/octet-stream")},
                    )
            print(json.dumps(read_response(response), indent=2))
            return
        if args.knowledge_command in {
            "pipeline-config",
            "synchronization-policy",
            "pipeline-context",
            "synchronization-jobs",
        }:
            from urllib.parse import quote

            path = f"{API_PREFIX}/projects/{quote(args.project, safe='')}"
            if args.knowledge_command in {"pipeline-config", "synchronization-policy"}:
                path += "/" + args.knowledge_command
                response = (
                    client.put(path, json=json.loads(Path(args.input).read_text()))
                    if args.input
                    else client.get(path)
                )
            elif args.knowledge_command == "pipeline-context":
                response = client.get(
                    path + f"/states/{quote(args.state, safe='')}/pipeline-context",
                    params={
                        "configuration": args.configuration,
                        "offset": args.offset,
                        "limit": args.limit,
                    },
                )
            else:
                if args.action and not args.job:
                    raise ValueError("A synchronization action requires --job")
                path += "/synchronization-jobs"
                if args.job:
                    path += "/" + quote(args.job, safe="")
                if args.action:
                    path += "/" + args.action
                response = (
                    client.post(path)
                    if args.action in {"retry", "cancel"}
                    else client.get(path, params={"offset": args.offset, "limit": args.limit})
                )
            print(json.dumps(read_response(response), indent=2))
            return
        if args.knowledge_command == "identity-matches":
            from urllib.parse import quote

            path = f"{API_PREFIX}/projects/{quote(args.project, safe='')}/states/{quote(args.target, safe='')}/identity-matches"
            result = read_response(
                client.get(
                    path, params={"source": args.source, "offset": args.offset, "limit": args.limit}
                )
            )
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"Identity report: {result['report_digest']}")
                print(
                    f"Matched: {result['summary']['matched']} · Unresolved: {result['summary']['unresolved']}"
                )
                for row in result["items"]:
                    print(f"{row['basis']}: {row['source_id']} -> {row['target_id']}")
                for row in result.get("unresolved", []):
                    print(f"Unresolved {row['current_ref']}: {row['reason']}")
                if result.get("diagnostics_truncated"):
                    print("Unresolved diagnostics truncated; summary counts are complete.")
                if result.get("next_offset") is not None:
                    print(f"Next offset: {result['next_offset']}")
                print(
                    "Read-only: inventory, contextual coverage and human approvals are unchanged."
                )
            return
        if args.knowledge_command == "legacy-archive-preview":
            from urllib.parse import quote

            result = archive_request(
                client,
                args.archive,
                f"{API_PREFIX}/projects/{quote(args.project, safe='')}/migration/v1-archive/preview",
                params={"offset": args.offset, "limit": args.limit},
            )
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"Preview: {result['preview_digest']} · Source versions: {result['total']}")
                print("Statistics: " + json.dumps(result["statistics"], sort_keys=True))
                for row in result["items"]:
                    print(
                        f"Entry {row['entry_index']} {row['source_entry_id']} · Normalization: {row['normalization']['status']}"
                    )
                    for loss in row["losses"]:
                        print("  Loss: " + loss)
                for limitation in result["limitations"]:
                    print("Limit: " + limitation)
                if result.get("next_offset") is not None:
                    print(f"Next offset: {result['next_offset']} (resubmit the identical archive)")
            return
        if args.knowledge_command == "legacy-archive-publication":
            from stat import S_ISREG
            from urllib.parse import quote

            from dtvp.knowledge.legacy_archive import strict_json
            from dtvp.knowledge.legacy_archive_migration import MAX_HEADER

            path = Path(args.input)
            metadata_stat = path.stat()
            if not S_ISREG(metadata_stat.st_mode) or metadata_stat.st_size > MAX_HEADER:
                raise ValueError("Migration metadata requires a regular file within 8 KiB")
            with path.open("rb") as stream:
                opened = os.fstat(stream.fileno())
                if not S_ISREG(opened.st_mode) or opened.st_size > MAX_HEADER:
                    raise ValueError("Opened migration metadata exceeds its upload bound")
                raw = stream.read(MAX_HEADER + 1)
            if len(raw) > MAX_HEADER:
                raise ValueError("Migration metadata file exceeds 8 KiB")
            metadata = strict_json(raw)
            if not isinstance(metadata, dict):
                raise ValueError("Migration metadata must be a JSON object")
            header = json.dumps(metadata, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
            if len(header) > MAX_HEADER:
                raise ValueError("ASCII migration metadata header exceeds 8 KiB")
            endpoint = (
                f"{API_PREFIX}/projects/{quote(args.project, safe='')}/versions/{quote(args.version, safe='')}/migration/v1-archive/"
                + ("apply" if args.apply else "preview")
            )
            result = archive_request(client, args.archive, endpoint, metadata_header=header)
            print(json.dumps(result, indent=2))
            return
        if args.knowledge_command == "evidence-summary":
            from urllib.parse import quote

            result = read_response(
                client.get(
                    f"{API_PREFIX}/projects/{quote(args.project, safe='')}/states/{quote(args.state, safe='')}/evidence-summary"
                )
            )
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"State: {result['state']} · Evidence summary: {result['summary_digest']}")
                for section in (
                    "inventory",
                    "vulnerabilities",
                    "licenses",
                    "documents",
                    "retained",
                ):
                    print(section + ": " + json.dumps(result[section], sort_keys=True))
                for limitation in result["limitations"]:
                    print(f"Limit [{limitation['code']}]: {limitation['description']}")
            return
        if args.knowledge_command == "licenses":
            from urllib.parse import quote

            result = read_response(
                client.get(
                    f"{API_PREFIX}/projects/{quote(args.project, safe='')}/states/{quote(args.state, safe='')}/license-worklist",
                    params={
                        name: getattr(args, name)
                        for name in (
                            "q",
                            "evidence_status",
                            "review_status",
                            "approved_disposition",
                            "offset",
                            "limit",
                        )
                    },
                )
            )
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"State: {result['state']} · Matching components: {result['total']}")
                print("Selection statistics: " + json.dumps(result["statistics"], sort_keys=True))
                for row in result["items"]:
                    review = row["license_review"]
                    approved = review.get("approved_assessment") if review.get("approved") else None
                    disposition = approved["payload"]["disposition"] if approved else "missing"
                    print(
                        f"{row['component_ref']}  {row['component'].get('name') or ''}  source={row['evidence']['status']} review={review['status']} approved_disposition={disposition}"
                    )
                if result.get("next_offset") is not None:
                    print(f"Next offset: {result['next_offset']} (same --state {result['state']})")
            return
        if args.knowledge_command == "input-quality":
            from urllib.parse import quote

            result = read_response(
                client.get(
                    f"{API_PREFIX}/projects/{quote(args.project, safe='')}/states/{quote(args.state, safe='')}/input-quality",
                    params={
                        "q": args.q,
                        "code": args.code,
                        "offset": args.offset,
                        "limit": args.limit,
                    },
                )
            )
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                counts = result["statistics"]
                print(f"State: {result['state']} · Input report: {result['report_digest']}")
                print(
                    f"Occurrences: {counts['occurrences']} · Roles: {json.dumps(counts['by_role'], sort_keys=True)}"
                )
                print(
                    f"All observations: {counts['issues']} · Matching observations: {result['total']}"
                )
                for source in result["sources"]:
                    print(
                        f"Source: {source['id']} · producer coverage: {json.dumps(source['collection'], sort_keys=True)} (not verified)"
                    )
                for item in result["items"]:
                    print(
                        f"{item['code']}  component={item.get('component_ref') or 'none'} source={item.get('source_id') or 'unresolved'}  {json.dumps(item['details'], sort_keys=True)}"
                    )
                for limitation in result["limitations"]:
                    print("Limit: " + limitation)
                if result.get("next_offset") is not None:
                    print(f"Next offset: {result['next_offset']} (same --state {result['state']})")
            return
        if args.knowledge_command == "portfolio":
            from urllib.parse import quote

            params = {"q": args.q, "lifecycle": args.lifecycle}
            params.update(
                {name: getattr(args, name) for name in WORKSPACE_FILTERS if getattr(args, name)}
            )
            if args.version:
                params["version"] = args.version
            if args.work_scope:
                params["work_scope"] = args.work_scope
            if args.team:
                params["team_id"] = args.team
            if args.expected_heads:
                params["expected_heads"] = args.expected_heads
            result = read_response(
                client.get(
                    f"{API_PREFIX}/projects/{quote(args.project, safe='')}/portfolio", params=params
                )
            )
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                counts = result["statistics"]
                print(f"Heads: {result['heads_digest']} · Versions: {len(result['heads'])}")
                print(
                    f"Context findings: {counts['context_findings']} · Unique vulnerabilities: {counts['unique_vulnerabilities']}"
                )
                print(
                    f"Latest logical assessments: {counts['unique_latest_logical_assessments']} · Approved logical assessments: {counts['unique_approved_logical_assessments']}"
                )
                for version, group in result["by_version"].items():
                    work = group["required_context_review_workload"]
                    print(
                        f"{version}  findings={group['context_findings']}  approved targets={work['approved_targets']}/{work['required_targets']}  remaining={work['remaining_targets']}  not assessable={work['not_assessable_targets']}"
                    )
                for team, group in result.get("by_team", {}).items():
                    print(
                        f"team={result.get('team_labels', {}).get(team, team)}  findings={group['context_findings']}  approved targets={group['reviewed_covered_targets']}"
                    )
                for version, facts in result.get("state_evidence", {}).items():
                    coverage = facts["collection_coverage"]
                    print(
                        f"{version}  baseline={facts['baseline_status']}  declared coverage: packages={coverage['package_coverage']}, dependencies={coverage['dependency_coverage']}, licenses={coverage['license_coverage']} (state unfiltered)"
                    )
                for limitation in result.get("limitations", []):
                    print("Limit: " + limitation)
            return
        if args.knowledge_command == "compare-intelligence":
            from urllib.parse import quote

            result = read_response(
                client.post(
                    f"{API_PREFIX}/projects/{quote(args.project, safe='')}/compare/intelligence",
                    params={"offset": args.offset, "limit": args.limit},
                    json={
                        "inventory_state": args.state,
                        "evidence_state": None if args.no_evidence else args.evidence_state,
                        "expected_digest": args.expected_digest,
                    },
                )
            )
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"Report: {result['report_digest']} · Claim groups: {result['total']}")
                print(
                    "Selected evidence currently selected: "
                    + str(result["currentness"]["selected_is_current"])
                )
                print("Statistics: " + json.dumps(result["statistics"], sort_keys=True))
                for row in result["items"]:
                    print(
                        f"{row['vulnerability_id']}  source={row['source']} publisher={row['publisher']}  {row['status']}"
                    )
                for limitation in result["limitations"]:
                    print("Limit: " + limitation)
                if result.get("next_offset") is not None:
                    print(
                        f"Next offset: {result['next_offset']} (same state/evidence pins; --expected-digest {result['report_digest']})"
                    )
            return
        if args.knowledge_command == "coverage":
            from urllib.parse import quote

            result = read_response(
                client.post(
                    f"{API_PREFIX}/projects/{quote(args.project, safe='')}/coverage/candidates",
                    params={"offset": args.offset, "limit": args.limit},
                    json={
                        "source": args.state,
                        "context_id": args.context,
                        "vulnerability_id": args.vulnerability,
                        "expected_preview": args.expected_preview,
                        **(
                            {
                                "version_selection": {
                                    "lower": args.version_from,
                                    "upper": args.version_through,
                                    "include": args.include_version,
                                    "exclude": args.exclude_version,
                                }
                            }
                            if args.version_from
                            or args.version_through
                            or args.include_version
                            or args.exclude_version
                            else {}
                        ),
                    },
                )
            )
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(
                    f"Preview: {result['preview_digest']} · Versions: {result['statistics']['versions']} · Targets: {result['total']}"
                )
                if result.get("version_selection"):
                    for version in result["version_selection"]["versions"]:
                        print(f"Version {version['version']}: {version['status']}")
                    print(result["version_selection"]["semantics"])
                for row in result["items"]:
                    print(
                        f"{row['version']}  context={row['context_id']}  team={row.get('team_id') or 'unresolved'}  "
                        f"coverage={row['coverage']['status']}  comparison={row['classification']}  "
                        f"actions={','.join(row.get('capabilities', [])) or 'read-only'}"
                    )
                print(
                    "Read-only candidates; matching inputs do not grant applicability or reviewed coverage."
                )
                if result.get("next_offset") is not None:
                    print(
                        f"Next offset: {result['next_offset']} (pin --expected-preview {result['preview_digest']})"
                    )
            return
        if args.knowledge_command in {"import-file", "document-register", "evidence-import"}:
            from urllib.parse import quote

            metadata_text = Path(args.metadata).read_text() if args.metadata else "{}"
            metadata = json.loads(metadata_text)
            if not isinstance(metadata, dict):
                raise ValueError("Upload metadata must be a JSON object")
            with Path(args.file).open("rb") as source:
                project_id = args.project
                if args.knowledge_command == "import-file":
                    from stat import S_ISREG

                    if not S_ISREG(os.fstat(source.fileno()).st_mode):
                        raise ValueError("SBOM upload requires a regular file")
                    selection = {"project": args.project}
                    if args.workspace is not None:
                        selection["workspace_id"] = args.workspace
                    project = read_response(
                        client.post(f"{API_PREFIX}/projects/resolve", json=selection)
                    )
                    project_id = project["id"]
                    if project["created"]:
                        print(f"Created product {project['name']} ({project_id})", file=sys.stderr)
                    if any(
                        key not in metadata for key in ("source", "build_number", "occurred_at")
                    ):
                        params = {"version": args.version}
                        if args.part:
                            params["part_id"] = args.part
                        target = read_response(
                            client.get(
                                f"{API_PREFIX}/projects/{quote(project_id, safe='')}/intake-target",
                                params=params,
                            )
                        )
                        if "import" not in target["capabilities"]:
                            raise ValueError(
                                "File import unavailable: " + ", ".join(target["blocked_reasons"])
                            )
                        metadata = {**target["defaults"], "expected": target["state"], **metadata}
                    if "request_id" not in metadata:
                        from uuid import uuid4

                        metadata["request_id"] = str(uuid4())
                    metadata.setdefault("completeness", "complete")
                    if not args.metadata or metadata != json.loads(metadata_text):
                        metadata_text = json.dumps(metadata)
                        print(
                            "Captured import metadata (reuse with --metadata for an exact retry): "
                            + metadata_text,
                            file=sys.stderr,
                        )
                path = f"{API_PREFIX}/projects/{quote(project_id, safe='')}"
                if args.knowledge_command == "evidence-import":
                    path += "/evidence/files" + ("/preview" if args.preview else "")
                else:
                    path += f"/versions/{quote(args.version, safe='')}"
                    if args.knowledge_command == "document-register":
                        path += "/documents/" + ("submit" if args.submit else "draft")
                    else:
                        if args.part:
                            path += f"/parts/{quote(args.part, safe='')}"
                        path += "/files"
                from contextlib import nullcontext

                from dtvp.knowledge.upload_progress import UploadProgress

                progress = (
                    UploadProgress(source, Path(args.file).name)
                    if args.knowledge_command == "import-file"
                    else nullcontext(source)
                )
                with progress as upload:
                    result = read_response(
                        client.post(
                            path,
                            data={
                                "metadata": metadata_text
                                if args.knowledge_command == "import-file"
                                else json.dumps(metadata)
                            },
                            files={
                                "file": (Path(args.file).name, upload, "application/octet-stream")
                            },
                        )
                    )
                    if args.knowledge_command == "import-file":
                        upload.finish(result)
            print(json.dumps(result, indent=2))
            return
        if args.knowledge_command == "correspondence-draft":
            from urllib.parse import quote

            body = json.loads(Path(args.input).read_text())
            if not isinstance(body, dict):
                raise ValueError("Correspondence draft input must be a JSON object")
            path = f"{API_PREFIX}/projects/{quote(args.project, safe='')}/correspondence-drafts"
            result = read_response(
                client.post(path + ("" if args.apply else "/preview"), json=body)
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
                    f"{API_PREFIX}/projects/{quote(args.project, safe='')}/synchronization/preview",
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
            path = f"{API_PREFIX}/projects/{quote(args.project, safe='')}/{suffix}"
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

            path = f"{API_PREFIX}/projects/{quote(args.project, safe='')}/versions/{quote(args.version, safe='')}/workspace"
            params = {
                "offset": args.offset,
                "limit": args.limit,
                "q": args.q,
                "lifecycle": args.lifecycle,
            }
            params.update(
                {name: getattr(args, name) for name in WORKSPACE_FILTERS if getattr(args, name)}
            )
            if args.work_scope:
                params["work_scope"] = args.work_scope
            if args.team:
                params["team_id"] = args.team
            if args.expected:
                params["expected"] = args.expected
            result = read_response(client.get(path, params=params))
            if not args.json:
                display_workspace(result, show_context=args.show_context)
                return
        else:
            if not args.path.startswith(API_PREFIX + "/") or "\\" in args.path:
                raise ValueError(f"Requests must address {API_PREFIX}/ on the configured server")
            options = {}
            if args.body:
                options["json"] = (
                    json.load(sys.stdin)
                    if args.body == "-"
                    else json.loads(Path(args.body).read_text())
                )
            result = read_response(client.request(args.method, args.path, **options))
        print(json.dumps(result, indent=2))
