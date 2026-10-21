"""HTTP-only team administration; authorization remains on the server."""

import json
from typing import get_args
from urllib.parse import quote

from dtvp.api_contract import API_PREFIX
from dtvp.schemas import MemberInput, WorkspaceInput


def configure_teams(parser):
    commands = parser.add_subparsers(dest="teams_command")
    listing = commands.add_parser("list", help="List accessible teams (also: teams)")
    listing.add_argument("--json", action="store_true")
    create = commands.add_parser("create", help="Create a team as organization administrator")
    create.add_argument("--name", required=True)
    create.add_argument("--json", action="store_true")
    members = commands.add_parser("members", help="List a team's current member mappings")
    members.add_argument("--team", required=True, help="Team ID from teams")
    members.add_argument("--json", action="store_true")
    assign = commands.add_parser(
        "assign", help="Add a member or replace their complete role assignment"
    )
    assign.add_argument("--team", required=True, help="Team ID from teams")
    assign.add_argument("--issuer", required=True, help="Verified OIDC issuer")
    assign.add_argument("--subject", required=True, help="Verified OIDC subject")
    assign.add_argument("--name", required=True, help="Display name for a new user")
    assign.add_argument(
        "--role",
        required=True,
        action="append",
        choices=get_args(get_args(MemberInput.model_fields["roles"].annotation)[0]),
        help="Complete replacement roles; repeat for multiple roles",
    )
    assign.add_argument("--json", action="store_true")


def run_teams(client, args):
    from dtvp.knowledge.client import read_response

    command = args.teams_command
    if command == "list":
        result = read_response(client.get(f"{API_PREFIX}/workspaces"))
    elif command == "create":
        payload = WorkspaceInput(name=args.name).model_dump()
        result = read_response(client.post(f"{API_PREFIX}/workspaces", json=payload))
    else:
        path = f"{API_PREFIX}/workspaces/{quote(args.team, safe='')}/members"
        if command == "members":
            result = read_response(client.get(path))
        else:
            payload = MemberInput(
                issuer=args.issuer,
                subject=args.subject,
                name=args.name,
                roles=list(dict.fromkeys(args.role)),
            ).model_dump()
            result = read_response(client.put(path, json=payload))
    if args.json:
        print(json.dumps(result, indent=2))
    elif command in {"list", "create"}:
        for team in [result] if command == "create" else result:
            print(f"{team['id']}  {team['name']}")
        if not result:
            print("No results.")
    elif command == "members":
        for member in result:
            print(
                f"{member['user_id']}  {member['name']}  "
                f"issuer={member['issuer']}  subject={member['subject']}  "
                f"roles={','.join(member['roles']) or 'none'}"
            )
        if not result:
            print("No members.")
    else:
        print(f"Membership saved: {result['user_id']}  roles={','.join(result['roles'])}")
