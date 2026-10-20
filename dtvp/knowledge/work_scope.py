"""Responsibility views, independent of project access and decision permissions."""

from typing import Literal

WorkScope = Literal["all", "my_teams", "unassigned", "conflicts"]


def member_teams(actor):
    """Current applicable memberships, restricted by the current credential."""
    return frozenset(
        team
        for team in actor.memberships
        if actor.workspace(team, "assess") or actor.workspace(team, "approve")
    )


def matches_scope(context, work_scope="all", team_ids=None):
    if work_scope == "my_teams":
        responsible = set(context.get("team_scope", {}))
        if context.get("team_id"):
            responsible.add(context["team_id"])
        return bool(responsible.intersection(team_ids or ()))
    if work_scope == "unassigned":
        return not context.get("candidate_teams") and not context.get("team_id")
    if work_scope == "conflicts":
        return len(context.get("candidate_teams", [])) > 1
    if work_scope != "all":
        raise ValueError("Unknown work scope")
    return True
