"""The team mapping file, organised by team (ADR 0012).

The file maps each team to what it owns::

    {
      "Core": {
        "aliases": ["DE-Core"],
        "projects": ["stats-srv"],
        "components": ["vp-stats-app", "project:ViewPoint_Product::core"]
      },
      "3P": ["libtiff", "purl::pkg:generic/ffmpeg"],
      "Unknown": "*"
    }

A value is an object with optional ``aliases``, ``projects`` (Dependency-Track
project names) and ``components`` (selectors, see ``dtvp.team_mapping``), or
a string or list of strings meaning ``components``. ``*`` is a component
entry of the team that owns the catch-all.

The matching engine works on selectors: ``selector_mapping`` turns the team
document into ``{selector: [team, *aliases]}``, where a project ``X`` is the
selector ``project::X``. The older format, that selector mapping itself,
still loads unchanged; ``team_config_from_document`` converts it for the
editor, and a save writes the team format.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .team_mapping import normalize_team_values, parse_team_mapping_key

FORMAT_TEAMS = "teams"
FORMAT_SELECTORS = "selectors"
TEAM_FIELDS = ("aliases", "projects", "components")


@dataclass
class TeamEntry:
    name: str
    aliases: list[str] = field(default_factory=list)
    projects: list[str] = field(default_factory=list)
    components: list[str] = field(default_factory=list)

    def document(self) -> dict[str, list[str]]:
        return {
            name: list(getattr(self, name))
            for name in TEAM_FIELDS
            if getattr(self, name)
        }


@dataclass
class TeamConfig:
    teams: list[TeamEntry]
    source_format: str
    warnings: list[str] = field(default_factory=list)

    def document(self) -> dict[str, dict[str, list[str]]]:
        return {team.name: team.document() for team in self.teams}


def is_team_format(document: Any) -> bool:
    """Whether a mapping document is organised by team. Both formats can be
    a string-to-string object, so the team format is recognised by an
    object value or by a team owning ``*`` (``"Unknown": "*"``); a file of
    selector keys has ``*`` as a key instead. A file with neither is read
    as selector keys; DTVP itself always writes objects."""
    if not isinstance(document, dict) or not document:
        return False
    for value in document.values():
        if isinstance(value, dict):
            return True
        if isinstance(value, str) and value.strip() == "*":
            return True
        if isinstance(value, list) and any(
            isinstance(item, str) and item.strip() == "*" for item in value
        ):
            return True
    return False


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        text = str(item).strip() if isinstance(item, str) else ""
        if text and text not in result:
            result.append(text)
    return result


def _team_entry(name: str, value: Any) -> TeamEntry:
    if isinstance(value, dict):
        return TeamEntry(
            name=name,
            aliases=_strings(value.get("aliases")),
            projects=_strings(value.get("projects")),
            components=_strings(value.get("components")),
        )
    return TeamEntry(name=name, components=_strings(value))


def _convert_selector_mapping(document: dict[str, Any]) -> TeamConfig:
    """The old format (selector -> team or [team, *aliases]) by team. A
    selector goes to its primary team; aliases merge. An alias claimed by
    two teams, or naming another team, stays with the first and is dropped
    from the others, with a warning."""
    teams: dict[str, TeamEntry] = {}
    warnings: list[str] = []
    for key, value in document.items():
        tags = normalize_team_values(value)
        if not tags:
            continue
        primary, aliases = tags[0], tags[1:]
        team = teams.get(primary.lower())
        if team is None:
            team = teams[primary.lower()] = TeamEntry(name=primary)
        for alias in aliases:
            if alias.lower() != team.name.lower() and alias not in team.aliases:
                team.aliases.append(alias)
        selector = parse_team_mapping_key(key)
        text = str(key).strip()
        if selector.project_fallback and selector.project:
            if selector.project not in team.projects:
                team.projects.append(selector.project)
        elif text not in team.components:
            team.components.append(text)

    owner_of: dict[str, str] = {team.name.lower(): team.name for team in teams.values()}
    for team in teams.values():
        kept: list[str] = []
        for alias in team.aliases:
            owner = owner_of.get(alias.lower())
            if owner is not None and owner != team.name:
                if alias.lower() in teams:
                    warnings.append(
                        f"Alias {alias!r} of team {team.name!r} is the name of team "
                        f"{owner!r}; dropped from {team.name!r}"
                    )
                else:
                    warnings.append(
                        f"Alias {alias!r} is listed for teams {owner!r} and "
                        f"{team.name!r}; kept for {owner!r}"
                    )
                continue
            owner_of[alias.lower()] = team.name
            kept.append(alias)
        team.aliases = kept
    return TeamConfig(list(teams.values()), FORMAT_SELECTORS, warnings)


def team_config_from_document(document: Any) -> TeamConfig:
    """The team configuration of a mapping document of either format."""
    if not isinstance(document, dict):
        return TeamConfig([], FORMAT_TEAMS)
    if is_team_format(document):
        return TeamConfig(
            [_team_entry(str(name).strip(), value) for name, value in document.items()],
            FORMAT_TEAMS,
        )
    return _convert_selector_mapping(document)


def team_config_errors(document: Any) -> list[str]:
    """Why a team-format document cannot be saved: malformed values,
    invalid selectors, a selector, project or ``*`` owned by two teams, and
    aliases that name another team or another team's alias."""
    if not isinstance(document, dict):
        return ["Team mapping must be a JSON object"]
    errors: list[str] = []
    teams: list[TeamEntry] = []
    for raw_name, value in document.items():
        name = str(raw_name).strip()
        if not name:
            errors.append("A team name is empty")
            continue
        if isinstance(value, dict):
            unknown = [key for key in value if key not in TEAM_FIELDS]
            if unknown:
                errors.append(
                    f"Team {name!r}: unknown field {unknown[0]!r}; "
                    "use aliases, projects and components"
                )
            for field_name in TEAM_FIELDS:
                items = value.get(field_name, [])
                if not isinstance(items, list) or not all(
                    isinstance(item, str) for item in items
                ):
                    errors.append(f"Team {name!r}: {field_name} must be a list of strings")
        elif not isinstance(value, str) and not (
            isinstance(value, list) and all(isinstance(item, str) for item in value)
        ):
            errors.append(
                f"Team {name!r}: the value must be an object, a selector or a list of selectors"
            )
        teams.append(_team_entry(name, value))

    team_names: dict[str, str] = {}
    for team in teams:
        if team.name.lower() in team_names:
            errors.append(
                f"Teams {team_names[team.name.lower()]!r} and {team.name!r} differ only by case"
            )
        team_names.setdefault(team.name.lower(), team.name)

    alias_owner: dict[str, str] = {}
    selector_owner: dict[str, str] = {}
    project_owner: dict[str, str] = {}
    wildcard_owner: Optional[str] = None
    for team in teams:
        for alias in team.aliases:
            lowered = alias.lower()
            if lowered == team.name.lower():
                continue
            if lowered in team_names:
                errors.append(
                    f"Alias {alias!r} of team {team.name!r} is the name of team "
                    f"{team_names[lowered]!r}"
                )
            elif lowered in alias_owner and alias_owner[lowered] != team.name:
                errors.append(
                    f"Alias {alias!r} is listed for teams {alias_owner[lowered]!r} "
                    f"and {team.name!r}"
                )
            alias_owner.setdefault(lowered, team.name)

        projects = list(team.projects)
        for component in team.components:
            if component == "*":
                if wildcard_owner is not None and wildcard_owner != team.name:
                    errors.append(
                        f"'*' is owned by teams {wildcard_owner!r} and {team.name!r}; "
                        "at most one team owns it"
                    )
                wildcard_owner = wildcard_owner or team.name
                continue
            selector = parse_team_mapping_key(component)
            if selector.error:
                errors.append(f"Team {team.name!r}: selector {component!r}: {selector.error}")
                continue
            if selector.project_fallback and selector.project:
                projects.append(selector.project)
                continue
            owner = selector_owner.get(component)
            if owner is not None and owner != team.name:
                errors.append(
                    f"Selector {component!r} is listed under teams {owner!r} and {team.name!r}"
                )
            selector_owner.setdefault(component, team.name)
        for project in projects:
            if "::" in project and project.lower().startswith("project"):
                errors.append(
                    f"Team {team.name!r}: project {project!r}: give the project name only"
                )
            owner = project_owner.get(project.lower())
            if owner is not None and owner != team.name:
                errors.append(
                    f"Project {project!r} is listed under teams {owner!r} and {team.name!r}"
                )
            project_owner.setdefault(project.lower(), team.name)
    return errors


def selector_mapping(document: Any) -> dict[str, Any]:
    """The selector mapping the matching engine reads:
    ``{selector: team}`` or ``{selector: [team, *aliases]}``; a project
    ``X`` is the selector ``project::X``. A document in the older selector
    format is returned as it is."""
    if not isinstance(document, dict):
        return {}
    if not is_team_format(document):
        return document
    mapping: dict[str, Any] = {}
    for name, value in document.items():
        team = _team_entry(str(name).strip(), value)
        if not team.name:
            continue
        tags: Any = [team.name, *[a for a in team.aliases if a.lower() != team.name.lower()]]
        if len(tags) == 1:
            tags = team.name
        for component in team.components:
            mapping.setdefault(component, tags)
        for project in team.projects:
            mapping.setdefault(f"project::{project}", tags)
    return mapping
