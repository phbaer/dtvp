from __future__ import annotations

from typing import Any

from .team_mapping import normalize_team_values


def _text(value: Any) -> str:
    return str(value or "").strip()


def _team_alias_index(team_mapping: dict[str, Any] | None) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for raw_value in (team_mapping or {}).values():
        values = normalize_team_values(raw_value)
        if not values:
            continue
        primary = values[0]
        for value in values:
            aliases.setdefault(value.lower(), primary)
    return aliases


def configured_team_names(team_mapping: dict[str, Any] | None) -> list[str]:
    """Return canonical configured team names in stable display order."""
    teams: dict[str, str] = {}
    for raw_value in (team_mapping or {}).values():
        values = normalize_team_values(raw_value)
        if not values:
            continue
        teams.setdefault(values[0].lower(), values[0])
    return sorted(teams.values(), key=lambda value: value.lower())


def validate_team_group_config(
    config: dict[str, Any] | None,
    team_mapping: dict[str, Any] | None,
) -> list[str]:
    """Validate explicit team and nested-group membership."""
    if not isinstance(config, dict):
        return ["Team groups must be a JSON object"]

    errors: list[str] = []
    team_aliases = _team_alias_index(team_mapping)
    group_names: dict[str, str] = {}
    definitions: dict[str, dict[str, list[str]]] = {}

    for raw_name, raw_definition in config.items():
        name = _text(raw_name)
        if not name:
            errors.append("Team group names must not be empty")
            continue
        normalized_name = name.lower()
        if normalized_name in group_names:
            errors.append(
                f"Team group names are duplicated case-insensitively: "
                f"{group_names[normalized_name]}, {name}"
            )
            continue
        group_names[normalized_name] = name
        if not isinstance(raw_definition, dict):
            errors.append(f"Team group {name} must be an object")
            continue

        definition: dict[str, list[str]] = {"teams": [], "groups": []}
        for member_type in ("teams", "groups"):
            raw_members = raw_definition.get(member_type, [])
            if not isinstance(raw_members, list):
                errors.append(f"Team group {name}.{member_type} must be an array")
                continue
            seen: set[str] = set()
            for index, raw_member in enumerate(raw_members):
                member = _text(raw_member)
                if not member:
                    errors.append(
                        f"Team group {name}.{member_type}[{index}] must be a "
                        "non-empty string"
                    )
                    continue
                normalized_member = member.lower()
                if normalized_member in seen:
                    errors.append(
                        f"Team group {name}.{member_type} contains duplicate "
                        f"member {member}"
                    )
                    continue
                seen.add(normalized_member)
                definition[member_type].append(member)
        if not definition["teams"] and not definition["groups"]:
            errors.append(f"Team group {name} must contain at least one team or group")
        definitions[normalized_name] = definition

    for normalized_name, definition in definitions.items():
        name = group_names[normalized_name]
        for team in definition["teams"]:
            if team.lower() not in team_aliases:
                errors.append(
                    f"Team group {name} references unknown configured team {team}"
                )
        for child in definition["groups"]:
            if child.lower() not in group_names:
                errors.append(f"Team group {name} references unknown group {child}")

    visiting: list[str] = []
    visited: set[str] = set()

    def visit(group_key: str) -> None:
        if group_key in visited or group_key not in definitions:
            return
        if group_key in visiting:
            cycle_start = visiting.index(group_key)
            cycle = [*visiting[cycle_start:], group_key]
            errors.append(
                "Team group cycle detected: "
                + " -> ".join(group_names[key] for key in cycle)
            )
            return
        visiting.append(group_key)
        for child in definitions[group_key]["groups"]:
            visit(child.lower())
        visiting.pop()
        visited.add(group_key)

    for group_key in definitions:
        visit(group_key)

    return errors


def resolve_team_groups(
    config: dict[str, Any] | None,
    team_mapping: dict[str, Any] | None,
) -> dict[str, list[str]]:
    """Expand nested groups to canonical leaf teams, deduplicated per group."""
    definitions = canonical_team_group_structure(config, team_mapping)
    resolved: dict[str, list[str]] = {}

    def expand(group_name: str) -> list[str]:
        if group_name in resolved:
            return resolved[group_name]
        members: dict[str, str] = {}
        definition = definitions[group_name]
        for team in definition["teams"]:
            members.setdefault(team.lower(), team)
        for child in definition["groups"]:
            for canonical in expand(child):
                members.setdefault(canonical.lower(), canonical)
        resolved[group_name] = list(members.values())
        return resolved[group_name]

    for group_name in definitions:
        expand(group_name)
    return resolved


def canonical_team_group_structure(
    config: dict[str, Any] | None,
    team_mapping: dict[str, Any] | None,
) -> dict[str, dict[str, list[str]]]:
    """Return direct membership with canonical team and group display names."""
    errors = validate_team_group_config(config, team_mapping)
    if errors:
        raise ValueError("; ".join(errors))

    if not config:
        return {}

    team_aliases = _team_alias_index(team_mapping)
    group_names = {
        _text(name).lower(): _text(name)
        for name in config
        if _text(name)
    }
    structure: dict[str, dict[str, list[str]]] = {}
    for raw_name, raw_definition in config.items():
        name = _text(raw_name)
        if not name or not isinstance(raw_definition, dict):
            continue
        teams: dict[str, str] = {}
        for raw_team in raw_definition.get("teams") or []:
            canonical = team_aliases[_text(raw_team).lower()]
            teams.setdefault(canonical.lower(), canonical)
        groups: dict[str, str] = {}
        for raw_group in raw_definition.get("groups") or []:
            child = group_names[_text(raw_group).lower()]
            groups.setdefault(child.lower(), child)
        structure[name] = {
            "teams": list(teams.values()),
            "groups": list(groups.values()),
        }
    return structure
