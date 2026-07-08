from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class ComponentIdentity:
    name: str
    group: Optional[str] = None
    purl: Optional[str] = None
    group_known: bool = False


@dataclass(frozen=True)
class TeamMappingSelector:
    raw_key: str
    name: str = ""
    group: Optional[str] = None
    purl: Optional[str] = None
    require_no_group: bool = False
    case_sensitive: bool = False
    wildcard: bool = False


@dataclass(frozen=True)
class TeamMappingMatch:
    key: str
    value: Any
    selector: TeamMappingSelector
    tags: tuple[str, ...]


def normalize_team_values(value: Any) -> tuple[str, ...]:
    if isinstance(value, list):
        result: list[str] = []
        seen: set[str] = set()
        for tag in value:
            tag_text = str(tag or "").strip()
            if tag_text and tag_text not in seen:
                result.append(tag_text)
                seen.add(tag_text)
        return tuple(result)
    tag_text = str(value or "").strip()
    return (tag_text,) if tag_text else ()


def primary_team(value: Any) -> str:
    tags = normalize_team_values(value)
    return tags[0] if tags else ""


def compile_team_mapping(
    team_mapping: dict[str, Any] | tuple[TeamMappingMatch, ...] | None,
) -> tuple[TeamMappingMatch, ...]:
    if not team_mapping:
        return ()
    if isinstance(team_mapping, tuple):
        return team_mapping

    entries: list[TeamMappingMatch] = []
    for key, value in (team_mapping or {}).items():
        tags = normalize_team_values(value)
        if not tags:
            continue
        entries.append(
            TeamMappingMatch(
                key=str(key),
                value=value,
                selector=parse_team_mapping_key(key),
                tags=tags,
            )
        )
    return tuple(entries)


def parse_team_mapping_key(key: Any) -> TeamMappingSelector:
    raw_key = str(key or "").strip()
    if raw_key == "*":
        return TeamMappingSelector(raw_key=raw_key, wildcard=True)

    remaining = raw_key
    case_sensitive = False
    require_no_group = False
    match_purl = False

    if "::" in remaining:
        modifier_part, identity_part = remaining.split("::", 1)
        modifiers = [
            token.strip().lower()
            for token in modifier_part.replace("+", ",").split(",")
            if token.strip()
        ]
        known_modifiers = {
            "cs",
            "case",
            "case-sensitive",
            "case_sensitive",
            "ci",
            "case-insensitive",
            "case_insensitive",
            "nogroup",
            "no-group",
            "no_group",
            "purl",
            "package-url",
            "package_url",
            "packageurl",
        }
        if modifiers and all(modifier in known_modifiers for modifier in modifiers):
            for modifier in modifiers:
                if modifier in {
                    "cs",
                    "case",
                    "case-sensitive",
                    "case_sensitive",
                }:
                    case_sensitive = True
                elif modifier in {
                    "ci",
                    "case-insensitive",
                    "case_insensitive",
                }:
                    case_sensitive = False
                elif modifier in {"nogroup", "no-group", "no_group"}:
                    require_no_group = True
                elif modifier in {"purl", "package-url", "package_url", "packageurl"}:
                    match_purl = True
            remaining = identity_part

    group: Optional[str] = None
    purl: Optional[str] = None
    name = remaining.strip()
    if match_purl:
        purl = remaining.strip()
        name = ""
    elif not require_no_group and ":" in remaining:
        group_part, name_part = remaining.split(":", 1)
        if group_part.strip():
            group = group_part.strip()
            name = name_part.strip()

    return TeamMappingSelector(
        raw_key=raw_key,
        name=name,
        group=group,
        purl=purl,
        require_no_group=require_no_group,
        case_sensitive=case_sensitive,
    )


def _matches_text(selector_text: str, actual_text: str, *, case_sensitive: bool) -> bool:
    if case_sensitive:
        return selector_text == actual_text
    return selector_text.lower() == actual_text.lower()


def _purl_without_version_qualifiers_or_subpath(value: str) -> str:
    text = value.strip()
    text = text.split("#", 1)[0].split("?", 1)[0]
    last_segment = text.rsplit("/", 1)[-1]
    if "@" in last_segment:
        prefix, _version = text.rsplit("@", 1)
        return prefix
    return text


def _purl_requests_exact_version(value: str) -> bool:
    text = value.strip()
    base = text.split("#", 1)[0].split("?", 1)[0]
    return "@" in base.rsplit("/", 1)[-1] or "?" in text or "#" in text


def _matches_purl(selector_purl: str, actual_purl: str, *, case_sensitive: bool) -> bool:
    selector = selector_purl.strip()
    actual = actual_purl.strip()
    if not selector or not actual:
        return False
    if _purl_requests_exact_version(selector):
        return _matches_text(selector, actual, case_sensitive=case_sensitive)
    return _matches_text(
        _purl_without_version_qualifiers_or_subpath(selector),
        _purl_without_version_qualifiers_or_subpath(actual),
        case_sensitive=case_sensitive,
    )


def _exact_case_match(selector: TeamMappingSelector, identity: ComponentIdentity) -> bool:
    if selector.wildcard:
        return False
    if selector.purl is not None:
        return _matches_purl(selector.purl, identity.purl or "", case_sensitive=True)
    if selector.name != identity.name:
        return False
    if selector.group is not None:
        return identity.group_known and selector.group == (identity.group or "")
    return True


def selector_matches_identity(
    selector: TeamMappingSelector,
    identity: ComponentIdentity,
    *,
    include_wildcard: bool = False,
) -> bool:
    name = (identity.name or "").strip()
    if selector.wildcard:
        return include_wildcard
    if selector.purl is not None:
        return _matches_purl(
            selector.purl,
            identity.purl or "",
            case_sensitive=selector.case_sensitive,
        )
    if not selector.name or not name:
        return False
    if not _matches_text(selector.name, name, case_sensitive=selector.case_sensitive):
        return False

    group = (identity.group or "").strip()
    if selector.require_no_group:
        return identity.group_known and not group

    if selector.group is not None:
        return (
            identity.group_known
            and bool(group)
            and _matches_text(
                selector.group,
                group,
                case_sensitive=selector.case_sensitive,
            )
        )

    if identity.group_known and group:
        return False
    return True


def _selector_specificity(selector: TeamMappingSelector) -> int:
    if selector.wildcard:
        return 0
    if selector.purl is not None:
        return 5
    if selector.group is not None:
        return 4
    if selector.require_no_group:
        return 3
    return 2


def _match_sort_key(
    match: TeamMappingMatch,
    identity: ComponentIdentity,
) -> tuple[int, int, int, str]:
    selector = match.selector
    return (
        -_selector_specificity(selector),
        -(1 if selector.case_sensitive else 0),
        -(1 if _exact_case_match(selector, identity) else 0),
        selector.raw_key,
    )


def find_team_mapping_match(
    team_mapping: dict[str, Any] | tuple[TeamMappingMatch, ...] | None,
    identity: ComponentIdentity,
    *,
    include_wildcard: bool = False,
) -> Optional[TeamMappingMatch]:
    matches: list[TeamMappingMatch] = []
    for entry in compile_team_mapping(team_mapping):
        selector = entry.selector
        if not selector_matches_identity(
            selector,
            identity,
            include_wildcard=include_wildcard,
        ):
            continue
        matches.append(entry)

    if not matches:
        return None

    return sorted(matches, key=lambda match: _match_sort_key(match, identity))[0]


def get_team_mapping_tags(
    team_mapping: dict[str, Any] | tuple[TeamMappingMatch, ...] | None,
    component_name: Any,
    component_group: Any = None,
    component_purl: Any = None,
    *,
    group_known: bool = False,
    include_wildcard: bool = False,
) -> tuple[str, ...]:
    match = find_team_mapping_match(
        team_mapping,
        ComponentIdentity(
            name=str(component_name or "").strip(),
            group=str(component_group).strip()
            if component_group not in (None, "")
            else None,
            purl=str(component_purl).strip()
            if component_purl not in (None, "")
            else None,
            group_known=group_known,
        ),
        include_wildcard=include_wildcard,
    )
    return match.tags if match else ()


def get_primary_team_for_identity(
    team_mapping: dict[str, Any] | None,
    component_name: Any,
    component_group: Any = None,
    component_purl: Any = None,
    *,
    group_known: bool = False,
    include_wildcard: bool = False,
) -> str:
    tags = get_team_mapping_tags(
        team_mapping,
        component_name,
        component_group,
        component_purl,
        group_known=group_known,
        include_wildcard=include_wildcard,
    )
    return tags[0] if tags else ""
