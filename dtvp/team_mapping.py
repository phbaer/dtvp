from dataclasses import dataclass, replace
from typing import Any, Optional
from urllib.parse import unquote


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
    # ``project:<name>::<selector>``: the component selector applies only in
    # this Dependency-Track project.
    project: Optional[str] = None
    # ``project::<name>``: owns the project's findings no component selector
    # owns (``project`` holds the name).
    project_fallback: bool = False
    # Why the key is not a valid selector; ``None`` when it is. Saving a
    # mapping rejects invalid keys; one already stored still matches as it
    # did before (an unknown modifier part is read as part of the name).
    error: Optional[str] = None


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


_CASE_SENSITIVE_MODIFIERS = frozenset(
    {"cs", "case", "case-sensitive", "case_sensitive"}
)
_CASE_INSENSITIVE_MODIFIERS = frozenset(
    {"ci", "case-insensitive", "case_insensitive"}
)
_NO_GROUP_MODIFIERS = frozenset({"nogroup", "no-group", "no_group"})
_PURL_MODIFIERS = frozenset({"purl", "package-url", "package_url", "packageurl"})
_KNOWN_MODIFIERS = (
    _CASE_SENSITIVE_MODIFIERS
    | _CASE_INSENSITIVE_MODIFIERS
    | _NO_GROUP_MODIFIERS
    | _PURL_MODIFIERS
)
PROJECT_PREFIX = "project:"


def _parse_component_key(raw_key: str, remaining: str, project: Optional[str]) -> TeamMappingSelector:
    case_sensitive = False
    require_no_group = False
    match_purl = False
    error: Optional[str] = None

    if "::" in remaining:
        modifier_part, identity_part = remaining.split("::", 1)
        modifiers = [
            token.strip().lower()
            for token in modifier_part.replace("+", ",").split(",")
            if token.strip()
        ]
        unknown = [modifier for modifier in modifiers if modifier not in _KNOWN_MODIFIERS]
        if not modifiers:
            error = "Nothing before '::'; use a modifier such as cs, nogroup or purl"
        elif unknown:
            error = f"Unknown modifier {unknown[0]!r} before '::'"
            if unknown[0] == "project":
                error = "'project::<name>' cannot be combined with other modifiers"
        else:
            kinds = set(modifiers)
            if kinds & _CASE_SENSITIVE_MODIFIERS and kinds & _CASE_INSENSITIVE_MODIFIERS:
                error = "Modifiers cs and ci contradict each other"
            elif kinds & _PURL_MODIFIERS and kinds & _NO_GROUP_MODIFIERS:
                error = "Modifier nogroup does not apply to a purl selector"
            for modifier in modifiers:
                if modifier in _CASE_SENSITIVE_MODIFIERS:
                    case_sensitive = True
                elif modifier in _CASE_INSENSITIVE_MODIFIERS:
                    case_sensitive = False
                elif modifier in _NO_GROUP_MODIFIERS:
                    require_no_group = True
                elif modifier in _PURL_MODIFIERS:
                    match_purl = True
            remaining = identity_part

    group: Optional[str] = None
    purl: Optional[str] = None
    name = remaining.strip()
    if match_purl:
        purl = remaining.strip()
        name = ""
        if error is None and not purl.lower().startswith("pkg:"):
            error = "A purl selector needs a package URL starting with pkg:"
    elif not require_no_group and ":" in remaining:
        group_part, name_part = remaining.split(":", 1)
        if group_part.strip():
            group = group_part.strip()
            name = name_part.strip()
    elif not require_no_group and "/" in remaining:
        # Scoped package names commonly use group/name (for example @scope/pkg).
        group_part, name_part = remaining.rsplit("/", 1)
        if group_part.strip() and name_part.strip():
            group = group_part.strip()
            name = name_part.strip()

    if error is None and not match_purl and not name:
        error = "The selector names no component"

    return TeamMappingSelector(
        raw_key=raw_key,
        name=name,
        group=group,
        purl=purl,
        require_no_group=require_no_group,
        case_sensitive=case_sensitive,
        project=project,
        error=error,
    )


def parse_team_mapping_key(key: Any) -> TeamMappingSelector:
    """Parse a mapping key. Forms (see docs/assessment-model.md):

    ``*``; ``project::<project>``; ``project:<project>::<selector>``; and the
    component selectors ``name``, ``group:name``, ``group/name`` with the
    optional modifiers ``cs``, ``ci``, ``nogroup`` and ``purl`` before ``::``.
    Mirrored by ``parseTeamMappingKey`` (frontend/src/lib/team-mapping.ts).
    """
    raw_key = str(key or "").strip()
    if raw_key == "*":
        return TeamMappingSelector(raw_key=raw_key, wildcard=True)
    if not raw_key:
        return TeamMappingSelector(raw_key=raw_key, error="The key is empty")

    if "::" in raw_key:
        head, rest = raw_key.split("::", 1)
        head_text = head.strip()
        if head_text.lower() == "project":
            project_name = rest.strip()
            return TeamMappingSelector(
                raw_key=raw_key,
                project=project_name or None,
                project_fallback=True,
                error=None if project_name else "'project::' needs a project name",
            )
        if head_text.lower().startswith(PROJECT_PREFIX):
            project_name = head_text[len(PROJECT_PREFIX):].strip()
            inner = rest.strip()
            if not project_name:
                return TeamMappingSelector(
                    raw_key=raw_key,
                    error="'project:<name>::' needs a project name",
                )
            if inner == "*":
                return TeamMappingSelector(
                    raw_key=raw_key,
                    project=project_name,
                    error=f"Use 'project::{project_name}' for the project's own findings",
                )
            inner_head = inner.split("::", 1)[0].strip().lower() if "::" in inner else ""
            if inner_head == "project" or inner_head.startswith(PROJECT_PREFIX):
                return TeamMappingSelector(
                    raw_key=raw_key,
                    project=project_name,
                    error="A project selector cannot contain another project selector",
                )
            return _parse_component_key(raw_key, inner, project_name)

    return _parse_component_key(raw_key, raw_key, None)


def team_mapping_key_errors(mapping: Any) -> list[str]:
    """Errors of the keys of a mapping document: every key that is not a
    valid selector, with the reason."""
    if not isinstance(mapping, dict):
        return []
    errors: list[str] = []
    for key in mapping:
        selector = parse_team_mapping_key(key)
        if selector.error:
            errors.append(f"Mapping key {str(key)!r}: {selector.error}")
    return errors


def _same_project(selector_project: Optional[str], project: Optional[str]) -> bool:
    if not selector_project or not project:
        return False
    return selector_project.strip().lower() == str(project).strip().lower()


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
    if selector.wildcard or selector.project_fallback:
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
    project: Optional[str] = None,
) -> bool:
    """Whether a component selector matches the component. ``project`` is
    the Dependency-Track project the component is in; a project-scoped
    selector matches only there. ``project::`` selectors and ``*`` are
    fallbacks, not component selectors (``*`` matches with
    ``include_wildcard``)."""
    name = (identity.name or "").strip()
    if selector.wildcard:
        return include_wildcard
    if selector.project_fallback:
        return False
    if selector.project is not None and not _same_project(selector.project, project):
        return False
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
) -> tuple[int, int, int, int, str]:
    selector = match.selector
    return (
        # A selector scoped to the component's project ranks above every
        # selector without a project.
        -(1 if selector.project is not None else 0),
        -_selector_specificity(selector),
        -(1 if selector.case_sensitive else 0),
        -(1 if _exact_case_match(selector, identity) else 0),
        selector.raw_key,
    )


def purl_package_identity(identity: ComponentIdentity) -> Optional[ComponentIdentity]:
    """The identity the component's package URL names: its package name and
    namespace (as the group). ``None`` without a package URL, or when it
    names the same name and group as the component already has."""
    text = (identity.purl or "").strip()
    if not text.lower().startswith("pkg:"):
        return None
    path = text[4:].split("#", 1)[0].split("?", 1)[0].strip("/")
    segments = path.split("/")
    if len(segments) < 2:
        return None
    last = segments[-1]
    if "@" in last:
        last = last.rsplit("@", 1)[0]
    name = unquote(last).strip()
    namespace = "/".join(unquote(segment) for segment in segments[1:-1]).strip()
    if not name:
        return None
    if (
        name.lower() == (identity.name or "").strip().lower()
        and namespace.lower() == (identity.group or "").strip().lower()
    ):
        return None
    return replace(identity, name=name, group=namespace or None, group_known=True)


def _best_match(
    entries: tuple[TeamMappingMatch, ...],
    identity: ComponentIdentity,
    *,
    include_wildcard: bool,
    project: Optional[str] = None,
) -> Optional[TeamMappingMatch]:
    matches = [
        entry
        for entry in entries
        if selector_matches_identity(
            entry.selector,
            identity,
            include_wildcard=include_wildcard,
            project=project,
        )
    ]
    if not matches:
        return None
    return sorted(matches, key=lambda match: _match_sort_key(match, identity))[0]


def project_fallback_match(
    team_mapping: dict[str, Any] | tuple[TeamMappingMatch, ...] | None,
    project: Optional[str],
) -> Optional[TeamMappingMatch]:
    """The ``project::<project>`` entry of a project, if any."""
    if not project:
        return None
    matches = [
        entry
        for entry in compile_team_mapping(team_mapping)
        if entry.selector.project_fallback
        and _same_project(entry.selector.project, project)
    ]
    if not matches:
        return None
    return sorted(
        matches,
        key=lambda entry: (
            # Exact case of the project name first, then the key.
            0 if (entry.selector.project or "").strip() == str(project).strip() else 1,
            entry.selector.raw_key,
        ),
    )[0]


def find_component_mapping_match(
    team_mapping: dict[str, Any] | tuple[TeamMappingMatch, ...] | None,
    identity: ComponentIdentity,
    *,
    project: Optional[str] = None,
) -> Optional[TeamMappingMatch]:
    """The component selector that owns a component, without fallbacks: by
    its name, group or package URL (selectors scoped to ``project`` first);
    else by the package name and namespace its package URL names (a BOM may
    name a component differently from its package, for example
    "stats-app" for pkg:npm/vp-stats-app)."""
    entries = compile_team_mapping(team_mapping)
    match = _best_match(entries, identity, include_wildcard=False, project=project)
    if match is None:
        package = purl_package_identity(identity)
        if package is not None:
            match = _best_match(
                entries, package, include_wildcard=False, project=project
            )
    return match


def find_team_mapping_match(
    team_mapping: dict[str, Any] | tuple[TeamMappingMatch, ...] | None,
    identity: ComponentIdentity,
    *,
    include_wildcard: bool = False,
    project: Optional[str] = None,
) -> Optional[TeamMappingMatch]:
    """The mapping entry for a component. Precedence: a selector scoped to
    ``project``, a component selector, the package its purl names (both in
    ``find_component_mapping_match``); with ``include_wildcard`` then
    ``project::<project>`` and last ``*``."""
    entries = compile_team_mapping(team_mapping)
    match = find_component_mapping_match(entries, identity, project=project)
    if match is None and include_wildcard:
        match = project_fallback_match(entries, project)
    if match is None and include_wildcard:
        match = _best_match(entries, identity, include_wildcard=True)
    return match


def get_team_mapping_tags(
    team_mapping: dict[str, Any] | tuple[TeamMappingMatch, ...] | None,
    component_name: Any,
    component_group: Any = None,
    component_purl: Any = None,
    *,
    group_known: bool = False,
    include_wildcard: bool = False,
    project: Optional[str] = None,
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
        project=project,
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
    project: Optional[str] = None,
) -> str:
    tags = get_team_mapping_tags(
        team_mapping,
        component_name,
        component_group,
        component_purl,
        group_known=group_known,
        include_wildcard=include_wildcard,
        project=project,
    )
    return tags[0] if tags else ""
