"""A recommendation derived from the version ranges Dependency-Track holds.

Dependency-Track's mirrors of NVD, GitHub advisories and OSV store, per
vulnerability, the affected packages with version ranges
(``VulnerableSoftware``). Its REST API returns them as ``affectedComponents``
of ``GET /api/v1/vulnerability/source/{source}/vuln/{vulnId}``. The end of
the range that contains the component's version (``versionEndExcluding``) is
the first fixed version.

Everything here is a pure function. Ambiguous or unreadable data gives no
fix; nothing is guessed. See docs/cyclonedx-export.md, section
"Recommendation", and ADR 0007.
"""

from __future__ import annotations

import functools
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping
from urllib.parse import unquote

BOUNDS = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)
_KEPT = ("identityType", "identity", "versionType", "version", *BOUNDS)

# -- Dependency-Track's version comparison ------------------------------------
# A port of org.dependencytrack.util.ComponentVersion (4.13.x and 4.14.x are
# identical), so that a range contains exactly the versions it contains for
# Dependency-Track.

_DEB = re.compile(r"^([0-9]+:)?(.*)(-[^-]+ubuntu[^-]+)$")
_PARTS = re.compile(
    r"(\d+[a-z]{1,3}$|[a-z]{1,3}[_-]?\d+|\d+|(rc|release|snapshot|beta|alpha)$)",
    re.IGNORECASE | re.ASCII,
)
_INT_MAX = 2**31 - 1


def version_parts(version: str) -> list[str]:
    """The parts ``ComponentVersion.parseVersion`` splits a version into."""
    text = version.lower()
    deb = _DEB.match(text)
    if deb:
        text = deb.group(2)
    parts = [match.group(0) for match in _PARTS.finditer(text)]
    return parts or [version]


def _java_int(part: str) -> int | None:
    # Integer.parseInt on what the pattern yields: digits within int range.
    if part.isascii() and part.isdigit():
        value = int(part)
        return value if value <= _INT_MAX else None
    return None


def compare_versions(left_version: str, right_version: str) -> int:
    """-1, 0 or 1, as ``ComponentVersion.compareTo`` orders the two."""
    left, right = version_parts(left_version), version_parts(right_version)
    shortest = min(len(left), len(right))
    for index in range(shortest):
        left_part, right_part = left[index], right[index]
        if left_part == right_part:
            continue
        left_int, right_int = _java_int(left_part), _java_int(right_part)
        if left_int is not None and right_int is not None:
            if left_int != right_int:
                return -1 if left_int < right_int else 1
        elif left_part != right_part:
            return -1 if left_part < right_part else 1
    # 1.0.0 equals 1.0.0.0.
    if len(left) == shortest and len(right) == len(left) + 1 and right[-1] == "0":
        return 0
    if len(right) == shortest and len(left) == len(right) + 1 and left[-1] == "0":
        return 0
    return (len(left) > len(right)) - (len(left) < len(right))


def range_contains(entry: Mapping[str, Any], version: str) -> bool | None:
    """Whether a RANGE entry contains ``version``, as Dependency-Track
    decides it; None when the version cannot be compared."""
    if not version or version in ("*", "-"):
        return None
    if end := entry.get("versionEndExcluding"):
        if compare_versions(end, version) <= 0:
            return False
    if start := entry.get("versionStartExcluding"):
        if compare_versions(start, version) >= 0:
            return False
    if end := entry.get("versionEndIncluding"):
        if compare_versions(end, version) < 0:
            return False
    if start := entry.get("versionStartIncluding"):
        if compare_versions(start, version) > 0:
            return False
    return True


# -- identities ----------------------------------------------------------------


def parse_purl(value: Any) -> dict[str, Any] | None:
    """Type, namespace, name and qualifiers of a package URL, or None."""
    text = str(value or "").strip()
    if not text.lower().startswith("pkg:"):
        return None
    text = text[4:].lstrip("/").partition("#")[0]
    path, _, query = text.partition("?")
    qualifiers = {
        key.lower(): unquote(item)
        for key, _, item in (pair.partition("=") for pair in query.split("&") if pair)
        if key
    }
    head, at, version = path.rpartition("@")
    if at and "/" not in version:
        path = head
    type_, _, rest = path.strip("/").partition("/")
    segments = [unquote(segment) for segment in rest.split("/") if segment]
    if not type_ or not segments:
        return None
    return {
        "type": type_.lower(),
        "namespace": "/".join(segments[:-1]),
        "name": segments[-1],
        "qualifiers": qualifiers,
    }


def _purl_key(purl: Mapping[str, Any]) -> tuple[str, str, str]:
    type_, namespace, name = purl["type"], purl["namespace"], purl["name"]
    if type_ == "maven":
        return type_, namespace, name
    if type_ == "pypi":
        name = re.sub(r"[-_.]+", "-", name)
    return type_, namespace.lower(), name.lower()


# CPE 2.3 attributes after part, vendor, product and version, as
# Dependency-Track's maybeMatchCpe compares them.
_CPE_OTHER = (
    "update", "edition", "language", "sw_edition", "target_sw", "target_hw", "other",
)
_CPE_ANY = ("", "*")


def _cpe_fields(value: Any) -> dict[str, str] | None:
    """The attributes of a CPE 2.3 or 2.2, or None without a vendor and a
    product. Attributes a CPE does not give are ``*`` (any)."""
    text = str(value or "").strip().lower()
    if text.startswith("cpe:2.3:"):
        values = re.split(r"(?<!\\):", text)[2:]
    elif text.startswith("cpe:/"):
        values = text[5:].split(":")
    else:
        return None
    names = ("part", "vendor", "product", "version", *_CPE_OTHER)
    fields = {name: (values[index] if index < len(values) else "*") or "*"
              for index, name in enumerate(names)}
    if fields["vendor"] in ("*", "-") or fields["product"] in ("*", "-"):
        return None
    return fields


def _cpe_matches(entry: Mapping[str, str], component: Mapping[str, str]) -> bool:
    """Same vendor and product, and no other attribute (part, target_sw, …)
    that both name with different values: Dependency-Track's DISJOINT."""
    if (entry["vendor"], entry["product"]) != (component["vendor"], component["product"]):
        return False
    return not any(
        entry[name] not in _CPE_ANY
        and component[name] not in _CPE_ANY
        and entry[name] != component[name]
        for name in ("part", *_CPE_OTHER)
    )


def component_identity(component: Mapping[str, Any]) -> dict[str, Any]:
    """The package URL and CPE of a finding's component, each None if absent."""
    return {
        "purl": parse_purl(component.get("purl")),
        "cpe": _cpe_fields(component.get("cpe")),
    }


def matching_entries(
    component: Mapping[str, Any], entries: Iterable[Mapping[str, Any]]
) -> list[Mapping[str, Any]]:
    """The affected-component entries that name the finding's component."""
    identity = component_identity(component)
    purl, cpe = identity["purl"], identity["cpe"]
    if purl is None and cpe is None:
        return []
    matched = []
    for entry in entries or []:
        if not isinstance(entry, Mapping):
            continue
        kind = str(entry.get("identityType") or "").upper()
        if kind == "PURL" and purl is not None:
            other = parse_purl(entry.get("identity"))
            if other is None or _purl_key(other) != _purl_key(purl):
                continue
            distro = purl["qualifiers"].get("distro")
            other_distro = other["qualifiers"].get("distro")
            if distro and other_distro and distro.casefold() != other_distro.casefold():
                continue
            matched.append(entry)
        elif kind == "CPE" and cpe is not None:
            other = _cpe_fields(entry.get("identity"))
            if other is not None and _cpe_matches(other, cpe):
                matched.append(entry)
    return matched


# -- the fix -------------------------------------------------------------------


@dataclass(frozen=True)
class Fix:
    version: str
    later_ranges: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()


def _is_range(entry: Mapping[str, Any]) -> bool:
    return str(entry.get("versionType") or "").upper() == "RANGE" or any(
        entry.get(bound) for bound in BOUNDS
    )


def _start(entry: Mapping[str, Any]) -> str | None:
    return entry.get("versionStartIncluding") or entry.get("versionStartExcluding")


def _low(entry: Mapping[str, Any]) -> str:
    """Where an entry starts: its start bound, or its exact version."""
    return str((_start(entry) if _is_range(entry) else entry.get("version")) or "")


def _entry_contains(entry: Mapping[str, Any], version: str) -> bool:
    if _is_range(entry):
        return bool(range_contains(entry, version))
    exact = str(entry.get("version") or "")
    return bool(exact) and compare_versions(exact, version) == 0


def range_text(entry: Mapping[str, Any]) -> str:
    """A range written like ``>=3.0.0 <3.0.2``."""
    parts = []
    if entry.get("versionStartIncluding"):
        parts.append(f">={entry['versionStartIncluding']}")
    elif entry.get("versionStartExcluding"):
        parts.append(f">{entry['versionStartExcluding']}")
    if entry.get("versionEndExcluding"):
        parts.append(f"<{entry['versionEndExcluding']}")
    elif entry.get("versionEndIncluding"):
        parts.append(f"<={entry['versionEndIncluding']}")
    return " ".join(parts)


def fix_for(
    component: Mapping[str, Any], entries: Iterable[Mapping[str, Any]]
) -> Fix | None:
    """The first fixed version for the component's version, or None.

    The ranges that name the component and contain its version, compared
    as Dependency-Track compares versions, must all end before the same
    version (``versionEndExcluding``). A version that cannot be compared,
    no containing range, an end that is included, an open end, disagreeing
    ends, or exact versions only give no fix. That the finding was reported
    says nothing about which range applies: other analyzers report findings
    too, and an unqualified range may be another distribution's.

    A fixed version that another entry of the component affects is moved to
    the end of that range; if that range has no excluded end, or an exact
    version is the fixed one, there is no fix.
    """
    matched = matching_entries(component, entries)
    ranges = [entry for entry in matched if _is_range(entry)]
    if not ranges:
        return None
    version = str(component.get("version") or "")
    contained = [(entry, range_contains(entry, version)) for entry in ranges]
    if any(result is None for _entry, result in contained):
        return None
    containing = [entry for entry, result in contained if result]
    if not containing:
        return None
    if any(
        entry.get("versionEndIncluding") or not entry.get("versionEndExcluding")
        for entry in containing
    ):
        return None
    ends = {str(entry["versionEndExcluding"]) for entry in containing}
    if len(ends) != 1:
        return None
    fixed = ends.pop()
    if compare_versions(version, fixed) >= 0:
        return None
    used = list(containing)
    # Overlapping data: each move goes past one more range, so at most
    # one move per entry.
    for _ in range(len(matched) + 1):
        affecting = [entry for entry in matched if _entry_contains(entry, fixed)]
        if not affecting:
            break
        if any(
            not _is_range(entry)
            or entry.get("versionEndIncluding")
            or not entry.get("versionEndExcluding")
            for entry in affecting
        ):
            return None
        used.extend(entry for entry in affecting if entry not in used)
        fixed = max(
            (str(entry["versionEndExcluding"]) for entry in affecting),
            key=functools.cmp_to_key(compare_versions),
        )
    else:
        return None
    later = [
        entry for entry in matched
        if entry not in used
        and (low := _low(entry))
        and compare_versions(low, fixed) >= 0
    ]
    later.sort(key=functools.cmp_to_key(
        lambda a, b: compare_versions(_low(a), _low(b))
    ))
    sources = sorted(
        {str(source) for entry in used for source in entry.get("sources") or [] if source}
    )
    return Fix(
        version=fixed,
        later_ranges=tuple(dict.fromkeys(
            range_text(entry) if _is_range(entry) else str(entry["version"])
            for entry in later
        )),
        sources=tuple(sources),
    )


def display_name(component: Mapping[str, Any]) -> str:
    """``group:name`` for maven, ``group/name`` for other types with a group,
    else the name. The package URL's name and namespace come first: they
    name the installed package (``sqlite3``), where the component's name
    may be a product name (``sqlite``)."""
    purl = parse_purl(component.get("purl")) or {}
    name = str(purl.get("name") or component.get("name") or "")
    group = str(purl.get("namespace") or component.get("group") or "")
    if not group:
        return name
    return f"{group}:{name}" if purl.get("type") == "maven" else f"{group}/{name}"


def installed_name(component: Mapping[str, Any]) -> str:
    """The package with its installed version, as a sentence names it."""
    version = str(component.get("version") or "").strip()
    return f"{display_name(component)} {version}".strip()


def recommendation_text(component: Mapping[str, Any], fix: Fix) -> str:
    text = f"Upgrade {installed_name(component)} to {fix.version} or later."
    if fix.later_ranges:
        text += f" Later versions are affected too: {', '.join(fix.later_ranges)}."
    return text


@dataclass(frozen=True)
class Derived:
    text: str
    sources: tuple[str, ...]


def derive_recommendation(
    component: Mapping[str, Any],
    entries: Iterable[Mapping[str, Any]] | None,
) -> Derived | None:
    """The sentence for one component from its ranges; None without a fix.

    The record's ``patchedVersions`` is not used: Trivy sets it once, from
    whichever package and distribution created the record, so it says
    nothing about this component (see the VDR's ``patched_versions``
    property).
    """
    fix = fix_for(component, entries or [])
    if fix is None:
        return None
    return Derived(recommendation_text(component, fix), fix.sources)


def slim_affected_components(items: Any) -> list[dict[str, Any]]:
    """What is kept of ``affectedComponents``: the identity, the version or
    the bounds, and the distinct sources of the attributions. Everything
    else is dropped."""
    slim = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, Mapping):
            continue
        entry = {
            key: str(item[key]) for key in _KEPT if item.get(key) not in (None, "")
        }
        if not entry.get("identity"):
            continue
        sources = list(dict.fromkeys(
            str(attribution.get("source"))
            for attribution in item.get("affectedVersionAttributions") or []
            if isinstance(attribution, Mapping) and attribution.get("source")
        ))
        if sources:
            entry["sources"] = sources
        slim.append(entry)
    return slim
