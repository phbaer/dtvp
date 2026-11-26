"""The dates the cutoff filter reads, and the filter itself.

ADR 0015. The cutoff compares one date per finding, by the basis a query
names (``cutoff_basis``):

- ``published`` (the default): when the vulnerability was published by its
  source, the earliest ``published`` of the vulnerability and its aliases
  among the records the group holds; the same for every finding of the
  group. What was publicly known by a date (premarket scope).
- ``attributed``: the earliest Dependency-Track attribution
  (``attributed_on``) of the same vulnerability on the same component
  identity in any version of the project, so new and re-created versions
  keep the earlier date. When monitoring learned of it (postmarket clock).

A finding without a date on the basis is *unknown*: shown and counted.

The cutoff is ``YYYY-MM-DD`` (UTC, the whole day included) or ``<N>d`` (N
days before today); its mode is ``before`` (on or before) or ``after``.
Functions here do no I/O.
"""

from __future__ import annotations

import math
import re
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable, Optional

DAY_MS = 24 * 60 * 60 * 1000
CUTOFF_MODE_BEFORE = "before"
CUTOFF_MODE_AFTER = "after"
CUTOFF_MODES = (CUTOFF_MODE_BEFORE, CUTOFF_MODE_AFTER)
BASIS_PUBLISHED = "published"
BASIS_ATTRIBUTED = "attributed"
CUTOFF_BASES = (BASIS_PUBLISHED, BASIS_ATTRIBUTED)
DEFAULT_CUTOFF_BASIS = BASIS_PUBLISHED
MAX_RELATIVE_DAYS = 36500
_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_RELATIVE_PATTERN = re.compile(r"^(\d{1,5})d$")


def parse_timestamp_ms(value: Any) -> Optional[int]:
    """Milliseconds since the epoch of an attribution value (ISO text, or
    seconds or milliseconds as a number); ``None`` when there is none."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(value) or value <= 0:
            return None
        return int(value * 1000 if value < 1_000_000_000_000 else value)
    raw = str(value).strip()
    if not raw:
        return None
    try:
        numeric = float(raw)
        if math.isfinite(numeric) and numeric > 0:
            return int(numeric * 1000 if numeric < 1_000_000_000_000 else numeric)
    except ValueError:
        pass
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp() * 1000)


def normalize_cutoff(value: Any) -> str:
    """The canonical text of a cutoff, ``""`` for none; ``ValueError`` when
    it is neither a date nor ``<N>d``."""
    text = str(value or "").strip().lower()
    if not text:
        return ""
    relative = _RELATIVE_PATTERN.match(text)
    if relative:
        days = int(relative.group(1))
        if not 0 <= days <= MAX_RELATIVE_DAYS:
            raise ValueError("cutoff: days out of range")
        return f"{days}d"
    if _DATE_PATTERN.match(text):
        try:
            date.fromisoformat(text)
        except ValueError as exc:
            raise ValueError(f"cutoff: invalid date {text!r}") from exc
        return text
    raise ValueError("cutoff must be a date YYYY-MM-DD or a number of days like 30d")


def normalize_cutoff_mode(value: Any) -> str:
    text = str(value or "").strip().lower() or CUTOFF_MODE_BEFORE
    if text not in CUTOFF_MODES:
        raise ValueError("cutoff_mode must be 'before' or 'after'")
    return text


def legacy_cutoff(days: Any, mode: Any) -> tuple[str, str]:
    """``attributed_before_days``/``attribution_mode`` as a cutoff."""
    if days is None or days == "":
        return "", CUTOFF_MODE_BEFORE
    number = int(days)
    if number < 1:
        raise ValueError("attributed_before_days must be at least 1")
    return (
        f"{number}d",
        CUTOFF_MODE_AFTER if str(mode or "").lower() == "younger" else CUTOFF_MODE_BEFORE,
    )


def normalize_cutoff_basis(value: Any, default: str = "") -> str:
    """A basis, or ``default`` for none; ``ValueError`` for an unknown one."""
    text = str(value or "").strip().lower()
    if not text:
        return default
    if text not in CUTOFF_BASES:
        raise ValueError(f"cutoff_basis must be one of {', '.join(CUTOFF_BASES)}")
    return text


def resolve_cutoff(
    cutoff: str,
    cutoff_mode: str = CUTOFF_MODE_BEFORE,
    attributed_before_days: Any = None,
    attribution_mode: Any = None,
    cutoff_basis: Any = "",
) -> tuple[str, str, str]:
    """The cutoff, mode and basis of a query. The retired attribution-age
    parameters, read when no cutoff is given, compared attribution dates:
    without a basis they mean ``attributed``."""
    normalized = normalize_cutoff(cutoff)
    if not normalized and attributed_before_days not in (None, ""):
        legacy, mode = legacy_cutoff(attributed_before_days, attribution_mode)
        return legacy, mode, normalize_cutoff_basis(cutoff_basis, BASIS_ATTRIBUTED)
    return (
        normalized,
        normalize_cutoff_mode(cutoff_mode),
        normalize_cutoff_basis(cutoff_basis, DEFAULT_CUTOFF_BASIS),
    )


def cutoff_end_ms(cutoff: str, *, today: date | None = None) -> Optional[int]:
    """The first millisecond after the cutoff day (UTC); ``None`` without a
    cutoff. A first-seen time below it is on or before the cutoff."""
    normalized = normalize_cutoff(cutoff)
    if not normalized:
        return None
    if normalized.endswith("d"):
        current = today or datetime.now(timezone.utc).date()
        day = current - timedelta(days=int(normalized[:-1]))
    else:
        day = date.fromisoformat(normalized)
    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    return int(start.timestamp() * 1000) + DAY_MS


def component_identity(component: dict[str, Any]) -> Optional[str]:
    """The component across versions: its package URL without the version,
    else its group and name; lower case."""
    purl = str(component.get("component_purl") or "").strip().lower()
    if purl:
        return re.sub(r"@[^?#]+", "", purl, count=1)
    name = str(component.get("component_name") or "").strip().lower()
    if not name:
        return None
    group = str(component.get("component_group") or "").strip().lower()
    return f"{group}/{name}" if group else name


def annotate_first_seen(group: dict[str, Any]) -> dict[str, Any]:
    """Set ``first_seen_ms`` (the ``attributed`` date) and ``published_ms``
    (or ``None``) on every finding of a group and return the list metadata
    of the cutoff filter: ``cutoff_dates`` maps each basis to

    - ``by_version``: per version label, ``[earliest, latest]`` known date of
      its findings;
    - ``unknown``: the version labels with a finding without a date.
    """
    findings: list[tuple[str, dict[str, Any]]] = []
    earliest: dict[str, int] = {}
    published: Optional[int] = None
    for affected_version in group.get("affected_versions") or []:
        label = str(
            affected_version.get("project_version")
            or affected_version.get("version")
            or ""
        ).strip()
        for component in affected_version.get("components") or []:
            if not isinstance(component, dict):
                continue
            findings.append((label, component))
            stated = parse_timestamp_ms(component.get("published"))
            if stated is not None and (published is None or stated < published):
                published = stated
            value = parse_timestamp_ms(component.get("attributed_on"))
            identity = component_identity(component)
            if value is None or identity is None:
                continue
            if identity not in earliest or value < earliest[identity]:
                earliest[identity] = value
    dates: dict[str, dict[str, Any]] = {
        basis: {"by_version": {}, "unknown": []} for basis in CUTOFF_BASES
    }

    def add(basis: str, label: str, value: Optional[int]) -> None:
        entry = dates[basis]
        if value is None:
            if label not in entry["unknown"]:
                entry["unknown"].append(label)
            return
        bounds = entry["by_version"].get(label)
        if bounds is None:
            entry["by_version"][label] = [value, value]
        else:
            bounds[0] = min(bounds[0], value)
            bounds[1] = max(bounds[1], value)

    for label, component in findings:
        identity = component_identity(component)
        carried = (
            earliest.get(identity)
            if identity is not None
            else parse_timestamp_ms(component.get("attributed_on"))
        )
        component["first_seen_ms"] = carried
        component["published_ms"] = published
        add(BASIS_PUBLISHED, label, published)
        add(BASIS_ATTRIBUTED, label, carried)
    return {"cutoff_dates": dates}


def cutoff_match(
    by_version: dict[str, Iterable[int]],
    unknown_versions: Iterable[str],
    *,
    end_ms: int,
    mode: str,
    versions: set[str] | None = None,
) -> Optional[str]:
    """``"known"`` when a finding in scope matches the cutoff, ``"unknown"``
    when none does but one has no date, else ``None``. Version labels are
    compared in lower case; ``versions`` empty or ``None`` means all."""
    scope = {value.lower() for value in versions} if versions else None
    for label, bounds in by_version.items():
        if scope is not None and label.lower() not in scope:
            continue
        low, high = list(bounds)[:2]
        if (mode == CUTOFF_MODE_AFTER and high >= end_ms) or (
            mode != CUTOFF_MODE_AFTER and low < end_ms
        ):
            return "known"
    for label in unknown_versions:
        if scope is None or label.lower() in scope:
            return "unknown"
    return None
