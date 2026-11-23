"""Release notes for the "What's new" dialog, built from the changelog.

The changelog is generated from Conventional Commits by git-cliff. The build
writes it twice: ``CHANGELOG.md`` for reading, and ``CHANGELOG.json``
(``git-cliff --context``) with every commit's parts. This module turns either
into releases that list only what matters to users:

- ``breaking``: commits marked breaking (``feat!:`` or a ``BREAKING CHANGE``
  footer), with the footer's text as a note;
- ``new`` (``feat``), ``faster`` (``perf``) and ``fixed`` (``fix``).

Everything else (chores, CI, tests, docs, build, style, refactoring and
dependency updates) is left out unless it is breaking.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from .file_io_services import read_text

GROUPS = ("breaking", "new", "faster", "fixed")
_TYPE_GROUP = {"feat": "new", "perf": "faster", "fix": "fixed"}
_HIDDEN_SCOPES = {"deps", "deps-dev"}
_HEADER_RE = re.compile(
    r"^(?P<type>[a-zA-Z]+)(?:\((?P<scope>[^)]*)\))?(?P<bang>!)?:\s*(?P<desc>.+)$"
)
_PR_RE = re.compile(r"\s*\(#(?P<pr>\d+)\)")
_PRERELEASE_RE = re.compile(r"(a|b|rc)\d+$")
_BREAKING_FOOTER_RE = re.compile(
    r"^BREAKING[ -]CHANGE:\s*(?P<text>.+?)(?:\n\s*\n|\Z)", re.M | re.S
)
_NOTE_LIMIT = 600


def _subject(message: str) -> str:
    """The first line of a commit message. A squash commit whose body was
    joined to its subject (older changelogs) ends the subject at its PR
    number."""
    first = message.strip().split("\n", 1)[0].strip()
    match = _PR_RE.search(first)
    if match and first[match.end():].strip():
        return first[: match.end()].strip()
    return first


def _sentence(text: str) -> str:
    text = text.strip().rstrip(".").strip()
    return text[:1].upper() + text[1:] if text else text


def _note(text: Optional[str], subject: str) -> Optional[str]:
    if not text:
        return None
    note = " ".join(text.split())
    if not note or _sentence(_PR_RE.sub("", note)).lower() == subject.lower():
        return None
    return note if len(note) <= _NOTE_LIMIT else note[: _NOTE_LIMIT - 1].rstrip() + "…"


def entry_from_message(
    message: str,
    *,
    breaking: bool = False,
    breaking_note: Optional[str] = None,
) -> Optional[tuple[str, dict[str, Any]]]:
    """``(group, entry)`` for one commit, or ``None`` when users don't need it.
    ``entry`` is ``{text, scope, pr, breaking, note}``."""
    header = _HEADER_RE.match(_subject(message))
    if not header:
        return None
    kind = header.group("type").lower()
    scope = (header.group("scope") or "").strip() or None
    is_breaking = bool(breaking or header.group("bang"))
    if not breaking_note:
        footer = _BREAKING_FOOTER_RE.search(message)
        if footer:
            is_breaking = True
            breaking_note = footer.group("text")
    if not is_breaking and (
        kind not in _TYPE_GROUP or (scope or "").lower() in _HIDDEN_SCOPES
    ):
        return None
    description = header.group("desc")
    pr_match = _PR_RE.search(description)
    pr = int(pr_match.group("pr")) if pr_match else None
    if pr_match:
        description = description[: pr_match.start()] + description[pr_match.end():]
    text = _sentence(description)
    if not text:
        return None
    return (
        "breaking" if is_breaking else _TYPE_GROUP[kind],
        {
            "text": text,
            "scope": scope,
            "pr": pr,
            "breaking": is_breaking,
            "note": _note(breaking_note, text) if is_breaking else None,
        },
    )


def _release(version: Optional[str], date: Optional[str]) -> dict[str, Any]:
    name = version.strip().lstrip("vV") if version else None
    return {
        "version": name,
        "date": date,
        "prerelease": bool(name and _PRERELEASE_RE.search(name)),
        "unreleased": name is None,
        "groups": {group: [] for group in GROUPS},
    }


def _add(release: dict[str, Any], result: Optional[tuple[str, dict[str, Any]]]) -> None:
    if result is None:
        return
    group, entry = result
    entries = release["groups"][group]
    if all(
        (existing["text"], existing["scope"]) != (entry["text"], entry["scope"])
        for existing in entries
    ):
        entries.append(entry)


def _date(timestamp: Any) -> Optional[str]:
    if not isinstance(timestamp, (int, float)) or timestamp <= 0:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).date().isoformat()


def releases_from_context(context: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Releases from ``git-cliff --context`` output, newest first as given."""
    releases = []
    for item in context:
        if not isinstance(item, dict):
            continue
        release = _release(item.get("version"), _date(item.get("timestamp")))
        for commit in item.get("commits") or []:
            if not isinstance(commit, dict):
                continue
            message = str(commit.get("raw_message") or commit.get("message") or "")
            _add(
                release,
                entry_from_message(
                    message,
                    breaking=bool(commit.get("breaking")),
                    breaking_note=commit.get("breaking_description") or None,
                ),
            )
        releases.append(release)
    return releases


_MD_RELEASE_RE = re.compile(r"^##\s+\[(?P<version>[^\]]+)\](?:\s*[—-]\s*(?P<date>\S+))?")
_MD_SECTION_GROUPS = (("feature", "new"), ("bug fix", "fixed"), ("performance", "faster"))
_MD_BREAKING = "⚠️ **BREAKING**"
_MD_SCOPE_RE = re.compile(r"^\*\*(?P<scope>[^*]+):\*\*\s*(?P<text>.+)$")


def _markdown_entry(
    text: str, section: Optional[str], breaking: bool
) -> Optional[tuple[str, dict[str, Any]]]:
    # Lines whose commit git-cliff could not parse keep "type(scope): ".
    parsed = entry_from_message(text, breaking=breaking)
    if parsed is not None or _HEADER_RE.match(_subject(text)):
        return parsed
    group = "breaking" if breaking else section
    if group is None:
        return None
    subject = _subject(text)
    scoped = _MD_SCOPE_RE.match(subject)
    scope = scoped.group("scope").strip() if scoped else None
    description = scoped.group("text") if scoped else subject
    pr_match = _PR_RE.search(description)
    pr = int(pr_match.group("pr")) if pr_match else None
    if pr_match:
        description = description[: pr_match.start()] + description[pr_match.end():]
    sentence = _sentence(description)
    if not sentence:
        return None
    return group, {
        "text": sentence, "scope": scope, "pr": pr, "breaking": breaking, "note": None,
    }


def releases_from_markdown(content: str) -> list[dict[str, Any]]:
    """Releases from ``CHANGELOG.md`` (cliff.toml's template), for builds
    without ``CHANGELOG.json``: the section says the group, a breaking marker
    makes an entry breaking, other sections are left out."""
    releases: list[dict[str, Any]] = []
    current: Optional[dict[str, Any]] = None
    section: Optional[str] = None
    for line in content.splitlines():
        heading = _MD_RELEASE_RE.match(line)
        if heading:
            version = heading.group("version")
            current = _release(
                None if version.lower() == "unreleased" else version,
                heading.group("date"),
            )
            releases.append(current)
            section = None
            continue
        if line.startswith("### "):
            title = line[4:].lower()
            section = next((group for word, group in _MD_SECTION_GROUPS if word in title), None)
            continue
        if current is None or not line.startswith("- "):
            continue
        text = line[2:].strip()
        breaking = text.startswith(_MD_BREAKING)
        if breaking:
            text = text[len(_MD_BREAKING):].strip()
        _add(current, _markdown_entry(text, section, breaking))
    return releases


_CACHE: dict[str, tuple[tuple[int, int], list[dict[str, Any]]]] = {}


def _stamp(path: str) -> tuple[int, int]:
    stat = os.stat(path)
    return stat.st_mtime_ns, stat.st_size


def _cached(path: str, build: Any) -> list[dict[str, Any]]:
    stamp = _stamp(path)
    cached = _CACHE.get(path)
    if cached is not None and cached[0] == stamp:
        return cached[1]
    releases = build(read_text(path))
    _CACHE[path] = (stamp, releases)
    return releases


def _from_context_text(text: str) -> list[dict[str, Any]]:
    context = json.loads(text)
    if not isinstance(context, list):
        raise ValueError("CHANGELOG.json is not a list of releases")
    return releases_from_context(context)


def load_releases(cwd: Optional[str] = None) -> list[dict[str, Any]]:
    """The releases of the running build: from ``CHANGELOG.json`` when the
    build has it (and it reads), else from ``CHANGELOG.md``, else none. The
    result is kept while the file is unchanged."""
    root_dir = cwd or os.getcwd()
    context_path = os.path.join(root_dir, "CHANGELOG.json")
    if os.path.exists(context_path):
        try:
            return _cached(context_path, _from_context_text)
        except (OSError, ValueError):
            pass
    markdown_path = os.path.join(root_dir, "CHANGELOG.md")
    if os.path.exists(markdown_path):
        try:
            return _cached(markdown_path, releases_from_markdown)
        except OSError:
            return []
    return []
