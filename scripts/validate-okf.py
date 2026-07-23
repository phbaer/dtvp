#!/usr/bin/env python3
"""Validate DTVP's Open Knowledge Format documentation bundle."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml


RESERVED_FILENAMES = {"index.md", "log.md"}
ALLOWED_TYPES = {
    "Architecture",
    "Component",
    "Integration",
    "Project",
    "Reference",
    "Security Model",
    "Workflow",
}
LINK_PATTERN = re.compile(r"!?\[[^\]]*]\(([^)]+)\)")
GLOB_PATTERN = re.compile(r"[*?[]")


def _parse_frontmatter(path: Path) -> tuple[dict[str, Any] | None, str, str | None]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, text, "missing YAML frontmatter"

    try:
        delimiter = next(
            index for index, line in enumerate(lines[1:], start=1) if line.strip() == "---"
        )
    except StopIteration:
        return None, text, "frontmatter has no closing delimiter"

    try:
        metadata = yaml.safe_load("\n".join(lines[1:delimiter]))
    except yaml.YAMLError as exc:
        return None, text, f"frontmatter is not valid YAML: {exc}"
    if not isinstance(metadata, dict):
        return None, text, "frontmatter must be a YAML mapping"

    return metadata, "\n".join(lines[delimiter + 1 :]), None


def _link_target(raw_target: str) -> str:
    target = raw_target.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    elif " " in target:
        target = target.split(" ", 1)[0]
    return unquote(target)


def _local_link_path(
    target: str,
    *,
    source: Path,
    bundle_root: Path,
) -> Path | None:
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or not parsed.path:
        return None
    if parsed.path.startswith("/"):
        return bundle_root / parsed.path.lstrip("/")
    return source.parent / parsed.path


def _validate_source_paths(
    metadata: dict[str, Any],
    *,
    relative_path: Path,
    repository_root: Path,
) -> list[str]:
    errors: list[str] = []
    values = metadata.get("source_paths")
    if not isinstance(values, list) or not values:
        return [f"{relative_path}: source_paths must be a non-empty YAML list"]

    for value in values:
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{relative_path}: source_paths entries must be non-empty strings")
            continue
        candidate = Path(value)
        if candidate.is_absolute() or ".." in candidate.parts:
            errors.append(
                f"{relative_path}: source path must stay repository-relative: {value}"
            )
            continue

        if GLOB_PATTERN.search(value):
            exists = any(repository_root.glob(value))
        else:
            exists = (repository_root / candidate).exists()
        if not exists:
            errors.append(f"{relative_path}: source path does not exist: {value}")

    return errors


def _validate_concept(
    path: Path,
    *,
    bundle_root: Path,
    repository_root: Path,
) -> tuple[list[str], str]:
    relative_path = path.relative_to(bundle_root)
    metadata, body, parse_error = _parse_frontmatter(path)
    if parse_error:
        return [f"{relative_path}: {parse_error}"], body
    assert metadata is not None

    errors: list[str] = []
    concept_type = metadata.get("type")
    if not isinstance(concept_type, str) or not concept_type.strip():
        errors.append(f"{relative_path}: type must be a non-empty string")
    elif concept_type not in ALLOWED_TYPES:
        errors.append(
            f"{relative_path}: unsupported type {concept_type!r}; "
            f"expected one of {sorted(ALLOWED_TYPES)}"
        )

    for field in ("title", "description"):
        value = metadata.get(field)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            errors.append(f"{relative_path}: {field} must be a non-empty string")

    tags = metadata.get("tags")
    if tags is not None and (
        not isinstance(tags, list)
        or any(not isinstance(tag, str) or not tag.strip() for tag in tags)
    ):
        errors.append(f"{relative_path}: tags must be a list of non-empty strings")

    review_when = metadata.get("review_when")
    if not isinstance(review_when, list) or not review_when or any(
        not isinstance(trigger, str) or not trigger.strip() for trigger in review_when
    ):
        errors.append(f"{relative_path}: review_when must be a non-empty string list")

    errors.extend(
        _validate_source_paths(
            metadata,
            relative_path=relative_path,
            repository_root=repository_root,
        )
    )
    return errors, body


def _validate_index(
    path: Path,
    *,
    bundle_root: Path,
    body: str,
) -> list[str]:
    relative_path = path.relative_to(bundle_root)
    errors: list[str] = []
    resolved_targets: set[Path] = set()
    for raw_target in LINK_PATTERN.findall(body):
        target = _link_target(raw_target)
        local_path = _local_link_path(
            target,
            source=path,
            bundle_root=bundle_root,
        )
        if local_path is not None:
            resolved_targets.add(local_path.resolve())

    expected: list[Path] = [
        child.resolve()
        for child in path.parent.glob("*.md")
        if child.name not in RESERVED_FILENAMES
    ]
    expected.extend(
        child.resolve()
        for child in path.parent.iterdir()
        if child.is_dir() and any(child.rglob("*.md"))
    )
    for child in sorted(expected):
        if child not in resolved_targets:
            errors.append(
                f"{relative_path}: missing direct entry for "
                f"{child.relative_to(path.parent)}"
            )
    return errors


def validate_bundle(bundle_root: Path, repository_root: Path) -> list[str]:
    """Return human-readable validation errors for an OKF bundle."""
    bundle_root = bundle_root.resolve()
    repository_root = repository_root.resolve()
    errors: list[str] = []
    root_index = bundle_root / "index.md"
    if not root_index.is_file():
        return ["index.md: root index is required by DTVP's OKF profile"]

    metadata, root_body, parse_error = _parse_frontmatter(root_index)
    if parse_error:
        errors.append(f"index.md: {parse_error}")
        root_body = root_index.read_text(encoding="utf-8")
    elif metadata != {"okf_version": "0.1"}:
        errors.append('index.md: root frontmatter must declare only okf_version: "0.1"')

    indexes: dict[Path, str] = {root_index: root_body}
    concept_bodies: dict[Path, str] = {}
    for path in sorted(bundle_root.rglob("*.md")):
        if path == root_index:
            continue
        if path.name == "index.md":
            text = path.read_text(encoding="utf-8")
            if text.startswith("---"):
                errors.append(
                    f"{path.relative_to(bundle_root)}: only the root index may have frontmatter"
                )
            indexes[path] = text
            continue
        if path.name == "log.md":
            errors.append(
                f"{path.relative_to(bundle_root)}: log.md is not used; rely on git and CHANGELOG.md"
            )
            continue

        concept_errors, body = _validate_concept(
            path,
            bundle_root=bundle_root,
            repository_root=repository_root,
        )
        errors.extend(concept_errors)
        concept_bodies[path] = body

    directories_with_concepts = {path.parent for path in concept_bodies}
    directories_with_concepts.update(
        parent
        for path in concept_bodies
        for parent in path.parents
        if parent != bundle_root and bundle_root in parent.parents
    )
    for directory in sorted(directories_with_concepts):
        index_path = directory / "index.md"
        if not index_path.is_file():
            errors.append(
                f"{directory.relative_to(bundle_root)}/: directory requires index.md"
            )

    for path, body in indexes.items():
        errors.extend(_validate_index(path, bundle_root=bundle_root, body=body))

    for path, body in {**indexes, **concept_bodies}.items():
        for raw_target in LINK_PATTERN.findall(body):
            target = _link_target(raw_target)
            local_path = _local_link_path(
                target,
                source=path,
                bundle_root=bundle_root,
            )
            if local_path is None:
                continue
            resolved = local_path.resolve()
            try:
                resolved.relative_to(repository_root)
            except ValueError:
                errors.append(
                    f"{path.relative_to(bundle_root)}: local link escapes repository: {target}"
                )
                continue
            if not resolved.exists():
                errors.append(
                    f"{path.relative_to(bundle_root)}: broken local link: {target}"
                )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", nargs="?", default="docs", type=Path)
    args = parser.parse_args()
    repository_root = Path(__file__).resolve().parents[1]
    errors = validate_bundle(args.bundle, repository_root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print(f"OKF bundle is valid: {args.bundle}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
