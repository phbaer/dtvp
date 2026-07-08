import json
import os
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Tuple

import toml
from git import GitCommandError, Repo
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from src.agents.dependency_scanner import _extract_locked_version


def _common_manifests() -> list[str]:
    from src.languages import registry

    return list(registry.all_manifest_filenames())


def _common_lock_files() -> list[str]:
    from src.languages import registry

    return list(registry.all_lockfile_filenames())


_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
}


def list_tags(repo_path: str) -> List[str]:
    try:
        repo = Repo(repo_path)
        tags = [t.name for t in repo.tags]
        # return as-is; caller may sort
        return tags
    except Exception:
        return []


def _normalize_product_versions(product_versions: List[str] | None) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for value in product_versions or []:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _major_minor_version(value: str) -> str | None:
    match = re.match(r"^v?(\d+\.\d+)(?:[.\-+].*)?$", value.strip(), re.I)
    return match.group(1) if match else None


def _product_version_ref_candidates(version: str) -> set[str]:
    raw = version.strip()
    if not raw:
        return set()
    no_v = raw[1:] if raw.lower().startswith("v") else raw
    bases = {raw, no_v, f"v{no_v}"}
    minor = _major_minor_version(raw)
    if minor:
        bases.update({minor, f"v{minor}"})

    candidates: set[str] = set()
    for base in bases:
        if not base:
            continue
        candidates.update(
            {
                base,
                f"release/{base}",
                f"releases/{base}",
                f"rel/{base}",
                f"release-{base}",
                f"release_{base}",
                f"stable/{base}",
                f"maintenance/{base}",
            }
        )
    return {candidate.lower() for candidate in candidates}


def _display_ref_name(name: str) -> str:
    display = str(name or "").strip()
    for prefix in ("refs/remotes/", "refs/heads/", "remotes/"):
        if display.startswith(prefix):
            display = display[len(prefix) :]
    if display.startswith("origin/"):
        display = display[len("origin/") :]
    return display


def _target_ref_matches(name: str, product_versions: List[str]) -> List[str]:
    display = _display_ref_name(name)
    candidates = {
        display.lower(),
        display.rsplit("/", 1)[-1].lower(),
    }
    matches: List[str] = []
    for version in product_versions:
        wanted = _product_version_ref_candidates(version)
        if candidates & wanted:
            matches.append(version)
            continue
        for candidate in wanted:
            simple = candidate.rsplit("/", 1)[-1]
            if (
                display.lower().endswith(f"/{candidate}")
                or display.lower().endswith(f"-{simple}")
                or display.lower().endswith(f"_{simple}")
            ):
                matches.append(version)
                break
    return matches


def list_release_refs(
    repo_path: str,
    product_versions: List[str] | None = None,
) -> List[Dict[str, Any]]:
    """List git tags, default branches, and release branches as release references.

    Returns a list of dicts ``{"ref": str, "type": "tag"|"branch"}``
    where *ref* is the name usable with ``git show ref:path``.

    Tags are included as-is.  The default branch (``main`` or ``master``)
    is included first.  Remote branches matching ``release/<semver>``
    (or ``origin/release/<semver>``) are included with the display name
    ``release/<semver>``.

    When *product_versions* are provided, non-release branches that look
    like a listed product version are included too.  This lets DTVP scan
    exact versions already known from the vulnerability card.
    """
    refs: List[Dict[str, Any]] = []
    seen: set[str] = set()
    product_versions = _normalize_product_versions(product_versions)

    def add_ref(
        ref: str,
        ref_type: str,
        *,
        display: str | None = None,
        product_matches: List[str] | None = None,
    ) -> None:
        display_name = display or _display_ref_name(ref)
        key = f"{ref_type}:{display_name}"
        matches = product_matches or _target_ref_matches(display_name, product_versions)
        for existing in refs:
            existing_key = f"{existing.get('type')}:{existing.get('display', existing.get('ref'))}"
            if existing_key != key:
                continue
            if matches:
                merged = list(
                    dict.fromkeys(
                        [
                            *(existing.get("product_versions") or []),
                            *matches,
                        ]
                    )
                )
                existing["product_versions"] = merged
            return
        entry: Dict[str, Any] = {"ref": ref, "type": ref_type}
        if display_name != ref:
            entry["display"] = display_name
        if matches:
            entry["product_versions"] = list(dict.fromkeys(matches))
        refs.append(entry)
        seen.add(display_name)

    try:
        repo = Repo(repo_path, search_parent_directories=True)
        remote_ref_names = [str(r) for r in repo.refs]

        # Default branch (main/master) — check first so it appears at the top
        for default_name in ("main", "master"):
            remote_ref_name = f"origin/{default_name}"
            if remote_ref_name not in seen:
                # Check if this remote ref actually exists
                if remote_ref_name in remote_ref_names:
                    add_ref(remote_ref_name, "branch", display=default_name)
                    seen.add(default_name)

        for t in repo.tags:
            add_ref(t.name, "tag", display=t.name)
        # Remote-tracking release branches and product-version branches
        for remote_ref in repo.refs:
            name = str(remote_ref)
            display = _display_ref_name(name)
            product_matches = _target_ref_matches(display, product_versions)
            # Match origin/release/X.Y.Z or release/X.Y.Z
            is_release_branch = False
            for prefix in ("origin/release/", "release/"):
                if name.startswith(prefix) or name.endswith("/" + prefix.rstrip("/")):
                    is_release_branch = True
                    break
            if not is_release_branch:
                # Also check the short name
                if not display.startswith("release/") and not product_matches:
                    continue
            if display not in seen:
                add_ref(
                    name,
                    "branch",
                    display=display,
                    product_matches=product_matches,
                )
    except Exception:
        pass
    return refs


def _read_file_at_tag(repo: Repo, tag: str, path: str) -> str:
    try:
        # git show tag:path
        return repo.git.show(f"{tag}:{path}")
    except GitCommandError:
        raise


def gather_component_versions(
    repo_path: str,
    component_name: str,
    product_versions: List[str] | None = None,
) -> List[Dict[str, Any]]:
    """Gather versions of a component across release refs and current worktree.

    Checks git tags **and** ``release/*`` branches to determine what version
    of *component_name* was present at each release point of the project.

    Checks both manifest files (declared version specifiers) and lock files
    (actual resolved versions).  When a lock file provides a concrete version
    it is preferred over specifiers from manifests because it reflects what
    was actually installed.

    Returns a list of dicts:
        {"ref": str, "ref_type": "worktree"|"tag"|"branch",
         "versions": [str], "source": str}.
    """
    results, _ = _gather_component_versions_with_metadata(
        repo_path,
        component_name,
        product_versions=product_versions,
    )
    return results


def _gather_component_versions_with_metadata(
    repo_path: str,
    component_name: str,
    product_versions: List[str] | None = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    product_versions = _normalize_product_versions(product_versions)
    metadata: Dict[str, Any] = {
        "worktree_lock_files": [],
        "ref_lock_files": {},
        "processed_lock_files": {"WORKTREE": []},
        "any_lock_files_found": False,
        "product_versions_requested": product_versions,
        "product_versions_matched": {},
    }

    # --- Current worktree (filesystem only — no git needed) ---
    worktree_lock_files = _read_matching_files_from_fs(repo_path, _common_lock_files())
    metadata["worktree_lock_files"] = sorted(worktree_lock_files)
    metadata["any_lock_files_found"] = bool(worktree_lock_files)
    locked = _scan_lock_files_in_texts(worktree_lock_files, component_name)
    metadata["processed_lock_files"]["WORKTREE"] = [
        path
        for path, txt in sorted(worktree_lock_files.items())
        if _lock_text_mentions_component(path, txt, component_name)
    ]
    if locked:
        results.append(
            {
                "ref": "WORKTREE",
                "ref_type": "worktree",
                "versions": locked,
                "source": "lock",
            }
        )
    else:
        manifest_vers = _scan_manifests_in_texts(
            _read_matching_files_from_fs(repo_path, _common_manifests()), component_name
        )
        results.append(
            {
                "ref": "WORKTREE",
                "ref_type": "worktree",
                "versions": manifest_vers,
                "source": "manifest",
            }
        )

    # --- Git tags + release branches (requires git; gracefully skipped if absent) ---
    try:
        repo = Repo(repo_path, search_parent_directories=True)
    except Exception:
        return results, metadata

    release_refs = list_release_refs(repo_path, product_versions=product_versions)
    for entry in release_refs:
        git_ref = entry["ref"]
        ref_type = entry["type"]
        display = entry.get("display", git_ref)
        matched_product_versions = list(entry.get("product_versions") or [])
        for product_version in matched_product_versions:
            metadata["product_versions_matched"].setdefault(product_version, [])
            metadata["product_versions_matched"][product_version].append(display)

        lock_paths = _list_matching_files_at_ref(repo, git_ref, _common_lock_files())
        if lock_paths:
            metadata["ref_lock_files"][display] = lock_paths
            metadata["any_lock_files_found"] = True
        metadata["processed_lock_files"][display] = _lock_paths_with_component_at_ref(
            repo,
            git_ref,
            component_name,
            lock_paths,
        )

        lock_versions = _component_versions_at_ref(
            repo,
            git_ref,
            component_name,
            lock_paths,
            lock=True,
        )
        if lock_versions:
            results.append(
                {
                    "ref": display,
                    "ref_type": ref_type,
                    "versions": list(dict.fromkeys(lock_versions)),
                    "source": "lock",
                    "product_versions": matched_product_versions,
                }
            )
            continue

        manifest_versions = _component_versions_at_ref(
            repo,
            git_ref,
            component_name,
            _list_matching_files_at_ref(repo, git_ref, _common_manifests()),
            lock=False,
        )
        results.append(
            {
                "ref": display,
                "ref_type": ref_type,
                "versions": list(dict.fromkeys(manifest_versions)),
                "source": "manifest",
                "product_versions": matched_product_versions,
            }
        )

    return results, metadata


def _component_versions_at_ref(
    repo: Repo,
    ref: str,
    component_name: str,
    paths: List[str],
    *,
    lock: bool,
) -> List[str]:
    """Extract component versions from files at a specific git ref."""
    versions: List[str] = []
    for path in paths:
        try:
            txt = repo.git.show(f"{ref}:{path}")
        except Exception:
            continue
        if lock:
            ver = _extract_locked_version(txt, component_name, os.path.basename(path))
            if ver:
                versions.append(ver)
        else:
            versions.extend(_scan_manifests_in_texts({path: txt}, component_name))
    return versions


def _read_files_from_fs(repo_path: str) -> Dict[str, str]:
    return _read_matching_files_from_fs(repo_path, _common_manifests())


def _read_lock_files_from_fs(repo_path: str) -> Dict[str, str]:
    return _read_matching_files_from_fs(repo_path, _common_lock_files())


def _walk_repo_files(repo_path: str, filenames: List[str]) -> List[str]:
    wanted = set(filenames)
    matches: List[str] = []
    if not repo_path or not os.path.isdir(repo_path):
        return matches

    for root, dirs, files in os.walk(repo_path):
        if root != repo_path and os.path.isdir(os.path.join(root, ".git")):
            dirs[:] = []
            continue

        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
        for fname in files:
            if fname in wanted:
                full_path = os.path.join(root, fname)
                matches.append(os.path.relpath(full_path, repo_path))
    return sorted(matches)


def _read_matching_files_from_fs(
    repo_path: str, filenames: List[str]
) -> Dict[str, str]:
    texts: Dict[str, str] = {}
    for rel_path in _walk_repo_files(repo_path, filenames):
        path = os.path.join(repo_path, rel_path)
        try:
            with open(path, "r", errors="ignore") as f:
                texts[rel_path] = f.read()
        except Exception:
            continue
    return texts


def _list_matching_files_at_ref(
    repo: Repo, ref: str, filenames: List[str]
) -> List[str]:
    wanted = set(filenames)
    try:
        all_paths = repo.git.ls_tree("-r", "--name-only", ref).splitlines()
    except Exception:
        return []
    return sorted(path for path in all_paths if os.path.basename(path) in wanted)


def _scan_lock_files_in_texts(files: Dict[str, str], component_name: str) -> List[str]:
    """Extract resolved versions from lock file contents."""
    versions: List[str] = []
    for fname, txt in files.items():
        ver = _extract_locked_version(txt, component_name, os.path.basename(fname))
        if ver:
            versions.append(ver)
    return list(dict.fromkeys(versions))


def _lock_text_mentions_component(
    filename: str,
    text: str,
    component_name: str,
) -> bool:
    from src.languages import registry as _lang_registry

    base = os.path.basename(filename)
    plugin = _lang_registry.for_lockfile(base)
    if plugin is not None:
        return plugin.lockfile_mentions_component(text, base, component_name)
    return component_name.lower() in text.lower()


def _lock_paths_with_component_at_ref(
    repo: Repo,
    ref: str,
    component_name: str,
    lock_paths: List[str],
) -> List[str]:
    processed: List[str] = []
    for path in lock_paths:
        try:
            txt = repo.git.show(f"{ref}:{path}")
        except Exception:
            continue
        if _lock_text_mentions_component(path, txt, component_name):
            processed.append(path)
    return processed


def _format_lockfile_summary_lines(
    found_by_ref: Dict[str, List[str]],
    processed_by_ref: Dict[str, List[str]],
) -> List[str]:
    lines: List[str] = []
    all_refs = list(dict.fromkeys([*found_by_ref.keys(), *processed_by_ref.keys()]))
    for ref in all_refs:
        found = found_by_ref.get(ref, [])
        processed = processed_by_ref.get(ref, [])
        found_text = ", ".join(found) if found else "none"
        processed_text = ", ".join(processed) if processed else "none"
        lines.append(f"  {ref}: found [{found_text}]")
        lines.append(f"  {ref}: processed [{processed_text}]")
    return lines


def _scan_manifests_in_texts(files: Dict[str, str], component_name: str) -> List[str]:
    versions: List[str] = []
    for fname, txt in files.items():
        lf = fname.lower()
        try:
            from src.languages import registry as _lang_registry

            plugin = _lang_registry.for_manifest(os.path.basename(fname))
            if plugin is not None and plugin.name == "java":
                versions.extend(
                    plugin.parse_manifest_versions(
                        txt,
                        os.path.basename(fname),
                        component_name,
                    )
                )
                continue

            if lf.endswith("package.json"):
                data = json.loads(txt)
                deps = {}
                for k in (
                    "dependencies",
                    "devDependencies",
                    "peerDependencies",
                    "optionalDependencies",
                ):
                    deps.update(data.get(k, {}))
                for name, ver in deps.items():
                    if name.lower() == component_name.lower():
                        versions.append(ver.strip())
                continue

            if (
                lf.endswith("pyproject.toml")
                or lf.endswith("cargo.toml")
                or lf.endswith("cargo.toml")
            ):
                try:
                    data = toml.loads(txt)
                except Exception:
                    data = {}
                import re

                for l in txt.splitlines():
                    if component_name.lower() in l.lower():
                        m = re.search(
                            rf"{component_name}\s*==\s*([0-9a-zA-Z\.\-_]+)", l, re.I
                        )
                        if m:
                            versions.append(m.group(1))
                # pyproject: look under project.dependencies or tool.poetry.dependencies
                proj = data.get("project", {})
                if isinstance(proj, dict):
                    deps = proj.get("dependencies", {})
                    if isinstance(deps, list):
                        # list entries may be 'name version' or PEP 508
                        # specifiers like 'werkzeug>=2.0.0'
                        for entry in deps:
                            if (
                                isinstance(entry, str)
                                and component_name.lower() in entry.lower()
                            ):
                                parts = entry.split()
                                if len(parts) > 1:
                                    versions.append(parts[-1])
                                else:
                                    # PEP 508: "pkg>=1.0", "pkg[extra]~=2.0"
                                    m = re.search(
                                        r"[><=~!]+\s*([0-9][0-9a-zA-Z.\-_]*)",
                                        entry,
                                    )
                                    if m:
                                        versions.append(m.group(1))
                    elif isinstance(deps, dict):
                        for name, ver in deps.items():
                            if name.lower() == component_name.lower():
                                versions.append(ver if isinstance(ver, str) else "")
                # poetry
                poetry = data.get("tool", {}).get("poetry", {})
                if poetry:
                    deps = poetry.get("dependencies", {})
                    for name, ver in deps.items():
                        if name.lower() == component_name.lower():
                            versions.append(ver if isinstance(ver, str) else "")
                # cargo
                cargo = data.get("dependencies", {})
                for name, ver in cargo.items():
                    if name.lower() == component_name.lower():
                        if isinstance(ver, str):
                            versions.append(ver)
                        elif isinstance(ver, dict) and "version" in ver:
                            versions.append(ver.get("version"))
                continue

            if lf.endswith("cargo.toml"):
                try:
                    data = toml.loads(txt)
                    deps = data.get("dependencies", {})
                    for name, ver in deps.items():
                        if name.lower() == component_name.lower():
                            if isinstance(ver, str):
                                versions.append(ver)
                            elif isinstance(ver, dict) and "version" in ver:
                                versions.append(ver.get("version"))
                except Exception:
                    pass
                continue

            if lf.endswith("package.json"):
                # handled above
                continue

            if lf.endswith("pom.xml"):
                try:
                    root = ET.fromstring(txt)
                    ns = {k: v for k, v in root.attrib.items()}
                    # find dependencies
                    for dep in root.findall(".//dependency"):
                        gid = dep.find("groupId")
                        aid = dep.find("artifactId")
                        ver = dep.find("version")
                        if gid is not None and aid is not None and ver is not None:
                            name = f"{gid.text}:{aid.text}"
                            if component_name.lower() in name.lower():
                                versions.append(ver.text)
                except Exception:
                    pass
                continue

            if lf.endswith("go.mod"):
                # parse module lines like: require github.com/pkg/errors v0.9.1
                for line in txt.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2 and component_name.lower() in parts[0].lower():
                        versions.append(parts[-1])
                continue

            if lf.endswith("vcpkg.json"):
                try:
                    data = json.loads(txt)
                    for dep in data.get("dependencies", []):
                        name = dep if isinstance(dep, str) else dep.get("name", "")
                        ver = (
                            None
                            if isinstance(dep, str)
                            else dep.get("version>=", dep.get("version", ""))
                        )
                        if name.lower() == component_name.lower() and ver:
                            versions.append(ver)
                    # Also check overrides
                    for ov in data.get("overrides", []):
                        if (
                            isinstance(ov, dict)
                            and ov.get("name", "").lower() == component_name.lower()
                        ):
                            ver = ov.get("version")
                            if ver:
                                versions.append(ver)
                except Exception:
                    pass
                continue

            if lf.endswith("conanfile.txt"):
                # [requires] section: name/version
                import re as _re

                in_requires = False
                for line in txt.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("["):
                        in_requires = stripped.lower() == "[requires]"
                        continue
                    if in_requires and component_name.lower() in stripped.lower():
                        m = _re.search(r"/([0-9][0-9a-zA-Z\.\-_]*)", stripped)
                        if m:
                            versions.append(m.group(1))
                continue

            if lf.endswith("conanfile.py"):
                # requires("name/version") or self.requires("name/version")
                import re as _re

                for line in txt.splitlines():
                    if component_name.lower() in line.lower():
                        m = _re.search(
                            rf"{component_name}/([0-9][0-9a-zA-Z\.\-_]*)",
                            line,
                            _re.I,
                        )
                        if m:
                            versions.append(m.group(1))
                continue

            if lf.endswith("cmakelists.txt"):
                # find_package(name version) or FetchContent_Declare version
                import re as _re

                for line in txt.splitlines():
                    if component_name.lower() in line.lower():
                        m = _re.search(
                            rf"find_package\s*\(\s*{component_name}\s+([0-9][0-9a-zA-Z\.\-_]*)",
                            line,
                            _re.I,
                        )
                        if m:
                            versions.append(m.group(1))
                            continue
                        m = _re.search(
                            r"GIT_TAG\s+[v]?([0-9][0-9a-zA-Z\.\-_]*)",
                            line,
                            _re.I,
                        )
                        if m:
                            versions.append(m.group(1))
                            continue
                        m = _re.search(
                            r"VERSION\s+([0-9][0-9a-zA-Z\.\-_]*)",
                            line,
                            _re.I,
                        )
                        if m:
                            versions.append(m.group(1))
                continue

            # Fallback heuristic: scan lines for component name and version-like tokens
            import re

            for line in txt.splitlines():
                if component_name.lower() in line.lower():
                    # equality or pinned
                    m = re.search(
                        rf"{component_name}\s*==\s*([0-9a-zA-Z\.\-_]+)", line, re.I
                    )
                    if m:
                        versions.append(m.group(1))
                        continue
                    # name >= or ~= or <= or simple version
                    m = re.search(
                        rf"{component_name}[^\n]*?([0-9]+\.[0-9a-zA-Z\.\-_]+)",
                        line,
                        re.I,
                    )
                    if m:
                        versions.append(m.group(1))
                        continue
                    # JSON style: "name": "1.2.3"
                    m = re.search(
                        rf'"{component_name}"\s*[:=]\s*"([0-9a-zA-Z\.\-_]+)"',
                        line,
                        re.I,
                    )
                    if m:
                        versions.append(m.group(1))
        except Exception:
            continue
    return versions


def version_in_affected_ranges(
    ver: str,
    affected_ranges: List[Dict[str, Any]],
    affected_versions: List[str] | None = None,
) -> Tuple[bool, str, List[str]]:
    """Check if a version string falls into any affected ranges.

    Also checks the explicit *affected_versions* list when provided (e.g.
    from OSV ``versions`` fields).

    Returns ``(is_affected, note, trace)`` where *trace* is a list of
    human-readable lines documenting every comparison that was made.

    """
    normalized_ver = _normalize_version_string(ver)
    trace: List[str] = []

    explicit_versions = [
        candidate
        for candidate in (
            _normalize_version_string(v) for v in (affected_versions or [])
        )
        if candidate
    ]
    explicit_set = set(explicit_versions)
    if normalized_ver and explicit_set:
        if normalized_ver in explicit_set:
            trace.append(f"version={ver}: MATCH in explicit affected versions list")
            return True, "version is in the explicit affected versions list", trace
        trace.append(f"version={ver}: no match in explicit affected versions list")

    semver_ranges = [
        item for item in affected_ranges if item.get("type") in ("SEMVER", "ECOSYSTEM")
    ]
    git_ranges = [item for item in affected_ranges if item.get("type") == "GIT"]

    parsed_version = _parse_packaging_version(normalized_ver or ver)
    if semver_ranges and parsed_version is not None:
        for item in semver_ranges:
            event = item.get("event") or {}
            source = item.get("source", "?")

            # GitHub Advisory API stores ranges as a pre-built specifier string
            # e.g. ">= 4.0.0, <= 4.17.22" under event["range"] instead of the
            # standard OSV event["introduced"] / event["fixed"] keys.
            prebuilt_range = event.get("range", "").strip()
            if prebuilt_range:
                try:
                    spec = SpecifierSet(prebuilt_range)
                except Exception:
                    trace.append(
                        f"version={ver}: skipped unparseable range string "
                        f"'{prebuilt_range}' (source={source})"
                    )
                    continue
                if parsed_version in spec:
                    trace.append(
                        f"version={ver}: MATCH in affected range {spec} (source={source})"
                    )
                    return True, f"version falls in affected range {spec}", trace
                trace.append(
                    f"version={ver}: outside affected range {spec} (source={source})"
                )
                continue

            introduced = _normalize_version_string(event.get("introduced"))
            fixed = _normalize_version_string(event.get("fixed"))
            spec = _specifier_from_event(introduced, fixed)
            if not spec:
                trace.append(
                    f"version={ver}: skipped unusable {item.get('type', '?')} range "
                    f"introduced={introduced or '?'} fixed={fixed or 'none'} (source={source})"
                )
                continue
            if parsed_version in spec:
                trace.append(
                    f"version={ver}: MATCH in affected range {spec} (source={source})"
                )
                return True, f"version falls in affected range {spec}", trace
            trace.append(
                f"version={ver}: outside affected range {spec} (source={source})"
            )

        return False, "version is outside the affected ranges", trace

    if semver_ranges and parsed_version is None:
        trace.append(
            f"version={ver}: could not parse version for semver comparison — assuming affected"
        )
        return True, "assumed affected (version could not be parsed)", trace

    if git_ranges:
        trace.append(f"version={ver}: only GIT ranges available — assuming affected")
        return True, "assumed affected (only GIT ranges available)", trace

    if explicit_set:
        trace.append(
            f"version={ver}: explicit affected versions present and no match found"
        )
        return False, "version is not in the explicit affected versions list", trace

    trace.append(
        f"version={ver}: no usable affected ranges or explicit versions — assuming affected"
    )
    return True, "assumed affected (no usable version constraints)", trace


def summarize_ranges_for_debug(
    affected_ranges: List[Dict[str, Any]],
    affected_versions: List[str] | None = None,
) -> List[str]:
    """Return concise range summaries for debug output."""
    summaries: List[str] = []
    for item in affected_ranges:
        event = item.get("event") or {}
        summaries.append(
            f"{item.get('type', '?')} range: introduced={event.get('introduced', '?')} "
            f"fixed={event.get('fixed', 'none')} (source={item.get('source', '?')})"
        )
    if affected_versions:
        summaries.append(f"Explicit affected versions: {len(affected_versions)} listed")
    return summaries


def inventory_versions(
    repo_path: str,
    component_name: str,
    affected_ranges: List[Dict[str, Any]],
    locked_version: str | None = None,
    affected_versions: List[str] | None = None,
    affected_product_versions: List[str] | None = None,
) -> Dict[str, Any]:
    """Produce a version inventory across all release refs.

    Iterates over the current worktree, git tags, and ``release/*``
    branches, extracts the version of *component_name* at each point,
    and checks it against the advisory's affected ranges.

    This is **not** a what-if analysis — it answers:

    1. Which version is currently pinned (lock file / manifest)?
    2. Which version was pinned at each past release point?
    3. Was that version in the affected range?

    When *locked_version* is provided it is treated as the **actual
    installed version** and checked first.  If the locked version is
    outside the affected ranges the component is considered not affected
    regardless of what manifest version specifiers say.

    *affected_versions* is an optional explicit list of affected version
    strings (e.g. from OSV ``versions`` fields).
    """
    rows: List[Dict[str, Any]] = []
    all_trace: List[str] = []
    any_affected = False
    affected_refs: List[str] = []
    affected_product_versions = _normalize_product_versions(affected_product_versions)

    # Document the ranges being used
    semver_ranges = [
        r for r in affected_ranges if r.get("type") in ("SEMVER", "ECOSYSTEM")
    ]
    git_ranges = [r for r in affected_ranges if r.get("type") == "GIT"]
    all_trace.append(
        f"Affected ranges: {len(semver_ranges)} SEMVER/ECOSYSTEM, "
        f"{len(git_ranges)} GIT, "
        f"{len(affected_versions or [])} explicit versions"
    )
    if affected_versions:
        all_trace.append(f"  Explicit affected versions: {affected_versions}")
    if affected_product_versions:
        all_trace.append(
            f"  DTVP affected product versions: {affected_product_versions}"
        )
    for r in semver_ranges:
        ev = r.get("event", {})
        prebuilt_range = str(ev.get("range", "")).strip()
        if prebuilt_range:
            all_trace.append(
                f"  SEMVER range: {prebuilt_range} (source={r.get('source', '?')})"
            )
        else:
            all_trace.append(
                f"  SEMVER range: introduced={ev.get('introduced')} "
                f"fixed={ev.get('fixed')} (source={r.get('source', '?')})"
            )
    for r in git_ranges:
        ev = r.get("event", {})
        all_trace.append(
            f"  GIT range: introduced={ev.get('introduced')} "
            f"fixed={ev.get('fixed')} (source={r.get('source', '?')}) "
            f"[not usable for semver comparison]"
        )

    # ---- 1. Check the locked (resolved) version first ----
    locked_affected: bool | None = None
    if locked_version:
        is_aff, note, trace = version_in_affected_ranges(
            locked_version, affected_ranges, affected_versions
        )
        locked_affected = is_aff
        all_trace.extend(trace)
        rows.append(
            {
                "component_version": locked_version,
                "affected": "YES" if is_aff else "No",
                "ref": "LOCKED",
                "ref_type": "lock",
                "notes": f"lock file — {note}",
            }
        )
        if is_aff:
            any_affected = True
            affected_refs.append("LOCKED")

    # ---- 2. Scan across worktree, tags, and release branches ----
    gathered, gather_meta = _gather_component_versions_with_metadata(
        repo_path,
        component_name,
        product_versions=affected_product_versions,
    )

    for entry in gathered:
        ref = entry.get("ref", entry.get("tag", "?"))
        ref_type = entry.get("ref_type", "tag")
        vers = entry.get("versions") or []
        source = entry.get("source", "manifest")
        product_versions_for_ref = list(entry.get("product_versions") or [])
        product_version = ", ".join(product_versions_for_ref)
        if not vers:
            rows.append(
                {
                    "component_version": "-",
                    "affected": "No",
                    "ref": ref,
                    "ref_type": ref_type,
                    "source": source,
                    "product_version": product_version,
                    "notes": "not found",
                }
            )
            continue
        for ver in vers:
            is_aff, note, trace = version_in_affected_ranges(
                ver, affected_ranges, affected_versions
            )
            all_trace.extend(trace)
            rows.append(
                {
                    "component_version": ver,
                    "affected": "YES" if is_aff else "No",
                    "ref": ref,
                    "ref_type": ref_type,
                    "source": source,
                    "product_version": product_version,
                    "notes": note,
                }
            )
            if is_aff:
                any_affected = True
                affected_refs.append(ref)

    matched_product_versions = {
        str(version)
        for version in gather_meta.get("product_versions_matched", {}).keys()
    }
    for product_version in affected_product_versions:
        if product_version in matched_product_versions:
            continue
        rows.append(
            {
                "component_version": "-",
                "affected": "No",
                "ref": product_version,
                "ref_type": "product-version",
                "source": "dtvp",
                "product_version": product_version,
                "notes": (
                    "DTVP reported this affected product version, but no matching "
                    "tag or branch was found in the repository"
                ),
            }
        )
        all_trace.append(
            "DTVP affected product version "
            f"{product_version}: no matching tag or branch found"
        )

    # ---- 3. Build worst-case summary ----
    current_rows = [
        row
        for row in rows
        if row.get("ref") in ("LOCKED", "WORKTREE")
        and row.get("component_version") != "-"
    ]
    current_affected = any(row.get("affected") == "YES" for row in current_rows)
    component_found = any(row.get("component_version") != "-" for row in rows)
    warnings: List[str] = []
    if not gather_meta.get("any_lock_files_found"):
        warning = (
            "No lock files found in the current worktree or scanned release refs; "
            "assuming worst-case exposure."
        )
        warnings.append(warning)
        all_trace.append(warning)

    # Overall affected = any tracked ref (worktree, tags, release branches).
    # A project is considered affected if ANY released or current version
    # shipped the vulnerable component.  Reachability analysis (workspace
    # only) can down-score the finding, but cannot alone clear it.
    overall_affected = any_affected if component_found else False

    if current_affected:
        note = "current workspace version is in the affected range"
    elif overall_affected:
        note = (
            "current workspace version is outside the affected range, "
            "but one or more tracked releases shipped an affected version"
        )
    else:
        note = "no tracked version (workspace or releases) is in the affected range"

    worst_case: Dict[str, Any] = {
        "affected": overall_affected,
        "current_workspace_affected": current_affected,
        "note": note,
    }
    if warnings:
        worst_case["warnings"] = warnings
        if component_found:
            worst_case["affected"] = True
        worst_case["note"] = warning
    if locked_version:
        worst_case["locked_version"] = locked_version
    if affected_refs:
        worst_case["affected_refs"] = list(dict.fromkeys(affected_refs))

    # Historical summary: which past releases were affected?
    historical = [
        r
        for r in rows
        if r["affected"] == "YES" and r.get("ref") not in ("LOCKED", "WORKTREE")
    ]
    if historical:
        worst_case["historical_affected"] = [
            {
                "ref": r["ref"],
                "ref_type": r["ref_type"],
                "component_version": r["component_version"],
            }
            for r in historical
        ]

    return {
        "version_table": rows,
        "worst_case": worst_case,
        "trace": all_trace,
        "comparison_inputs": {
            "repo_path": repo_path,
            "component_name": component_name,
            "locked_version": locked_version,
            "lock_files_found": sorted(gather_meta.get("worktree_lock_files", [])),
            "lock_files_found_by_ref": {
                "WORKTREE": sorted(gather_meta.get("worktree_lock_files", [])),
                **{
                    ref: sorted(paths)
                    for ref, paths in sorted(
                        gather_meta.get("ref_lock_files", {}).items()
                    )
                },
            },
            "lock_files_processed_by_ref": {
                ref: sorted(paths)
                for ref, paths in sorted(
                    gather_meta.get("processed_lock_files", {}).items()
                )
            },
            "historical_lock_refs": sorted(
                gather_meta.get("ref_lock_files", {}).keys()
            ),
            "affected_ranges_summary": summarize_ranges_for_debug(
                affected_ranges,
                affected_versions,
            ),
            "affected_versions_count": len(affected_versions or []),
            "affected_product_versions": affected_product_versions,
            "affected_product_versions_count": len(affected_product_versions),
            "affected_product_version_refs": {
                version: sorted(refs)
                for version, refs in sorted(
                    gather_meta.get("product_versions_matched", {}).items()
                )
            },
        },
    }


# ----------------------------------------------------------------------- #
# What-if remediation analysis
# ----------------------------------------------------------------------- #


def analyze_what_if(
    version_inventory: Dict[str, Any],
    affected_ranges: List[Dict[str, Any]],
    fixed_versions: List[str] | None = None,
    affected_versions: List[str] | None = None,
) -> Dict[str, Any]:
    """Produce a what-if remediation analysis.

    Given the *version_inventory* (from :func:`inventory_versions`),
    determines:

    1. **Current exposure** — is the currently pinned version affected?
    2. **Remediation options** — which fixed versions resolve the issue?
    3. **Upgrade impact** — for each fixed version, how big is the jump
       from the current version?

    Returns a dict with:
        current_version   — the version currently pinned (or None)
        current_affected  — whether the current version is affected
        fixed_versions    — deduplicated list of known fixed versions
        remediation       — list of upgrade options with version delta info
        summary           — human-readable one-liner
    """
    table = version_inventory.get("version_table", [])
    worst = version_inventory.get("worst_case", {})

    # --- Determine current version (prefer locked, then worktree) ---
    current_version: str | None = None
    current_affected = False
    current_source: str | None = None

    for row in table:
        if row.get("ref") == "LOCKED" and row.get("component_version", "-") != "-":
            current_version = row["component_version"]
            current_affected = row.get("affected") == "YES"
            current_source = "lock file"
            break
    if current_version is None:
        for row in table:
            if (
                row.get("ref") == "WORKTREE"
                and row.get("component_version", "-") != "-"
            ):
                current_version = row["component_version"]
                current_affected = row.get("affected") == "YES"
                current_source = row.get("source", "manifest")
                break

    # --- Collect fixed versions from advisory ranges ---
    all_fixed: list[str] = list(fixed_versions or [])
    for r in affected_ranges:
        ev = r.get("event", {})
        fixed = ev.get("fixed")
        if fixed and fixed not in all_fixed:
            all_fixed.append(fixed)
    # Deduplicate preserving order
    all_fixed = list(dict.fromkeys(all_fixed))

    # --- Build remediation options ---
    remediation: list[Dict[str, Any]] = []
    for fix_ver in all_fixed:
        option: Dict[str, Any] = {
            "target_version": fix_ver,
        }
        if current_version:
            option["from_version"] = current_version
            option["change"] = _describe_version_delta(current_version, fix_ver)
        remediation.append(option)

    # --- Component not found in project ---
    component_not_found = (
        all(row.get("component_version", "-") == "-" for row in table)
        if table
        else True
    )

    # --- Summary ---
    if component_not_found:
        summary = "Component not found in project — no remediation needed."
    elif not current_affected:
        summary = (
            f"Current version {current_version} ({current_source}) is "
            f"not in the affected range — no action required."
        )
    elif all_fixed:
        targets = ", ".join(all_fixed)
        summary = (
            f"Current version {current_version} ({current_source}) IS affected. "
            f"Upgrade to {targets} to remediate."
        )
    else:
        summary = (
            f"Current version {current_version} ({current_source}) IS affected "
            f"but no fixed version is known from the advisory."
        )

    return {
        "current_version": current_version,
        "current_source": current_source,
        "current_affected": current_affected,
        "component_not_found": component_not_found,
        "fixed_versions": all_fixed,
        "remediation": remediation,
        "summary": summary,
    }


def _describe_version_delta(from_ver: str, to_ver: str) -> str:
    """Return a human-readable description of the version jump."""
    from_parts = _parse_semver_loose(from_ver)
    to_parts = _parse_semver_loose(to_ver)
    if from_parts is None or to_parts is None:
        return f"{from_ver} → {to_ver}"

    f_major, f_minor, f_patch = from_parts
    t_major, t_minor, t_patch = to_parts

    if t_major > f_major:
        return f"{from_ver} → {to_ver} (major upgrade)"
    elif t_minor > f_minor:
        return f"{from_ver} → {to_ver} (minor upgrade)"
    elif t_patch > f_patch:
        return f"{from_ver} → {to_ver} (patch upgrade)"
    elif (t_major, t_minor, t_patch) == (f_major, f_minor, f_patch):
        return f"{from_ver} → {to_ver} (same version)"
    else:
        return f"{from_ver} → {to_ver} (downgrade)"


def _parse_semver_loose(ver: str) -> tuple[int, int, int] | None:
    """Best-effort parse of a version string into (major, minor, patch)."""
    import re

    ver = ver.lstrip("v")
    m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", ver)
    if not m:
        return None
    return (
        int(m.group(1)),
        int(m.group(2) or 0),
        int(m.group(3) or 0),
    )


def _normalize_version_string(ver: Any) -> str | None:
    """Normalize common version spellings for comparison."""
    if ver is None:
        return None
    text = str(ver).strip()
    if not text or text in {"*", "unknown"}:
        return None
    return text[1:] if text.startswith("v") else text


def _parse_packaging_version(ver: str | None) -> Version | None:
    if not ver:
        return None
    try:
        return Version(ver)
    except InvalidVersion:
        return None


def _specifier_from_event(
    introduced: str | None, fixed: str | None
) -> SpecifierSet | None:
    """Convert normalized OSV event bounds into a packaging specifier set."""
    parts: list[str] = []
    if introduced and introduced not in {"0", "0.0", "0.0.0"}:
        parts.append(f">={introduced}")
    if fixed:
        parts.append(f"<{fixed}")
    if not parts:
        return None
    try:
        return SpecifierSet(",".join(parts))
    except Exception:
        return None
