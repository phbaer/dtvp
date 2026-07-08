import asyncio
import hashlib
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import quote, urlsplit, urlunsplit

from git import GitCommandError, Repo

logger = logging.getLogger(__name__)

# Persistent directory for cloned repos.
_REPOS_DIR = os.environ.get("AGENTYZER_REPOS_DIR", "repos")

# Pattern to strip embedded credentials from URLs and error messages.
_CREDENTIAL_RE = re.compile(r"://[^@/]+@")


def _sanitize(text: str) -> str:
    """Remove embedded credentials from a string (URLs, git stderr, etc.)."""
    return _CREDENTIAL_RE.sub("://***@", text)


class RepoError(RuntimeError):
    """Raised when repository operations fail. Messages are credential-free."""


def _repo_dir(url: str) -> str:
    """Derive a stable, unique local directory name from the repo URL."""
    # Strip credentials from the URL before hashing so the same repo
    # always maps to the same directory regardless of auth changes.
    parts = urlsplit(url)
    clean = urlunsplit((parts.scheme, parts.hostname or "", parts.path, "", ""))
    digest = hashlib.sha256(clean.encode()).hexdigest()[:12]
    # Use the last path component (repo name) for readability.
    name = Path(parts.path).stem or "repo"
    return os.path.join(_REPOS_DIR, f"{name}-{digest}")


def _auth_url(url: str, auth: Dict[str, Any]) -> str:
    """Embed credentials into the clone URL."""
    username = auth.get("username")
    password = auth.get("password")
    token = auth.get("token")

    parts = urlsplit(url)

    if username and password:
        netloc = (
            f"{quote(username, safe='')}:{quote(password, safe='')}@{parts.hostname}"
        )
        if parts.port:
            netloc += f":{parts.port}"
        url = urlunsplit(
            (parts.scheme, netloc, parts.path, parts.query, parts.fragment)
        )
        logger.debug("Clone URL rewritten with basic auth (user/pass)")
    elif token:
        netloc = f"{quote(token, safe='')}@{parts.hostname}"
        if parts.port:
            netloc += f":{parts.port}"
        url = urlunsplit(
            (parts.scheme, netloc, parts.path, parts.query, parts.fragment)
        )
        logger.debug("Clone URL rewritten with token auth")

    return url


async def prepare_repo(component_cfg: Dict[str, Any]) -> str:
    """Clone or update a repo for scanning. Returns local path.

    If the repo already exists on disk it is fetched and reset to the
    latest remote HEAD.  Otherwise a fresh clone is performed.

    Git operations are blocking I/O — they are offloaded to a thread so
    the asyncio event loop stays responsive (prevents 504 from upstream
    proxies during large clones).

    Raises :class:`RepoError` with a sanitized message on failure.
    """
    url = component_cfg.get("url")
    if not url:
        raise RepoError("No url in component config")

    safe_url = _sanitize(url)
    auth = component_cfg.get("auth") or {}
    authenticated_url = _auth_url(url, auth)

    dest = _repo_dir(url)
    os.makedirs(_REPOS_DIR, exist_ok=True)

    await asyncio.to_thread(_sync_repo, authenticated_url, safe_url, dest)
    return dest


def _sync_repo(authenticated_url: str, safe_url: str, dest: str) -> None:
    """Blocking helper that performs the actual git clone/fetch."""
    if os.path.isdir(os.path.join(dest, ".git")):
        # Repo already cloned — update it.
        logger.info("Repo exists at %s — pulling latest changes", dest)
        try:
            repo = Repo(dest)
            # Update the remote URL in case credentials changed.
            origin = repo.remotes.origin
            with origin.config_writer as cw:
                cw.set("url", authenticated_url)
            origin.fetch()
            # Reset working tree to remote HEAD.
            default_branch = _default_branch(repo)
            repo.head.reset(f"origin/{default_branch}", index=True, working_tree=True)
            logger.info("Updated %s to origin/%s", dest, default_branch)
        except Exception:
            logger.exception("Update failed for %s — re-cloning", safe_url)
            import shutil

            shutil.rmtree(dest, ignore_errors=True)
            try:
                Repo.clone_from(authenticated_url, dest)
            except GitCommandError as clone_exc:
                raise RepoError(
                    f"Failed to clone repository {safe_url}: {_sanitize(str(clone_exc))}"
                ) from None
            except Exception as clone_exc:
                raise RepoError(
                    f"Failed to clone repository {safe_url}: {_sanitize(str(clone_exc))}"
                ) from None
    else:
        # Fresh clone.
        logger.info("Cloning %s → %s", safe_url, dest)
        try:
            Repo.clone_from(authenticated_url, dest)
            logger.info("Clone successful: %s", dest)
        except GitCommandError as exc:
            logger.error("Clone failed for %s: %s", safe_url, _sanitize(str(exc)))
            raise RepoError(
                f"Failed to clone repository {safe_url}: {_sanitize(exc.stderr or str(exc))}"
            ) from None
        except Exception as exc:
            logger.error("Clone failed for %s: %s", safe_url, _sanitize(str(exc)))
            raise RepoError(
                f"Failed to clone repository {safe_url}: {_sanitize(str(exc))}"
            ) from None


def _default_branch(repo: Repo) -> str:
    """Detect the default branch (main, master, etc.)."""
    try:
        # Check what origin/HEAD points to.
        ref = repo.git.symbolic_ref("refs/remotes/origin/HEAD", short=True)
        return ref.replace("origin/", "")
    except GitCommandError:
        pass
    # Fallback: try common names.
    for name in ("main", "master"):
        if f"origin/{name}" in [r.name for r in repo.remotes.origin.refs]:
            return name
    # Last resort: current branch.
    return repo.active_branch.name


def find_component(
    repo_path: str,
    component_name: str,
    *,
    sbom_attributed: bool = False,
) -> Dict[str, Any]:
    """Look for component_name in dependency manifests and lock files.

    Returns a dict with:
            - found: True if present via repo evidence or SBOM attribution
            - repo_found: True if mentioned in repo manifests or lock files
            - sbom_attributed: True if upstream attribution already placed the component in the project SBOM
            - presence_basis: one of direct, transitive, sbom_attributed, not_found
      - direct: True if declared in a top-level manifest
      - transitive: True if only found in lock / resolved files
      - declared_in: list of manifest paths where it appears
      - locked_version: version string from a lock file (if found)
      - lock_files: list of lock file paths where it appears
    """
    findings: Dict[str, Any] = {
        "found": False,
        "repo_found": False,
        "sbom_attributed": sbom_attributed,
        "presence_basis": "not_found",
        "direct": False,
        "transitive": False,
        "declared_in": [],
        "locked_version": None,
        "lock_files": [],
    }
    if not component_name:
        logger.warning("find_component called with empty component_name — skipping")
        return findings

    # --- manifests (direct declarations) ---
    from src.languages import registry as _lang_registry

    _MANIFESTS = _lang_registry.all_manifest_filenames()
    # --- lock / resolved files (transitive deps) ---
    _LOCK_FILES = _lang_registry.all_lockfile_filenames()

    for root, dirs, files in os.walk(repo_path):
        # Skip hidden / VCS dirs
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for fname in files:
            is_manifest = fname in _MANIFESTS
            is_lock = fname in _LOCK_FILES
            if not is_manifest and not is_lock:
                continue

            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="ignore") as f:
                    txt = f.read()
            except Exception:
                continue

            plugin = (
                _lang_registry.for_manifest(fname)
                if is_manifest
                else _lang_registry.for_lockfile(fname)
            )
            if is_manifest and plugin is not None:
                has_component = plugin.manifest_mentions_component(
                    txt,
                    fname,
                    component_name,
                )
            elif is_lock and plugin is not None:
                has_component = plugin.lockfile_mentions_component(
                    txt,
                    fname,
                    component_name,
                )
            else:
                has_component = component_name.lower() in txt.lower()

            if not has_component:
                continue

            findings["found"] = True
            findings["repo_found"] = True
            rel = os.path.relpath(fpath, repo_path)

            if is_manifest:
                findings["direct"] = True
                findings["declared_in"].append(rel)
                logger.debug("Found '%s' in manifest %s", component_name, rel)
            if is_lock:
                findings["lock_files"].append(rel)
                if findings["locked_version"] is None:
                    findings["locked_version"] = _extract_locked_version(
                        txt,
                        component_name,
                        fname,
                    )
                logger.debug("Found '%s' in lock file %s", component_name, rel)

    # If it only appears in lock files, it's transitive
    if findings["found"] and not findings["direct"]:
        findings["transitive"] = True

    if findings["direct"]:
        findings["presence_basis"] = "direct"
    elif findings["transitive"]:
        findings["presence_basis"] = "transitive"
    elif findings["sbom_attributed"]:
        findings["found"] = True
        findings["presence_basis"] = "sbom_attributed"

    logger.info(
        "find_component(%s): found=%s, repo_found=%s, sbom_attributed=%s, basis=%s, direct=%s, transitive=%s, "
        "declared_in=%s, lock_files=%s, locked_version=%s",
        component_name,
        findings["found"],
        findings["repo_found"],
        findings["sbom_attributed"],
        findings["presence_basis"],
        findings["direct"],
        findings["transitive"],
        findings["declared_in"],
        findings["lock_files"],
        findings["locked_version"],
    )
    return findings


def _extract_locked_version(
    text: str,
    component_name: str,
    filename: str,
) -> str | None:
    """Best-effort extraction of the pinned version from a lock file."""
    from src.languages import registry as _lang_registry

    basename = os.path.basename(filename)
    plugin = _lang_registry.for_lockfile(basename)
    if plugin is not None:
        return plugin.extract_locked_version(text, component_name, basename)
    return None


# ---------------------------------------------------------------------------
# Reverse-dependency lookup — find which packages depend on a component
# ---------------------------------------------------------------------------


def find_reverse_dependencies(
    repo_path: str,
    component_name: str,
) -> List[Dict[str, Any]]:
    """Find packages that depend on *component_name* in lock files.

    Walks the repo for recognised lock files and extracts packages whose
    dependency list references the component.  This tells us which
    *intermediary* libraries pull in a transitive dependency, so the
    pipeline can check whether the project's usage of the intermediary
    could reach the vulnerable code.

    Returns a list of ``{"name": str, "version": str, "lock_file": str}``
    dicts — one per intermediary found.
    """
    results: List[Dict[str, Any]] = []
    seen: set[str] = set()

    from src.languages import registry as _lang_registry

    _LOCK_FILES = _lang_registry.all_lockfile_filenames()

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for fname in files:
            if fname not in _LOCK_FILES:
                continue
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, repo_path)
            try:
                with open(fpath, "r", errors="ignore") as f:
                    txt = f.read()
            except Exception:
                continue

            plugin = _lang_registry.for_lockfile(fname)
            if plugin is not None:
                has_component = plugin.lockfile_mentions_component(
                    txt,
                    fname,
                    component_name,
                )
            else:
                has_component = component_name.lower() in txt.lower()
            if not has_component:
                continue

            intermediaries = _extract_reverse_deps(txt, component_name, fname)
            for inter in intermediaries:
                key = inter["name"].lower()
                if key not in seen and key != component_name.lower():
                    seen.add(key)
                    inter["lock_file"] = rel
                    results.append(inter)

    logger.info(
        "find_reverse_dependencies(%s): found %d intermediaries: %s",
        component_name,
        len(results),
        [r["name"] for r in results],
    )
    return results


def build_dependency_chains(
    repo_path: str,
    component_name: str,
) -> List[Dict[str, Any]]:
    """Build full dependency chains from root packages to *component_name*.

    Parses lock files to extract the dependency graph and finds every path
    from a root-level (direct) package down to the vulnerable component.
    Each chain is a list of ``{"name": str, "version": str}`` dicts ordered
    from root → … → vulnerable component.

    Returns a list of chain dicts::

        [
            {
                "chain": [
                    {"name": "express", "version": "4.18.2"},
                    {"name": "body-parser", "version": "1.20.1"},
                    {"name": "qs", "version": "6.11.0"},
                ],
                "lock_file": "package-lock.json",
            },
            …
        ]

    The vulnerable component itself is NOT included at the end — the caller
    already knows the target.  Each chain starts with a root-level package
    (declared in a manifest) and walks through intermediaries.
    """
    from src.languages import registry as _lang_registry

    _LOCK_FILES = _lang_registry.all_lockfile_filenames()

    all_chains: List[Dict[str, Any]] = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for fname in files:
            if fname not in _LOCK_FILES:
                continue
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, repo_path)
            try:
                with open(fpath, "r", errors="ignore") as f:
                    txt = f.read()
            except Exception:
                continue

            plugin = _lang_registry.for_lockfile(fname)
            if plugin is not None:
                has_component = plugin.lockfile_mentions_component(
                    txt,
                    fname,
                    component_name,
                )
            else:
                has_component = component_name.lower() in txt.lower()
            if not has_component:
                continue

            graph = _build_dep_graph(txt, fname)
            if not graph:
                continue

            # Extract version info and remove the sentinel key
            pkg_versions: Dict[str, str] = graph.pop("__versions__", {})  # type: ignore[arg-type]

            # Find all root packages (those not depended on by others)
            all_pkgs = set(graph.keys())
            depended_on: set[str] = set()
            for deps in graph.values():
                depended_on.update(d.lower() for d in deps)
            roots = all_pkgs - depended_on
            if not roots:
                # Fallback: everything is a root (flat lock file)
                roots = all_pkgs

            cn_lower = component_name.lower()
            # DFS from each root to find paths to the target
            for root_pkg in roots:
                _dfs_chains(
                    graph,
                    root_pkg,
                    cn_lower,
                    [root_pkg],
                    set(),
                    all_chains,
                    rel,
                    pkg_versions,
                )

    # Deduplicate chains (same sequence of names)
    seen_sigs: set[str] = set()
    unique: List[Dict[str, Any]] = []
    for c in all_chains:
        sig = " → ".join(n["name"] for n in c["chain"])
        if sig not in seen_sigs:
            seen_sigs.add(sig)
            unique.append(c)

    logger.info(
        "build_dependency_chains(%s): found %d chains across lock files",
        component_name,
        len(unique),
    )
    return unique


def _dfs_chains(
    graph: Dict[str, List[str]],
    current: str,
    target: str,
    path: List[str],
    visited: set[str],
    results: List[Dict[str, Any]],
    lock_file: str,
    versions: Dict[str, str],
) -> None:
    """DFS to find all paths from *current* to *target* in the dep graph."""
    if current in visited:
        return
    visited.add(current)

    deps = graph.get(current, [])
    for dep in deps:
        dep_lower = dep.lower()
        if dep_lower == target:
            # Found the target — record chain (without the target itself)
            chain = [{"name": p, "version": versions.get(p, "")} for p in path]
            results.append({"chain": chain, "lock_file": lock_file})
        elif dep_lower in graph and dep_lower not in visited:
            _dfs_chains(
                graph,
                dep_lower,
                target,
                path + [dep_lower],
                visited,
                results,
                lock_file,
                versions,
            )

    visited.discard(current)


def _build_dep_graph(
    text: str,
    filename: str,
) -> Dict[str, List[str]]:
    """Parse a lock file into a dependency graph: {pkg_name: [dep_names]}.

    All keys and dependency names are lowercased for consistent lookup.
    """
    import json as _json
    import re as _re

    graph: Dict[str, List[str]] = {}
    versions: Dict[str, str] = {}

    if filename == "package-lock.json":
        try:
            data = _json.loads(text)
            # lockfileVersion 2/3
            packages = data.get("packages", {})
            for pkg_path, info in packages.items():
                if not isinstance(info, dict):
                    continue
                if "node_modules/" in pkg_path:
                    name = pkg_path.rsplit("node_modules/", 1)[-1].lower()
                elif pkg_path == "":
                    name = "__root__"
                else:
                    continue
                deps: List[str] = []
                for key in (
                    "dependencies",
                    "devDependencies",
                    "peerDependencies",
                    "optionalDependencies",
                ):
                    deps.extend(d.lower() for d in info.get(key, {}))
                graph[name] = deps
                versions[name] = info.get("version", "")
            # lockfileVersion 1 fallback
            if not graph or (len(graph) == 1 and "__root__" in graph):
                deps_v1 = data.get("dependencies", {})
                root_deps = []
                for name, info in deps_v1.items():
                    if not isinstance(info, dict):
                        continue
                    nl = name.lower()
                    root_deps.append(nl)
                    sub = list(info.get("requires", {}).keys())
                    graph[nl] = [s.lower() for s in sub]
                    versions[nl] = info.get("version", "")
                if root_deps:
                    graph["__root__"] = root_deps
        except Exception:
            pass

    elif filename == "yarn.lock":
        blocks = _re.split(r"\n(?=\S)", text)
        for block in blocks:
            lines = block.strip().splitlines()
            if not lines:
                continue
            header = lines[0]
            m = _re.match(r'"?([^@"]+)', header)
            name = m.group(1).strip().lower() if m else ""
            if not name:
                continue
            version = ""
            deps: List[str] = []
            in_deps = False
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("version "):
                    version = stripped.split('"')[1] if '"' in stripped else ""
                if stripped == "dependencies:":
                    in_deps = True
                    continue
                if in_deps:
                    if not line.startswith("    "):
                        in_deps = False
                        continue
                    dep_m = _re.match(r'\s+"?([^"\s]+)', line)
                    if dep_m:
                        deps.append(dep_m.group(1).lower())
            graph[name] = deps
            versions[name] = version

    elif filename == "poetry.lock":
        blocks = _re.split(r"\[\[package\]\]", text)
        for block in blocks:
            name_m = _re.search(r'name\s*=\s*"([^"]+)"', block)
            ver_m = _re.search(r'version\s*=\s*"([^"]+)"', block)
            if not name_m:
                continue
            name = name_m.group(1).lower()
            version = ver_m.group(1) if ver_m else ""
            deps: List[str] = []
            deps_m = _re.search(
                r"\[package\.dependencies\](.*?)(?:\[|\Z)",
                block,
                _re.DOTALL,
            )
            if deps_m:
                for dep_line in deps_m.group(1).splitlines():
                    dep_line = dep_line.strip()
                    if dep_line and "=" in dep_line:
                        dep_name = dep_line.split("=")[0].strip().strip('"').lower()
                        if dep_name:
                            deps.append(dep_name)
                    elif dep_line and not dep_line.startswith("["):
                        dep_name = dep_line.split()[0].strip('"').lower()
                        if dep_name:
                            deps.append(dep_name)
            graph[name] = deps
            versions[name] = version

    elif filename == "Cargo.lock":
        blocks = _re.split(r"\[\[package\]\]", text)
        for block in blocks:
            name_m = _re.search(r'name\s*=\s*"([^"]+)"', block)
            ver_m = _re.search(r'version\s*=\s*"([^"]+)"', block)
            if not name_m:
                continue
            name = name_m.group(1).lower()
            version = ver_m.group(1) if ver_m else ""
            deps: List[str] = []
            deps_m = _re.search(r"dependencies\s*=\s*\[(.*?)\]", block, _re.DOTALL)
            if deps_m:
                for dep_entry in deps_m.group(1).split(","):
                    dep_entry = dep_entry.strip().strip('"')
                    if dep_entry:
                        # Format: "name version" or "name version (registry+...)"
                        dep_name = dep_entry.split()[0].lower() if dep_entry else ""
                        if dep_name:
                            deps.append(dep_name)
            graph[name] = deps
            versions[name] = version

    elif filename == "composer.lock":
        try:
            data = _json.loads(text)
            for pkg in data.get("packages", []) + data.get("packages-dev", []):
                name = pkg.get("name", "").lower()
                version = pkg.get("version", "")
                deps = [d.lower() for d in pkg.get("require", {}).keys()]
                if name:
                    graph[name] = deps
                    versions[name] = version
        except Exception:
            pass

    elif filename == "pnpm-lock.yaml":
        # Simplified: line-based parsing for package entries with dependencies
        current_pkg = ""
        in_deps = False
        for line in text.splitlines():
            if line and not line.startswith(" "):
                current_pkg = ""
                in_deps = False
            # Top-level package entries
            pkg_m = _re.match(r"\s+/?'?([^:'@(\s]+)", line)
            if pkg_m and ":" in line and "dependencies" not in line:
                current_pkg = pkg_m.group(1).strip().rstrip("/").lower()
                if current_pkg and current_pkg not in graph:
                    graph[current_pkg] = []
            if "dependencies:" in line and current_pkg:
                in_deps = True
                continue
            if in_deps and current_pkg:
                dep_m = _re.match(r"\s+'?([^:'@(\s]+)", line)
                if dep_m:
                    dep_name = dep_m.group(1).strip().lower()
                    if dep_name:
                        graph[current_pkg].append(dep_name)

    # Attach versions dict for chain building
    if graph:
        graph["__versions__"] = versions  # type: ignore[assignment]

    return graph


def _extract_reverse_deps(
    text: str,
    component_name: str,
    filename: str,
) -> List[Dict[str, Any]]:
    """Extract packages that list *component_name* as a dependency."""
    import json as _json
    import re as _re

    results: List[Dict[str, Any]] = []
    cn_lower = component_name.lower()

    if filename == "package-lock.json":
        try:
            data = _json.loads(text)
            # lockfileVersion 2/3: packages dict
            packages = data.get("packages", {})
            for pkg_path, info in packages.items():
                if not isinstance(info, dict):
                    continue
                all_deps: Dict[str, str] = {}
                for key in (
                    "dependencies",
                    "devDependencies",
                    "peerDependencies",
                    "optionalDependencies",
                ):
                    all_deps.update(info.get(key, {}))
                if any(d.lower() == cn_lower for d in all_deps):
                    name = (
                        pkg_path.rsplit("node_modules/", 1)[-1]
                        if "node_modules/" in pkg_path
                        else ""
                    )
                    version = info.get("version", "")
                    if name and name.lower() != cn_lower:
                        results.append({"name": name, "version": version})
            # lockfileVersion 1: dependencies dict
            deps_v1 = data.get("dependencies", {})
            for name, info in deps_v1.items():
                if not isinstance(info, dict):
                    continue
                sub = info.get("requires", {})
                if any(d.lower() == cn_lower for d in sub):
                    if name.lower() != cn_lower:
                        results.append(
                            {"name": name, "version": info.get("version", "")}
                        )
        except Exception:
            pass
        return results

    if filename == "yarn.lock":
        blocks = _re.split(r"\n(?=\S)", text)
        for block in blocks:
            lines = block.strip().splitlines()
            if not lines:
                continue
            header = lines[0]
            in_deps = False
            has_component = False
            version = ""
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("version "):
                    version = stripped.split('"')[1] if '"' in stripped else ""
                if stripped == "dependencies:":
                    in_deps = True
                    continue
                if in_deps:
                    if not line.startswith("    "):
                        in_deps = False
                        continue
                    if cn_lower in stripped.lower():
                        has_component = True
            if has_component:
                m = _re.match(r'"?([^@"]+)', header)
                name = m.group(1).strip() if m else ""
                if name and name.lower() != cn_lower:
                    results.append({"name": name, "version": version})
        return results

    if filename == "poetry.lock":
        blocks = _re.split(r"\[\[package\]\]", text)
        for block in blocks:
            name_m = _re.search(r'name\s*=\s*"([^"]+)"', block)
            ver_m = _re.search(r'version\s*=\s*"([^"]+)"', block)
            if not name_m:
                continue
            name = name_m.group(1)
            version = ver_m.group(1) if ver_m else ""
            deps_m = _re.search(
                r"\[package\.dependencies\](.*?)(?:\[|\Z)",
                block,
                _re.DOTALL,
            )
            if deps_m and cn_lower in deps_m.group(1).lower():
                if name.lower() != cn_lower:
                    results.append({"name": name, "version": version})
        return results

    if filename == "Cargo.lock":
        blocks = _re.split(r"\[\[package\]\]", text)
        for block in blocks:
            name_m = _re.search(r'name\s*=\s*"([^"]+)"', block)
            ver_m = _re.search(r'version\s*=\s*"([^"]+)"', block)
            if not name_m:
                continue
            name = name_m.group(1)
            version = ver_m.group(1) if ver_m else ""
            deps_m = _re.search(r"dependencies\s*=\s*\[(.*?)\]", block, _re.DOTALL)
            if deps_m and cn_lower in deps_m.group(1).lower():
                if name.lower() != cn_lower:
                    results.append({"name": name, "version": version})
        return results

    if filename == "composer.lock":
        try:
            data = _json.loads(text)
            for pkg in data.get("packages", []) + data.get("packages-dev", []):
                requires = pkg.get("require", {})
                if any(d.lower() == cn_lower for d in requires):
                    name = pkg.get("name", "")
                    version = pkg.get("version", "")
                    if name and name.lower() != cn_lower:
                        results.append({"name": name, "version": version})
        except Exception:
            pass
        return results

    if filename == "Pipfile.lock":
        # Pipfile.lock doesn't contain dependency graph info
        return results

    if filename == "pnpm-lock.yaml":
        # Simple line-based scan: package blocks with dependencies
        current_pkg = ""
        in_deps = False
        for line in text.splitlines():
            if line and not line.startswith(" "):
                current_pkg = ""
                in_deps = False
            pkg_m = _re.match(r"\s+/?'?([^:'@(]+)", line)
            if pkg_m and ":" in line and "dependencies" not in line:
                current_pkg = pkg_m.group(1).strip().rstrip("/")
            if "dependencies:" in line:
                in_deps = True
                continue
            if in_deps and cn_lower in line.lower():
                if current_pkg and current_pkg.lower() != cn_lower:
                    results.append({"name": current_pkg, "version": ""})
                    in_deps = False

    return results
