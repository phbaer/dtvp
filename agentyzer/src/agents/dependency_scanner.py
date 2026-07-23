import asyncio
import base64
import fcntl
import hashlib
import logging
import os
import re
import shutil
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Any, Dict, Iterator, List
from urllib.parse import unquote, urlsplit, urlunsplit

from git import GitCommandError, Repo

from src.configuration import AgentyzerRuntimeSettings

logger = logging.getLogger(__name__)

# Persistent directory for cloned repos.
_REPOS_DIR = AgentyzerRuntimeSettings.from_env().repos_dir

_LOCKS_DIRNAME = ".locks"
_WORKTREES_DIRNAME = ".worktrees"
_LEASES_DIRNAME = ".leases"

# Worktree leases stay open for the lifetime of an analysis.  The OS releases
# their advisory locks if the process exits, allowing a later run to reclaim a
# checkout left behind by a crash.
_worktree_leases_guard = threading.Lock()
_worktree_leases: dict[str, IO[str]] = {}

# Pattern to strip embedded credentials from URLs and error messages.
_CREDENTIAL_RE = re.compile(r"://[^@/]+@")


def _sanitize(text: str, secrets: tuple[str, ...] = ()) -> str:
    """Remove embedded credentials from a string (URLs, git stderr, etc.)."""
    sanitized = _CREDENTIAL_RE.sub("://***@", text)
    for secret in secrets:
        if secret:
            sanitized = sanitized.replace(secret, "***")
    return sanitized


class RepoError(RuntimeError):
    """Raised when repository operations fail. Messages are credential-free."""


def _repo_dir(url: str) -> str:
    """Derive a stable, unique local directory name from the repo URL."""
    # Strip credentials from the URL before hashing so the same repo
    # always maps to the same directory regardless of auth changes.
    parts = urlsplit(_credential_free_url(url))
    clean = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    digest = hashlib.sha256(clean.encode()).hexdigest()[:12]
    # Use the last path component (repo name) for readability.
    name = Path(parts.path).stem or "repo"
    return os.path.join(_REPOS_DIR, f"{name}-{digest}")


def _repo_key(url: str) -> str:
    """Return the credential-free directory key for a repository URL."""
    return os.path.basename(_repo_dir(url))


def _safe_workspace_id(workspace_id: str) -> str:
    """Convert an internal run identifier into one safe path component."""
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", workspace_id):
        return workspace_id
    return hashlib.sha256(workspace_id.encode()).hexdigest()[:32]


def _worktree_dir(url: str, workspace_id: str) -> str:
    return os.path.join(
        _REPOS_DIR,
        _WORKTREES_DIRNAME,
        _repo_key(url),
        _safe_workspace_id(workspace_id),
    )


def _lease_path(url: str, workspace_id: str) -> str:
    return os.path.join(
        _REPOS_DIR,
        _LEASES_DIRNAME,
        _repo_key(url),
        f"{_safe_workspace_id(workspace_id)}.lock",
    )


@contextmanager
def _repository_lock(url: str) -> Iterator[None]:
    """Serialize cache mutations for one repository across OS processes."""
    lock_dir = os.path.join(_REPOS_DIR, _LOCKS_DIRNAME)
    os.makedirs(lock_dir, exist_ok=True)
    lock_path = os.path.join(lock_dir, f"{_repo_key(url)}.lock")
    with open(lock_path, "a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _credential_free_url(url: str) -> str:
    """Return a remote URL that is safe to persist in ``.git/config``."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        # SCP-style SSH URLs and local paths do not use URL user-info. They are
        # returned unchanged rather than risking an invalid rewrite.
        return url
    host = parts.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, "", ""))


def _auth_secrets(auth: Dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        str(value)
        for key in ("username", "password", "token")
        if (value := auth.get(key))
    )


def _effective_auth(url: str, configured: Dict[str, Any]) -> Dict[str, Any]:
    """Convert legacy URL user-info to transient auth during in-place migration."""
    auth = dict(configured)
    if any(auth.get(key) for key in ("username", "password", "token")):
        return auth
    parts = urlsplit(url)
    if parts.username is None:
        return auth
    if parts.password is None:
        auth["token"] = unquote(parts.username)
    else:
        auth["username"] = unquote(parts.username)
        auth["password"] = unquote(parts.password)
    return auth


def _git_environment(url: str, auth: Dict[str, Any]) -> dict[str, str]:
    """Build per-command Git authentication without command-line secrets.

    ``GIT_CONFIG_*`` injects an HTTP authorization header into only the child
    Git process. The remote itself always receives the credential-free URL, so
    neither a successful clone nor a failed update persists the credential.
    """

    env = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    username = str(auth.get("username") or "")
    password = str(auth.get("password") or "")
    token = str(auth.get("token") or "")
    scheme = str(auth.get("scheme") or "basic").strip().lower()
    if scheme == "bearer" and token:
        authorization = f"Authorization: Bearer {token}"
    elif username and password:
        credential = f"{username}:{password}"
        header = base64.b64encode(credential.encode("utf-8")).decode("ascii")
        authorization = f"Authorization: Basic {header}"
    elif token:
        # Preserve the previous token-in-URL semantics: token as the HTTP basic
        # username with an empty password.
        credential = f"{token}:"
        header = base64.b64encode(credential.encode("utf-8")).decode("ascii")
        authorization = f"Authorization: Basic {header}"
    else:
        return env

    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise RepoError("Configured repository authentication requires an HTTP(S) URL")
    host = parts.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parts.port:
        host = f"{host}:{parts.port}"
    scope = f"{parts.scheme}://{host}/"
    env.update(
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": f"http.{scope}.extraHeader",
            "GIT_CONFIG_VALUE_0": authorization,
        }
    )
    return env


async def prepare_repo(
    component_cfg: Dict[str, Any],
    *,
    workspace_id: str,
) -> str:
    """Prepare an isolated repository worktree for one analysis.

    The persistent control repository is cloned or fetched under a
    cross-process lock.  A detached, leased worktree is then created at the
    resolved remote-default-branch commit and returned to the caller.  Later
    analyses may update the control repository without changing this run's
    files.

    Git operations are blocking I/O — they are offloaded to a thread so
    the asyncio event loop stays responsive (prevents 504 from upstream
    proxies during large clones).

    Raises :class:`RepoError` with a sanitized message on failure.
    """
    url = component_cfg.get("url")
    if not url:
        raise RepoError("No url in component config")

    safe_url = _credential_free_url(url)
    auth = _effective_auth(url, component_cfg.get("auth") or {})

    dest = _repo_dir(url)
    os.makedirs(_REPOS_DIR, exist_ok=True)

    return await asyncio.to_thread(
        _prepare_worktree,
        url,
        safe_url,
        auth,
        dest,
        workspace_id,
    )


async def refresh_repo_cache(component_cfg: Dict[str, Any]) -> Dict[str, str]:
    """Clone or fetch one configured repository without creating a worktree.

    This keeps the persistent control repository current independently of an
    assessment run.  ``prepare_repo`` still performs the same refresh under the
    repository lock immediately before resolving a per-run worktree.
    """
    url = component_cfg.get("url")
    if not url:
        raise RepoError("No url in component config")

    safe_url = _credential_free_url(url)
    auth = _effective_auth(url, component_cfg.get("auth") or {})
    dest = _repo_dir(url)
    os.makedirs(_REPOS_DIR, exist_ok=True)
    component_name = str(component_cfg.get("name") or "unlabeled").strip()
    logger.info(
        "Repository cache refresh starting: component=%s url=%s",
        component_name,
        safe_url,
    )
    commit = await asyncio.to_thread(
        _refresh_control_repository,
        url,
        safe_url,
        auth,
        dest,
    )
    logger.info(
        "Repository cache refresh complete: component=%s cache=%s commit=%s",
        component_name,
        dest,
        commit,
    )
    return {"repo_path": dest, "commit": commit}


async def cleanup_repo_worktree(
    component_cfg: Dict[str, Any],
    *,
    workspace_id: str,
) -> None:
    """Remove one run's worktree and release its cross-process lease."""
    url = component_cfg.get("url")
    if not url:
        return
    await asyncio.to_thread(_cleanup_worktree_for_run, url, workspace_id)


def _prepare_worktree(
    url: str,
    safe_url: str,
    auth: Dict[str, Any],
    dest: str,
    workspace_id: str,
) -> str:
    """Synchronously prepare a cache and leased detached worktree."""
    worktree = _worktree_dir(url, workspace_id)
    lease = _lease_path(url, workspace_id)

    with _repository_lock(url):
        repo, commit = _sync_repo(safe_url, auth, dest)
        _cleanup_stale_worktrees(repo, url)
        lease_file = _acquire_worktree_lease(lease)
        try:
            os.makedirs(os.path.dirname(worktree), exist_ok=True)
            if os.path.lexists(worktree):
                _remove_worktree(repo, worktree)
            repo.git.worktree("add", "--detach", worktree, commit)
        except Exception as exc:
            _remove_worktree(repo, worktree)
            _release_worktree_lease(lease, lease_file)
            raise RepoError(
                f"Failed to create isolated worktree for {safe_url}: "
                f"{_sanitize(str(exc))}"
            ) from None

    logger.info("Prepared isolated worktree %s at %s", worktree, commit)
    return worktree


def _refresh_control_repository(
    url: str,
    safe_url: str,
    auth: Dict[str, Any],
    dest: str,
) -> str:
    """Synchronize one control repository and return its resolved commit."""
    with _repository_lock(url):
        _repo, commit = _sync_repo(safe_url, auth, dest)
    return commit


def _cleanup_worktree_for_run(url: str, workspace_id: str) -> None:
    dest = _repo_dir(url)
    worktree = _worktree_dir(url, workspace_id)
    lease = _lease_path(url, workspace_id)

    with _repository_lock(url):
        lease_file = _claim_worktree_lease(lease)
        if lease_file is None:
            logger.warning(
                "Skipped cleanup for active worktree owned by another process: %s",
                worktree,
            )
            return
        try:
            if os.path.isdir(os.path.join(dest, ".git")):
                _remove_worktree(Repo(dest), worktree)
            else:
                _remove_path(worktree)
        finally:
            _release_worktree_lease(lease, lease_file)


def _acquire_worktree_lease(path: str) -> IO[str]:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lease_file = open(path, "a+", encoding="utf-8")
    try:
        fcntl.flock(lease_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except Exception:
        lease_file.close()
        raise RepoError(f"Workspace lease is already active: {path}") from None
    with _worktree_leases_guard:
        _worktree_leases[path] = lease_file
    return lease_file


def _claim_worktree_lease(path: str) -> IO[str] | None:
    """Claim an owned or abandoned lease for cleanup."""
    with _worktree_leases_guard:
        owned = _worktree_leases.pop(path, None)
    if owned is not None:
        return owned

    os.makedirs(os.path.dirname(path), exist_ok=True)
    lease_file = open(path, "a+", encoding="utf-8")
    try:
        fcntl.flock(lease_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lease_file.close()
        return None
    return lease_file


def _release_worktree_lease(path: str, lease_file: IO[str]) -> None:
    with _worktree_leases_guard:
        if _worktree_leases.get(path) is lease_file:
            _worktree_leases.pop(path, None)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    finally:
        fcntl.flock(lease_file.fileno(), fcntl.LOCK_UN)
        lease_file.close()


def _cleanup_stale_worktrees(repo: Repo, url: str) -> None:
    """Reclaim worktrees whose owning process no longer holds its lease."""
    worktree_root = os.path.join(_REPOS_DIR, _WORKTREES_DIRNAME, _repo_key(url))
    lease_root = os.path.join(_REPOS_DIR, _LEASES_DIRNAME, _repo_key(url))
    os.makedirs(worktree_root, exist_ok=True)
    os.makedirs(lease_root, exist_ok=True)

    for lease_entry in Path(lease_root).glob("*.lock"):
        lease = str(lease_entry)
        with _worktree_leases_guard:
            if lease in _worktree_leases:
                continue
        lease_file = _claim_worktree_lease(lease)
        if lease_file is None:
            continue
        worktree = os.path.join(worktree_root, lease_entry.stem)
        try:
            _remove_worktree(repo, worktree)
        finally:
            _release_worktree_lease(lease, lease_file)

    leased_ids = {entry.stem for entry in Path(lease_root).glob("*.lock")}
    for worktree_entry in Path(worktree_root).iterdir():
        if worktree_entry.name not in leased_ids:
            _remove_worktree(repo, str(worktree_entry))

    try:
        repo.git.worktree("prune", "--expire", "now")
    except GitCommandError:
        logger.warning("Failed to prune stale worktree metadata for %s", repo.working_dir)


def _remove_worktree(repo: Repo, worktree: str) -> None:
    try:
        repo.git.worktree("remove", "--force", worktree)
    except GitCommandError:
        _remove_path(worktree)
        try:
            repo.git.worktree("prune", "--expire", "now")
        except GitCommandError:
            pass


def _remove_path(path: str) -> None:
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path, ignore_errors=True)
    else:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def _sync_repo(
    safe_url: str,
    auth: Dict[str, Any],
    dest: str,
) -> tuple[Repo, str]:
    """Clone/fetch the control repository and resolve an immutable commit."""
    git_env = _git_environment(safe_url, auth)
    secrets = _auth_secrets(auth)

    if os.path.isdir(os.path.join(dest, ".git")):
        logger.info("Repository cache exists at %s — fetching latest changes", dest)
        try:
            repo = Repo(dest)
            _scrub_repo_credentials(repo, safe_url)
            origin = repo.remotes.origin
            with repo.git.custom_environment(**git_env):
                origin.fetch(prune=True)
            try:
                repo.git.remote("set-head", "origin", "--auto")
            except GitCommandError:
                logger.debug("Could not refresh origin/HEAD for %s", safe_url)
        except Exception as exc:
            message = _sanitize(str(exc), secrets)
            logger.error(
                "Update failed for %s; cached repository preserved: %s",
                safe_url,
                message,
            )
            raise RepoError(f"Failed to update repository {safe_url}: {message}") from None
    else:
        if os.path.lexists(dest):
            logger.warning("Removing incomplete repository cache at %s", dest)
            _remove_path(dest)
        logger.info("Cloning repository cache %s → %s", safe_url, dest)
        try:
            for stale_temp in Path(os.path.dirname(dest)).glob(
                f".{os.path.basename(dest)}-clone-*"
            ):
                _remove_path(str(stale_temp))
            with tempfile.TemporaryDirectory(
                prefix=f".{os.path.basename(dest)}-clone-",
                dir=os.path.dirname(dest),
            ) as temp_root:
                candidate = os.path.join(temp_root, "repository")
                repo = Repo.clone_from(
                    safe_url,
                    candidate,
                    no_checkout=True,
                    env=git_env,
                )
                _scrub_repo_credentials(repo, safe_url)
                os.replace(candidate, dest)
            repo = Repo(dest)
            logger.info("Clone successful: %s", dest)
        except GitCommandError as exc:
            message = _sanitize(exc.stderr or str(exc), secrets)
            logger.error("Clone failed for %s: %s", safe_url, message)
            raise RepoError(
                f"Failed to clone repository {safe_url}: {message}"
            ) from None
        except RepoError:
            raise
        except Exception as exc:
            message = _sanitize(str(exc), secrets)
            logger.error("Clone failed for %s: %s", safe_url, message)
            raise RepoError(f"Failed to clone repository {safe_url}: {message}") from None

    _scrub_repo_credentials(repo, safe_url)
    try:
        default_branch = _default_branch(repo)
        commit = repo.commit(f"origin/{default_branch}").hexsha
    except Exception as exc:
        raise RepoError(
            f"Failed to resolve remote default branch for {safe_url}: "
            f"{_sanitize(str(exc), secrets)}"
        ) from None
    logger.info(
        "Repository cache %s resolved origin/%s at %s",
        dest,
        default_branch,
        commit,
    )
    return repo, commit


def _scrub_repo_credentials(repo: Repo, safe_url: str) -> None:
    """Migrate a cached checkout without deleting its objects or history."""
    try:
        origin = repo.remotes.origin
    except (AttributeError, IndexError):
        raise RepoError(
            f"Cached repository has no origin remote: {repo.working_tree_dir}"
        ) from None

    with origin.config_writer as writer:
        writer.set("url", safe_url)
        try:
            writer.remove_option("pushurl")
        except Exception:
            pass

    # Older/manual configurations may contain persisted HTTP authorization
    # headers. They are never required now that auth is injected per command.
    try:
        configured_headers = repo.git.config(
            "--local",
            "--get-regexp",
            r"^http\..*\.extraheader$",
        )
    except GitCommandError:
        configured_headers = ""
    for line in configured_headers.splitlines():
        key, _, _value = line.partition(" ")
        if not key:
            continue
        try:
            repo.git.config("--local", "--unset-all", key)
        except GitCommandError:
            pass


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
            - sbom_attributed: True if upstream attribution already placed this exact component in the project SBOM
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
