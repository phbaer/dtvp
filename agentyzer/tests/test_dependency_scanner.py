import asyncio
import threading
import time
from pathlib import Path

from git import Repo

from src.agents import dependency_scanner


def _build_remote(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    repo = Repo.init(source)
    with repo.config_writer() as writer:
        writer.set_value("user", "name", "Agentyzer Test")
        writer.set_value("user", "email", "agentyzer@example.invalid")
    (source / "package.json").write_text('{"dependencies":{"left-pad":"1.3.0"}}')
    repo.index.add(["package.json"])
    repo.index.commit("initial")
    remote = tmp_path / "remote.git"
    repo.clone(remote, bare=True)
    return remote


def test_cached_repo_uses_credential_free_origin_and_isolated_worktrees(
    tmp_path,
    monkeypatch,
):
    remote = _build_remote(tmp_path)
    repos_dir = tmp_path / "repos"
    monkeypatch.setattr(dependency_scanner, "_REPOS_DIR", str(repos_dir))
    dependency_scanner._workspace_locks.clear()

    async def exercise():
        first, second = await asyncio.gather(
            dependency_scanner.prepare_repo(
                {"url": remote.as_uri(), "_scan_id": "scan-first"}
            ),
            dependency_scanner.prepare_repo(
                {"url": remote.as_uri(), "_scan_id": "scan-second"}
            ),
        )
        assert first != second
        assert (Path(first) / "package.json").is_file()
        assert (Path(second) / "package.json").is_file()

        cache_path = Path(dependency_scanner._repo_dir(remote.as_uri()))
        assert cache_path.is_dir()
        assert Repo(cache_path).remotes.origin.url == remote.as_uri()

        await dependency_scanner.release_scan_worktree("scan-first")
        await dependency_scanner.release_scan_worktree("scan-second")
        assert cache_path.is_dir()
        assert not Path(first).exists()
        assert not Path(second).exists()

    asyncio.run(exercise())


def test_existing_cache_credentials_are_scrubbed_without_deleting_history(tmp_path):
    remote = _build_remote(tmp_path)
    checkout = tmp_path / "checkout"
    repo = Repo.clone_from(remote.as_uri(), checkout)
    secret_url = "https://user:super-secret@example.invalid/team/repo.git"
    repo.remotes.origin.set_url(secret_url)
    with repo.config_writer() as writer:
        writer.add_section('http "https://example.invalid/"')
        writer.set_value(
            'http "https://example.invalid/"',
            "extraHeader",
            "Authorization: Bearer super-secret",
        )
    commit = repo.head.commit.hexsha

    dependency_scanner._scrub_repo_credentials(
        repo,
        "https://example.invalid/team/repo.git",
    )

    config = (checkout / ".git" / "config").read_text()
    assert "super-secret" not in config
    assert "user@" not in config
    assert repo.head.commit.hexsha == commit
    assert repo.remotes.origin.url == "https://example.invalid/team/repo.git"


def test_legacy_url_credentials_become_transient_git_environment():
    url = "https://legacy-user:legacy-password@example.invalid/team/repo.git"
    auth = dependency_scanner._effective_auth(url, {})
    safe_url = dependency_scanner._credential_free_url(url)
    environment = dependency_scanner._git_environment(safe_url, auth)

    assert safe_url == "https://example.invalid/team/repo.git"
    assert auth == {"username": "legacy-user", "password": "legacy-password"}
    assert "legacy-user" not in environment["GIT_CONFIG_KEY_0"]
    assert "legacy-password" not in environment["GIT_CONFIG_KEY_0"]
    assert environment["GIT_CONFIG_VALUE_0"].startswith("Authorization: Basic ")


def _commit_file(repo: Repo, name: str, content: str) -> None:
    path = repo.working_tree_dir and Path(repo.working_tree_dir) / name
    assert path is not None
    path.write_text(content)
    repo.index.add([name])
    repo.index.commit(f"update {name}")


def test_credential_free_url_removes_userinfo_query_and_fragment():
    safe = dependency_scanner._credential_free_url(
        "https://user:password@example.test:8443/org/repo.git?token=secret#fragment"
    )

    assert safe == "https://example.test:8443/org/repo.git"


def test_git_environment_keeps_raw_credentials_out_of_command_configuration():
    env = dependency_scanner._git_environment(
        "https://example.test/org/repo.git",
        {"username": "build-user", "password": "super-secret"},
    )

    serialized = "\n".join(f"{key}={value}" for key, value in env.items())
    assert "build-user" not in serialized
    assert "super-secret" not in serialized
    assert env["GIT_CONFIG_KEY_0"].endswith(".extraHeader")
    assert env["GIT_CONFIG_VALUE_0"].startswith("Authorization: Basic ")


def test_scrub_repo_credentials_preserves_checkout(tmp_path):
    repo = Repo.init(tmp_path / "cache")
    _commit_file(repo, "README.md", "cached content")
    repo.create_remote(
        "origin",
        "https://legacy-user:legacy-password@example.test/org/repo.git",
    )
    with repo.config_writer(config_level="repository") as writer:
        writer.set_value(
            'http "https://example.test/org/repo.git"',
            "extraheader",
            "Authorization: Basic legacy-secret",
        )

    dependency_scanner._scrub_repo_credentials(
        repo,
        "https://example.test/org/repo.git",
    )

    assert list(repo.remotes.origin.urls) == ["https://example.test/org/repo.git"]
    config = (tmp_path / "cache" / ".git" / "config").read_text()
    assert "legacy-user" not in config
    assert "legacy-password" not in config
    assert "legacy-secret" not in config
    assert (tmp_path / "cache" / "README.md").read_text() == "cached content"


def test_prepare_repo_reuses_cache_and_returns_isolated_worktrees(tmp_path, monkeypatch):
    source = Repo.init(tmp_path / "source")
    _commit_file(source, "package-lock.json", '{"version": "1"}')
    repos_root = tmp_path / "repos"
    monkeypatch.setattr(dependency_scanner, "_REPOS_DIR", str(repos_root))

    first = asyncio.run(
        dependency_scanner.prepare_repo(
            {"url": str(tmp_path / "source"), "_scan_id": "firstscan"}
        )
    )
    cache = dependency_scanner._repo_dir(str(tmp_path / "source"))

    assert first != cache
    assert (Path(first) / "package-lock.json").is_file()
    assert (Path(cache) / ".git").is_dir()

    asyncio.run(dependency_scanner.release_scan_worktree("firstscan"))
    assert not Path(first).exists()
    assert Path(cache).is_dir()

    _commit_file(source, "package-lock.json", '{"version": "2"}')
    second = asyncio.run(
        dependency_scanner.prepare_repo(
            {"url": str(tmp_path / "source"), "_scan_id": "secondscan"}
        )
    )
    assert second != first
    assert (Path(second) / "package-lock.json").read_text() == '{"version": "2"}'
    asyncio.run(dependency_scanner.release_scan_worktree("secondscan"))
    assert Path(cache).is_dir()


def test_prepare_repo_serializes_updates_for_one_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(dependency_scanner, "_REPOS_DIR", str(tmp_path / "repos"))
    active = 0
    maximum = 0
    guard = threading.Lock()

    def fake_sync(safe_url, auth, dest, scan_id):
        nonlocal active, maximum
        with guard:
            active += 1
            maximum = max(maximum, active)
        time.sleep(0.03)
        with guard:
            active -= 1
        return f"{dest}-{scan_id}"

    monkeypatch.setattr(dependency_scanner, "_sync_repo", fake_sync)

    async def run_both():
        return await asyncio.gather(
            dependency_scanner.prepare_repo(
                {"url": "https://example.test/repo.git", "_scan_id": "scan-id-a"}
            ),
            dependency_scanner.prepare_repo(
                {"url": "https://example.test/repo.git", "_scan_id": "scan-id-b"}
            ),
        )

    asyncio.run(run_both())
    assert maximum == 1


def test_find_component_keeps_sbom_attributed_presence_without_repo_match(tmp_path):
    result = dependency_scanner.find_component(
        str(tmp_path),
        "left-pad",
        sbom_attributed=True,
    )

    assert result["found"] is True
    assert result["repo_found"] is False
    assert result["sbom_attributed"] is True
    assert result["presence_basis"] == "sbom_attributed"
    assert result["direct"] is False
    assert result["transitive"] is False


def test_find_component_matches_maven_group_artifact_split(tmp_path):
    pom = tmp_path / "pom.xml"
    pom.write_text(
        """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>io.netty</groupId>
      <artifactId>netty-resolver-dns</artifactId>
      <version>4.1.134.Final</version>
    </dependency>
  </dependencies>
</project>
"""
    )

    result = dependency_scanner.find_component(
        str(tmp_path),
        "io.netty:netty-resolver-dns",
    )

    assert result["found"] is True
    assert result["repo_found"] is True
    assert result["presence_basis"] == "direct"
    assert result["declared_in"] == ["pom.xml"]


def test_find_component_extracts_gradle_lock_version_for_bare_java_name(tmp_path):
    lock_dir = tmp_path / "gradle" / "dependency-locks"
    lock_dir.mkdir(parents=True)
    lockfile = lock_dir / "runtimeClasspath.lockfile"
    lockfile.write_text(
        "io.netty:netty-resolver-dns:4.1.134.Final=runtimeClasspath\n"
    )

    result = dependency_scanner.find_component(str(tmp_path), "netty")

    assert result["found"] is True
    assert result["repo_found"] is True
    assert result["presence_basis"] == "transitive"
    assert result["locked_version"] == "4.1.134.Final"
    assert result["lock_files"] == ["gradle/dependency-locks/runtimeClasspath.lockfile"]
