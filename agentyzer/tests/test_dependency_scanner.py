import asyncio
import json
import logging
import subprocess
from pathlib import Path

import pytest

from src.agents import dependency_scanner


def _git(repo, *args):
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _source_repository(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "-q", "-b", "main")
    _git(source, "config", "user.name", "Agentyzer Test")
    _git(source, "config", "user.email", "agentyzer@example.invalid")
    (source / "version.txt").write_text("one\n")
    _git(source, "add", "version.txt")
    _git(source, "commit", "-q", "-m", "version one")
    return source


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


def test_javascript_root_package_name_is_not_dependency_evidence(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "vp-auth-server",
                "version": "1.0.0",
                "dependencies": {"path-to-regexp": "0.1.12"},
            }
        )
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "vp-auth-server",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "vp-auth-server", "version": "1.0.0"},
                    "node_modules/path-to-regexp": {"version": "0.1.12"},
                },
            }
        )
    )

    project = dependency_scanner.find_component(str(tmp_path), "vp-auth-server")
    vulnerable_dependency = dependency_scanner.find_component(
        str(tmp_path),
        "path-to-regexp",
    )

    assert project["repo_found"] is False
    assert project["direct"] is False
    assert project["lock_files"] == []
    assert project["locked_version"] is None
    assert project["presence_basis"] == "not_found"
    assert vulnerable_dependency["repo_found"] is True
    assert vulnerable_dependency["direct"] is True
    assert vulnerable_dependency["declared_in"] == ["package.json"]
    assert vulnerable_dependency["lock_files"] == ["package-lock.json"]
    assert vulnerable_dependency["locked_version"] == "0.1.12"


def test_concurrent_prepare_uses_isolated_worktrees_and_one_shared_cache(
    monkeypatch,
    tmp_path,
):
    source = _source_repository(tmp_path)
    repos_dir = tmp_path / "repos"
    monkeypatch.setattr(dependency_scanner, "_REPOS_DIR", str(repos_dir))
    component_cfg = {"url": source.as_uri()}

    async def scenario():
        first, second = await asyncio.gather(
            dependency_scanner.prepare_repo(component_cfg, workspace_id="run-one"),
            dependency_scanner.prepare_repo(component_cfg, workspace_id="run-two"),
        )
        try:
            assert first != second
            assert (repos_dir / dependency_scanner._repo_key(source.as_uri())).is_dir()
            assert (Path(first) / "version.txt").read_text() == "one\n"
            assert (Path(second) / "version.txt").read_text() == "one\n"
        finally:
            await asyncio.gather(
                dependency_scanner.cleanup_repo_worktree(
                    component_cfg, workspace_id="run-one"
                ),
                dependency_scanner.cleanup_repo_worktree(
                    component_cfg, workspace_id="run-two"
                ),
            )
        assert not Path(first).exists()
        assert not Path(second).exists()

    asyncio.run(scenario())


def test_refresh_repo_cache_clones_and_fetches_without_leaving_a_worktree(
    caplog,
    monkeypatch,
    tmp_path,
):
    source = _source_repository(tmp_path)
    repos_dir = tmp_path / "repos"
    monkeypatch.setattr(dependency_scanner, "_REPOS_DIR", str(repos_dir))
    component_cfg = {"name": "demo", "url": source.as_uri()}
    caplog.set_level(logging.INFO, logger=dependency_scanner.__name__)

    first = asyncio.run(dependency_scanner.refresh_repo_cache(component_cfg))
    cache_path = repos_dir / dependency_scanner._repo_key(source.as_uri())

    assert first["repo_path"] == str(cache_path)
    assert first["commit"] == _git(source, "rev-parse", "HEAD")
    assert (cache_path / ".git").is_dir()
    assert not (repos_dir / ".worktrees").exists()
    assert "Cloning repository cache" in caplog.text
    assert "Repository cache refresh complete" in caplog.text

    (source / "version.txt").write_text("two\n")
    _git(source, "add", "version.txt")
    _git(source, "commit", "-q", "-m", "version two")

    caplog.clear()
    second = asyncio.run(dependency_scanner.refresh_repo_cache(component_cfg))

    assert second["repo_path"] == str(cache_path)
    assert second["commit"] == _git(source, "rev-parse", "HEAD")
    assert second["commit"] != first["commit"]
    assert not (repos_dir / ".worktrees").exists()
    assert "Repository cache exists" in caplog.text
    assert "fetching latest changes" in caplog.text


def test_existing_worktree_remains_on_resolved_commit_while_cache_updates(
    monkeypatch,
    tmp_path,
):
    source = _source_repository(tmp_path)
    monkeypatch.setattr(dependency_scanner, "_REPOS_DIR", str(tmp_path / "repos"))
    component_cfg = {"url": source.as_uri()}

    async def scenario():
        first = await dependency_scanner.prepare_repo(
            component_cfg,
            workspace_id="first-snapshot",
        )
        (source / "version.txt").write_text("two\n")
        _git(source, "add", "version.txt")
        _git(source, "commit", "-q", "-m", "version two")

        second = await dependency_scanner.prepare_repo(
            component_cfg,
            workspace_id="second-snapshot",
        )
        try:
            assert (Path(first) / "version.txt").read_text() == "one\n"
            assert (Path(second) / "version.txt").read_text() == "two\n"
        finally:
            await dependency_scanner.cleanup_repo_worktree(
                component_cfg,
                workspace_id="first-snapshot",
            )
            await dependency_scanner.cleanup_repo_worktree(
                component_cfg,
                workspace_id="second-snapshot",
            )

    asyncio.run(scenario())


def test_failed_cache_update_does_not_remove_an_active_worktree(
    monkeypatch,
    tmp_path,
):
    source = _source_repository(tmp_path)
    monkeypatch.setattr(dependency_scanner, "_REPOS_DIR", str(tmp_path / "repos"))
    component_cfg = {"url": source.as_uri()}

    async def scenario():
        first = await dependency_scanner.prepare_repo(
            component_cfg,
            workspace_id="active-snapshot",
        )
        source.rename(tmp_path / "source-unavailable")
        try:
            with pytest.raises(dependency_scanner.RepoError, match="Failed to update"):
                await dependency_scanner.prepare_repo(
                    component_cfg,
                    workspace_id="failed-update",
                )
            assert (Path(first) / "version.txt").read_text() == "one\n"
        finally:
            await dependency_scanner.cleanup_repo_worktree(
                component_cfg,
                workspace_id="active-snapshot",
            )

    asyncio.run(scenario())


def test_next_prepare_reclaims_worktree_with_abandoned_process_lease(
    monkeypatch,
    tmp_path,
):
    source = _source_repository(tmp_path)
    monkeypatch.setattr(dependency_scanner, "_REPOS_DIR", str(tmp_path / "repos"))
    component_cfg = {"url": source.as_uri()}

    async def scenario():
        abandoned = await dependency_scanner.prepare_repo(
            component_cfg,
            workspace_id="abandoned-run",
        )
        lease_path = dependency_scanner._lease_path(
            source.as_uri(),
            "abandoned-run",
        )
        with dependency_scanner._worktree_leases_guard:
            lease_file = dependency_scanner._worktree_leases.pop(lease_path)
        dependency_scanner.fcntl.flock(
            lease_file.fileno(),
            dependency_scanner.fcntl.LOCK_UN,
        )
        lease_file.close()

        current = await dependency_scanner.prepare_repo(
            component_cfg,
            workspace_id="current-run",
        )
        try:
            assert not Path(abandoned).exists()
            assert (Path(current) / "version.txt").read_text() == "one\n"
        finally:
            await dependency_scanner.cleanup_repo_worktree(
                component_cfg,
                workspace_id="current-run",
            )

    asyncio.run(scenario())
