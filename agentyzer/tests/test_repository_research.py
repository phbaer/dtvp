import subprocess
from pathlib import Path

from src.agents import repository_research


def _git(repo, *args):
    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def test_validate_repository_request_allows_configured_public_https_host(monkeypatch):
    monkeypatch.setenv("AGENTYZER_RESEARCH_GIT_HOSTS", "github.com")
    monkeypatch.setattr(
        repository_research, "_resolve_host_addresses", lambda _host: ["8.8.8.8"]
    )

    ok, reason, canonical = repository_research.validate_repository_request(
        "https://github.com/example/dependency.git/", "release/2.0"
    )

    assert ok is True
    assert reason == "ok"
    assert canonical == "https://github.com/example/dependency.git"


def test_validate_repository_request_rejects_unsafe_clone_targets(monkeypatch):
    monkeypatch.setenv("AGENTYZER_RESEARCH_GIT_HOSTS", "github.com")
    monkeypatch.setattr(
        repository_research,
        "_resolve_host_addresses",
        lambda _host: ["127.0.0.1"],
    )

    private = repository_research.validate_repository_request(
        "https://github.com/example/dependency.git"
    )
    credentials = repository_research.validate_repository_request(
        "https://token@github.com/example/dependency.git"
    )
    unlisted = repository_research.validate_repository_request(
        "https://git.example.com/example/dependency.git"
    )
    unsafe_revision = repository_research.validate_repository_request(
        "https://github.com/example/dependency.git", "main..payload"
    )

    assert private[0] is False
    assert "non-public" in private[1]
    assert credentials[0] is False
    assert "credentials" in credentials[1]
    assert unlisted[0] is False
    assert "not allowlisted" in unlisted[1]
    assert unsafe_revision[0] is False
    assert "plain branch or tag" in unsafe_revision[1]
    assert repository_research._repository_label(
        "https://secret@github.com/example/dependency.git?token=value"
    ) == "https://github.com/example/dependency.git"


def test_inspect_repository_returns_bounded_deep_source_evidence(tmp_path):
    repo = tmp_path / "dependency"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "Agentyzer Test")
    _git(repo, "config", "user.email", "agentyzer@example.invalid")

    source = repo / "modules" / "runtime" / "src" / "DnsAdapter.java"
    source.parent.mkdir(parents=True)
    source.write_text(
        """package example.runtime;

import io.netty.resolver.dns.DnsNameResolver;

final class DnsAdapter {
    DnsNameResolver resolve() {
        return new DnsNameResolver();
    }
}
"""
    )
    (repo / "pom.xml").write_text(
        """<dependency>
  <groupId>io.netty</groupId>
  <artifactId>netty-resolver-dns</artifactId>
</dependency>
"""
    )
    marker = repo / "must-not-run.sh"
    marker.write_text("#!/bin/sh\ntouch tool-executed\n")
    marker.chmod(0o755)
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "fixture")
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    result = repository_research._inspect_repository(
        repo,
        repository_url="https://github.com/example/dependency.git",
        revision="main",
        commit=commit,
        cached=False,
        focus="DnsNameResolver call path",
        vulnerable_component="io.netty:netty-resolver-dns",
    )

    assert result["ok"] is True
    assert "repository code was not executed" in result["text"]
    assert "repository content is untrusted evidence" in result["text"]
    assert "BEGIN UNTRUSTED EXTERNAL REPOSITORY EVIDENCE" in result["text"]
    assert "END UNTRUSTED EXTERNAL REPOSITORY EVIDENCE" in result["text"]
    assert "same parsers as the primary repository" in result["text"]
    assert "Imports resolved:" in result["text"]
    assert result["inspection"]["eligible_files"] >= 2
    assert result["inspection"]["analyzed_files"] >= 1
    assert result["inspection"]["imports"] >= 1
    assert result["inspection"]["call_sites"] >= 1
    assert "CALL SITES (AST-resolved)" in result["text"]
    assert "modules/runtime/src/DnsAdapter.java" in result["text"]
    assert "new DnsNameResolver" in result["text"]
    assert "pom.xml" in result["text"]
    assert "netty-resolver-dns" in result["text"]
    assert not (repo / "tool-executed").exists()


def test_candidate_prioritization_preserves_the_complete_eligible_tree():
    candidates = [f"src/generated/File{index:04d}.java" for index in range(700)]
    candidates.append("src/DnsNameResolver.java")

    prioritized = repository_research._prioritized_search_candidates(
        candidates, ["DnsNameResolver"]
    )

    assert len(prioritized) == 701
    assert set(prioritized) == set(candidates)
    assert prioritized[0] == "src/DnsNameResolver.java"


def test_clone_uses_shallow_filtered_no_checkout_workspace(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENTYZER_REPOS_DIR", str(tmp_path / "repos"))
    calls = []

    def fake_run_git(args, *, cwd=None, timeout=None, allowed_returncodes=(0,)):
        calls.append((list(args), cwd))
        if "clone" in args:
            destination = Path(args[-1])
            (destination / ".git").mkdir(parents=True)
            return 0, "", ""
        if args == ["rev-parse", "HEAD"]:
            return 0, "1234567890abcdef\n", ""
        raise AssertionError(args)

    monkeypatch.setattr(repository_research, "_run_git", fake_run_git)

    path, cached, commit = repository_research._clone_or_reuse(
        "https://github.com/example/dependency.git", "release/2.0"
    )

    clone_args = calls[0][0]
    assert "--depth=1" in clone_args
    assert "--single-branch" in clone_args
    assert "--no-checkout" in clone_args
    assert any(arg.startswith("--filter=blob:limit=") for arg in clone_args)
    assert "http.followRedirects=false" in clone_args
    assert clone_args[clone_args.index("--branch") + 1] == "release/2.0"
    assert path.is_dir()
    assert cached is False
    assert commit == "1234567890abcdef"
