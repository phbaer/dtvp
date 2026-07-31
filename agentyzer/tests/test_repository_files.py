import os

from git import Repo

from src.repository_files import (
    RepositoryReadBudget,
    read_repository_blob_text,
    read_repository_text,
    repository_file_is_safe,
)


def test_repository_read_accepts_regular_file_and_consumes_budget(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("print('safe')\n")
    budget = RepositoryReadBudget(remaining_bytes=100)

    assert read_repository_text(str(repo), str(source), budget=budget) == (
        "print('safe')\n"
    )
    assert budget.remaining_bytes == 86
    assert repository_file_is_safe(str(repo), str(source)) is True


def test_repository_read_rejects_escape_symlink_special_file_and_oversize(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("secret")
    escape = repo / "escape.py"
    escape.symlink_to(outside)
    endless = repo / "endless.py"
    endless.symlink_to("/dev/zero")
    fifo = repo / "input.py"
    os.mkfifo(fifo)
    large = repo / "large.py"
    large.write_text("x" * 11)

    assert read_repository_text(str(repo), str(escape)) is None
    assert read_repository_text(str(repo), str(endless)) is None
    assert read_repository_text(str(repo), str(fifo)) is None
    assert read_repository_text(str(repo), str(large), max_bytes=10) is None
    assert read_repository_text(str(repo), str(outside)) is None


def test_repository_read_enforces_aggregate_budget(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    first = repo / "first.txt"
    second = repo / "second.txt"
    first.write_text("123456")
    second.write_text("abcdef")
    budget = RepositoryReadBudget(remaining_bytes=10)

    assert read_repository_text(str(repo), str(first), budget=budget) == "123456"
    assert read_repository_text(str(repo), str(second), budget=budget) is None
    assert budget.remaining_bytes == 4


def test_repository_blob_read_is_bounded_and_rejects_symlink_blob(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    worktree = tmp_path / "repo"
    regular = worktree / "package.json"
    regular.write_text('{"dependency":"safe"}')
    link = worktree / "requirements.txt"
    link.symlink_to("/dev/zero")
    repo.index.add(["package.json", "requirements.txt"])
    repo.index.commit("repository inputs")

    assert read_repository_blob_text(
        repo,
        "HEAD",
        "package.json",
        max_bytes=100,
    ) == '{"dependency":"safe"}'
    assert (
        read_repository_blob_text(repo, "HEAD", "package.json", max_bytes=5) is None
    )
    assert read_repository_blob_text(repo, "HEAD", "requirements.txt") is None
