import io
import stat
import tarfile
import zipfile
from pathlib import Path

import py7zr
import pytest

from src.agents import archive_extractor
from src.agents import code_scanner, dependency_scanner


def _assert_project_source(scan_root: str) -> None:
    root = Path(scan_root)
    assert root.name == "project"
    assert (root / "pyproject.toml").read_text() == "[project]\nname='demo'\n"
    assert (root / "src" / "app.py").read_text() == "print('demo')\n"


@pytest.mark.parametrize(
    ("suffix", "mode"),
    [
        (".tar", "w"),
        (".tar.gz", "w:gz"),
        (".tar.bz2", "w:bz2"),
        (".tar.xz", "w:xz"),
        (".tar.zst", "w:zst"),
    ],
)
def test_extracts_tar_and_compressed_tar_variants(tmp_path, suffix, mode):
    source = tmp_path / "source"
    (source / "src").mkdir(parents=True)
    (source / "pyproject.toml").write_text("[project]\nname='demo'\n")
    (source / "src" / "app.py").write_text("print('demo')\n")
    archive_path = tmp_path / f"source{suffix}"
    with tarfile.open(archive_path, mode) as archive:
        archive.add(source, arcname="project")

    repos_dir = tmp_path / "repos"
    scan_root = archive_extractor.extract_archive(
        archive_path,
        str(repos_dir),
        f"tar-{mode.replace(':', '-')}",
    )

    _assert_project_source(scan_root)


def test_extracts_zip_archive_and_collapses_single_root_directory(tmp_path):
    archive_path = tmp_path / "source.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("project/pyproject.toml", "[project]\nname='demo'\n")
        archive.writestr("project/src/app.py", "print('demo')\n")

    scan_root = archive_extractor.extract_archive(
        archive_path,
        str(tmp_path / "repos"),
        "zip-run",
    )

    _assert_project_source(scan_root)


def test_extracts_7z_archive(tmp_path):
    source = tmp_path / "source"
    (source / "src").mkdir(parents=True)
    (source / "pyproject.toml").write_text("[project]\nname='demo'\n")
    (source / "src" / "app.py").write_text("print('demo')\n")
    archive_path = tmp_path / "source.7z"
    with py7zr.SevenZipFile(archive_path, "w") as archive:
        archive.writeall(source, arcname="project")

    scan_root = archive_extractor.extract_archive(
        archive_path,
        str(tmp_path / "repos"),
        "seven-zip-run",
    )

    _assert_project_source(scan_root)


def test_extracts_rar_members_through_bounded_streams(monkeypatch, tmp_path):
    class _RarInfo:
        filename = "project/src/app.py"
        file_size = len(b"print('demo')\n")

        @staticmethod
        def is_dir():
            return False

        @staticmethod
        def is_file():
            return True

        @staticmethod
        def is_symlink():
            return False

        @staticmethod
        def needs_password():
            return False

    class _RarArchive:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        @staticmethod
        def needs_password():
            return False

        @staticmethod
        def infolist():
            return [_RarInfo()]

        @staticmethod
        def open(_member, _mode):
            return io.BytesIO(b"print('demo')\n")

    monkeypatch.setattr(archive_extractor.rarfile, "RarFile", lambda _path: _RarArchive())
    monkeypatch.setattr(
        archive_extractor.shutil,
        "which",
        lambda name: "/usr/bin/unrar" if name == "unrar" else None,
    )
    destination = tmp_path / "content"
    destination.mkdir()

    archive_extractor._extract_rar(tmp_path / "source.rar", destination)

    assert (destination / "project" / "src" / "app.py").read_text() == "print('demo')\n"


@pytest.mark.parametrize("member_name", ["../escape.py", "/absolute.py", "C:\\escape.py"])
def test_rejects_zip_path_traversal(member_name, tmp_path):
    archive_path = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(member_name, "unsafe")

    with pytest.raises(archive_extractor.ArchiveError, match="extraction root|drive path"):
        archive_extractor.extract_archive(
            archive_path,
            str(tmp_path / "repos"),
            "unsafe-zip",
        )

    assert not (tmp_path / "escape.py").exists()


def test_rejects_links_in_tar_archives(tmp_path):
    archive_path = tmp_path / "unsafe.tar"
    with tarfile.open(archive_path, "w") as archive:
        regular = tarfile.TarInfo("project/app.py")
        content = b"print('safe')\n"
        regular.size = len(content)
        archive.addfile(regular, io.BytesIO(content))
        link = tarfile.TarInfo("project/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        archive.addfile(link)

    with pytest.raises(archive_extractor.ArchiveError, match="links are not allowed"):
        archive_extractor.extract_archive(
            archive_path,
            str(tmp_path / "repos"),
            "unsafe-tar",
        )


def test_rejects_zip_symlinks(tmp_path):
    archive_path = tmp_path / "symlink.zip"
    link = zipfile.ZipInfo("project/link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("project/app.py", "print('safe')\n")
        archive.writestr(link, "../../outside")

    with pytest.raises(archive_extractor.ArchiveError, match="links are not allowed"):
        archive_extractor.extract_archive(
            archive_path,
            str(tmp_path / "repos"),
            "symlink-zip",
        )


def test_rejects_archives_over_expanded_size_limit(monkeypatch, tmp_path):
    archive_path = tmp_path / "large.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("project/app.py", "12345")
    monkeypatch.setattr(archive_extractor, "MAX_ARCHIVE_EXTRACTED_BYTES", 4)

    with pytest.raises(archive_extractor.ArchiveError, match="expand beyond"):
        archive_extractor.extract_archive(
            archive_path,
            str(tmp_path / "repos"),
            "large-zip",
        )


def test_rejects_unsupported_files_and_removes_partial_workspace(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("not an archive")
    repos_dir = tmp_path / "repos"

    with pytest.raises(archive_extractor.ArchiveError, match="Unsupported archive"):
        archive_extractor.extract_archive(source, str(repos_dir), "unsupported")

    assert not archive_extractor.archive_workspace_path(
        str(repos_dir), "unsupported"
    ).exists()


def test_rejects_symlinked_generated_workspace_root(tmp_path):
    archive_path = tmp_path / "source.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("project/app.py", "print('safe')\n")
    repository = tmp_path / "repository"
    outside = tmp_path / "outside"
    repository.mkdir()
    outside.mkdir()
    (repository / "__agentyzer_archives__").symlink_to(
        outside,
        target_is_directory=True,
    )

    with pytest.raises(archive_extractor.ArchiveError, match="symbolic link"):
        archive_extractor.extract_archive(
            archive_path,
            str(repository),
            "symlinked-root",
        )

    assert list(outside.iterdir()) == []


def test_cleanup_removes_only_the_selected_archive_workspace(tmp_path):
    repos_dir = tmp_path / "repos"
    selected = archive_extractor.archive_workspace_path(str(repos_dir), "selected")
    retained = archive_extractor.archive_workspace_path(str(repos_dir), "retained")
    selected.mkdir(parents=True)
    retained.mkdir(parents=True)

    archive_extractor.cleanup_archive_workspace(str(repos_dir), "selected")

    assert not selected.exists()
    assert retained.is_dir()


def test_repository_archive_tool_exposes_contents_to_existing_scanners(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    archive_path = repository / "packaged-source.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "application/package.json",
            '{"dependencies":{"left-pad":"1.3.0"}}',
        )
        archive.writestr(
            "application/app.py",
            "from left_pad import vulnerable_call\nvulnerable_call()\n",
        )

    inspection = archive_extractor.inspect_repository_archives(
        str(repository),
        "repository-archive-run",
    )

    assert inspection["inspected"] == 1
    assert inspection["errors"] == []
    assert inspection["archives"][0]["path"] == "packaged-source.zip"
    dependency = dependency_scanner.find_component(str(repository), "left-pad")
    assert dependency["found"] is True
    assert dependency["direct"] is True
    assert any("__agentyzer_archives__" in path for path in dependency["declared_in"])
    usage = code_scanner.search_usage(str(repository), "left_pad", ["vulnerable_call"])
    assert any("__agentyzer_archives__" in hit for hit in usage)

    archive_extractor.cleanup_archive_workspace(
        str(repository),
        "repository-archive-run",
    )
    assert archive_path.is_file()
    assert not (repository / "__agentyzer_archives__").exists()


def test_repository_archive_tool_inspects_nested_archives(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    nested_buffer = io.BytesIO()
    with zipfile.ZipFile(nested_buffer, "w") as nested:
        nested.writestr("source/app.py", "dangerous_call()\n")
    with zipfile.ZipFile(repository / "outer.zip", "w") as outer:
        outer.writestr("bundle/nested.zip", nested_buffer.getvalue())

    inspection = archive_extractor.inspect_repository_archives(
        str(repository),
        "nested-archive-run",
    )

    assert inspection["inspected"] == 2
    assert [item["nesting_level"] for item in inspection["archives"]] == [0, 1]
    assert inspection["archives"][1]["path"] == "outer.zip!nested.zip"
    assert any(
        "__agentyzer_archives__" in hit
        for hit in code_scanner.search_usage(
            str(repository),
            "dangerous_call",
            [],
        )
    )


def test_repository_archive_tool_reports_bad_archives_without_failing(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "broken.zip").write_text("not a zip")
    with zipfile.ZipFile(repository / "valid.zip", "w") as archive:
        archive.writestr("source/app.py", "print('ok')\n")

    inspection = archive_extractor.inspect_repository_archives(
        str(repository),
        "partial-archive-run",
    )

    assert inspection["inspected"] == 1
    assert inspection["archives"][0]["path"] == "valid.zip"
    assert inspection["errors"][0]["path"] == "broken.zip"


def test_repository_archive_tool_enforces_archive_count_limit(monkeypatch, tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    for name in ("one.zip", "two.zip"):
        with zipfile.ZipFile(repository / name, "w") as archive:
            archive.writestr(f"source/{name}.py", "print('ok')\n")
    monkeypatch.setattr(archive_extractor, "MAX_ARCHIVES", 1)

    inspection = archive_extractor.inspect_repository_archives(
        str(repository),
        "limited-archive-run",
    )

    assert inspection["inspected"] == 1
    assert inspection["truncated"] is True
