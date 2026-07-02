import zipfile
from pathlib import Path

import pytest

from dtvp.project_archive_services import (
    ARCHIVE_SCHEMA_VERSION,
    ProjectArchiveChecksumError,
    ProjectArchiveServiceDeps,
    ProjectArchiveValidationError,
    apply_project_archive,
    export_project_archive,
    load_project_archive,
    preview_project_archive,
)


PROJECT = {
    "uuid": "source-project-1",
    "name": "ArchiveApp",
    "version": "1.0.0",
    "classifier": "APPLICATION",
}
SOURCE_COMPONENT = {
    "uuid": "source-component-1",
    "name": "library-a",
    "version": "1.2.3",
    "purl": "pkg:maven/example/library-a@1.2.3",
}
SOURCE_VULNERABILITY = {
    "uuid": "source-vuln-1",
    "vulnId": "CVE-2026-0001",
    "name": "CVE-2026-0001",
    "aliases": [{"ghsa": "GHSA-abcd-1234"}],
}
SOURCE_ANALYSIS = {
    "analysisState": "NOT_AFFECTED",
    "analysisDetails": "Restored assessment",
    "analysisJustification": "CODE_NOT_PRESENT",
    "isSuppressed": True,
    "analysisComments": [{"comment": "historical comment", "timestamp": 1}],
}
SOURCE_FINDING = {
    "uuid": "source-finding-1",
    "matrix": "source-project-1:source-component-1:source-vuln-1",
    "component": SOURCE_COMPONENT,
    "vulnerability": SOURCE_VULNERABILITY,
    "analysis": SOURCE_ANALYSIS,
}
SOURCE_BOM = {
    "bomFormat": "CycloneDX",
    "metadata": {"component": {"uuid": "source-project-1", "bom-ref": "root"}},
    "components": [
        {
            **SOURCE_COMPONENT,
            "bom-ref": "pkg:maven/example/library-a@1.2.3",
        }
    ],
    "dependencies": [],
}


class FakeCacheManager:
    def __init__(self):
        self.saved_payloads = []
        self.queued_payloads = []

    async def get_projects(self, _client, name):
        return [PROJECT] if name == PROJECT["name"] else []

    async def get_vulnerabilities(self, _client, _project_uuid, refresh=False):
        return [SOURCE_FINDING]

    async def get_project_vulnerabilities(self, _client, _project_uuid, refresh=False):
        return [SOURCE_VULNERABILITY]

    async def get_bom(self, _client, _project_uuid, refresh=False):
        return SOURCE_BOM

    async def get_analysis(
        self,
        _client,
        project_uuid,
        component_uuid,
        vulnerability_uuid,
        refresh=False,
    ):
        assert project_uuid == PROJECT["uuid"]
        assert component_uuid == SOURCE_COMPONENT["uuid"]
        assert vulnerability_uuid == SOURCE_VULNERABILITY["uuid"]
        return SOURCE_ANALYSIS

    def _save_local_analysis(self, payload):
        self.saved_payloads.append(payload)

    async def queue_analysis_update(self, payload, replace=False):
        self.queued_payloads.append(payload)
        return "queued"

    async def refresh_project(self, _project_uuid, _client):
        return None

    def get_cached_project_versions(self):
        return [PROJECT]


class FakeLogger:
    def debug(self, *args, **kwargs):
        return None

    def warning(self, *args, **kwargs):
        return None


class FakeExportClient:
    base_url = "http://dependency-track.example"


class FakeRestoreClient:
    base_url = "http://dependency-track.example"

    def __init__(self, *, existing=False, fail_update=False):
        self.existing = existing
        self.fail_update = fail_update
        self.uploads = []
        self.updated_payloads = []
        self.target_project = {
            "uuid": "target-project-1",
            "name": PROJECT["name"],
            "version": PROJECT["version"],
        }
        self.target_finding = {
            "uuid": "target-finding-1",
            "component": {
                **SOURCE_COMPONENT,
                "uuid": "target-component-1",
            },
            "vulnerability": {
                **SOURCE_VULNERABILITY,
                "uuid": "target-vuln-1",
            },
        }

    async def find_project_by_name_version(self, _name, _version):
        return self.target_project if self.existing else None

    async def upload_bom(self, bom, **kwargs):
        self.uploads.append({"bom": bom, **kwargs})
        self.existing = True
        return {"token": "token"}

    async def wait_for_project_version(self, _name, _version):
        return self.target_project

    async def wait_for_project_findings(self, _project_uuid, expected_min_findings=0):
        return [self.target_finding]

    async def get_bom(self, _project_uuid):
        return SOURCE_BOM

    async def update_analysis(self, **payload):
        if self.fail_update:
            raise RuntimeError("offline")
        self.updated_payloads.append(payload)
        return {"status": "updated"}


def make_deps(tmp_path: Path, cache=None):
    return ProjectArchiveServiceDeps(
        cache_manager=cache or FakeCacheManager(),
        logger=FakeLogger(),
        sort_projects_by_version=lambda versions: versions,
        version="1.2.3",
        build_commit="abc123",
        archive_path_provider=lambda: str(tmp_path),
    )


async def create_archive(tmp_path: Path, cache=None):
    deps = make_deps(tmp_path, cache=cache)
    result = await export_project_archive(
        deps,
        FakeExportClient(),
        project_name=PROJECT["name"],
        refresh=True,
        created_by="reviewer",
    )
    return deps, result


@pytest.mark.asyncio
async def test_export_project_archive_contains_manifest_and_version_files(tmp_path):
    _deps, result = await create_archive(tmp_path)
    archive = load_project_archive(result["archive_path"])

    manifest = archive["manifest"]
    assert manifest["schema_version"] == ARCHIVE_SCHEMA_VERSION
    assert manifest["dtvp"]["version"] == "1.2.3"
    assert manifest["source"]["project_name"] == PROJECT["name"]
    assert len(archive["versions"]) == 1
    version = archive["versions"][0]
    assert version["project"]["uuid"] == PROJECT["uuid"]
    assert version["bom"]["components"][0]["name"] == SOURCE_COMPONENT["name"]
    assert version["findings"][0]["vulnerability"]["vulnId"] == "CVE-2026-0001"
    assert version["assessments"][0]["analysis"]["analysisDetails"] == (
        "Restored assessment"
    )
    assert "analysisComments" not in version["assessments"][0]["analysis"]
    assert "analysis_comments" not in version["assessments"][0]["analysis"]


@pytest.mark.asyncio
async def test_export_project_archive_can_write_diffable_expanded_tree(
    tmp_path,
    monkeypatch,
):
    expanded_base = tmp_path / "git-tree"
    monkeypatch.setenv("DTVP_PROJECT_ARCHIVE_EXPANDED_ENABLED", "true")
    monkeypatch.setenv("DTVP_PROJECT_ARCHIVE_EXPANDED_PATH", str(expanded_base))

    _deps, result = await create_archive(tmp_path)

    expanded_path = Path(result["expanded_path"])
    assert expanded_path.parent == expanded_base
    assert expanded_path.is_dir()
    assert (expanded_path / "versions" / "0001-1.0.0" / "bom.json").is_file()
    assert not list(expanded_path.glob("*.zip"))

    manifest = (expanded_path / "manifest.json").read_text()
    assert "created_at" not in manifest
    assert "build_commit" not in manifest
    assert "dtvp.project-archive/v1" in manifest

    rebuilt_archive = tmp_path / "rebuilt-from-tree.zip"
    with zipfile.ZipFile(rebuilt_archive, "w") as archive:
        for path in expanded_path.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(expanded_path).as_posix())
    rebuilt = load_project_archive(str(rebuilt_archive))
    assert rebuilt["versions"][0]["project"]["name"] == PROJECT["name"]


@pytest.mark.asyncio
async def test_load_project_archive_rejects_checksum_mismatch(tmp_path):
    _deps, result = await create_archive(tmp_path)
    original = Path(result["archive_path"])
    corrupted = tmp_path / "corrupted.zip"

    with zipfile.ZipFile(original, "r") as source, zipfile.ZipFile(
        corrupted,
        "w",
    ) as target:
        for name in source.namelist():
            data = source.read(name)
            if name.endswith("/findings.json"):
                data = b"[]\n"
            target.writestr(name, data)

    with pytest.raises(ProjectArchiveChecksumError):
        load_project_archive(str(corrupted))


def test_load_project_archive_rejects_unsafe_member_path(tmp_path):
    archive_path = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../evil.json", "{}")
        archive.writestr("manifest.json", "{}")

    with pytest.raises(ProjectArchiveValidationError):
        load_project_archive(str(archive_path))


@pytest.mark.asyncio
async def test_preview_project_archive_reports_existing_versions_without_writes(tmp_path):
    deps, result = await create_archive(tmp_path)
    client = FakeRestoreClient(existing=True)

    preview = await preview_project_archive(
        deps,
        client,
        archive_path=result["archive_path"],
    )

    assert preview["project_name"] == PROJECT["name"]
    assert preview["versions"][0]["target_exists"] is True
    assert preview["versions"][0]["restorable_assessment_count"] == 1
    assert client.uploads == []
    assert client.updated_payloads == []


@pytest.mark.asyncio
async def test_apply_project_archive_creates_missing_and_restores_assessment(tmp_path):
    cache = FakeCacheManager()
    deps, result = await create_archive(tmp_path, cache=cache)
    client = FakeRestoreClient(existing=False)

    applied = await apply_project_archive(
        deps,
        client,
        archive_path=result["archive_path"],
        mode="create_missing",
    )

    assert applied["summary"]["created"] == 1
    assert applied["summary"]["restored_assessments"] == 1
    assert client.uploads[0]["project_name"] == PROJECT["name"]
    assert client.updated_payloads == [
        {
            "project_uuid": "target-project-1",
            "component_uuid": "target-component-1",
            "vulnerability_uuid": "target-vuln-1",
            "state": "NOT_AFFECTED",
            "details": "Restored assessment",
            "justification": "CODE_NOT_PRESENT",
            "suppressed": True,
        }
    ]
    assert cache.saved_payloads == client.updated_payloads


@pytest.mark.asyncio
async def test_apply_project_archive_create_missing_skips_existing_versions(tmp_path):
    deps, result = await create_archive(tmp_path)
    client = FakeRestoreClient(existing=True)

    applied = await apply_project_archive(
        deps,
        client,
        archive_path=result["archive_path"],
        mode="create_missing",
    )

    assert applied["summary"]["skipped_existing"] == 1
    assert client.uploads == []
    assert client.updated_payloads == []


@pytest.mark.asyncio
async def test_apply_project_archive_update_touches_existing_versions(tmp_path):
    deps, result = await create_archive(tmp_path)
    client = FakeRestoreClient(existing=True)

    applied = await apply_project_archive(
        deps,
        client,
        archive_path=result["archive_path"],
        mode="update",
    )

    assert applied["summary"]["updated"] == 1
    assert client.uploads[0]["project_uuid"] == "target-project-1"
    assert applied["summary"]["restored_assessments"] == 1
