import asyncio
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dtvp import project_archive_routes as archive_routes
from dtvp.project_archive_routes import (
    ProjectArchiveRouteDeps,
    _archive_http_error,
    _task_for_user,
    create_project_archive_router,
)
from dtvp.project_archive_services import (
    ARCHIVE_FILE_SUFFIX,
    ProjectArchiveChecksumError,
    ProjectArchiveError,
    ProjectArchiveServiceDeps,
    ProjectArchiveValidationError,
    ProjectArchiveVersionError,
)


class FakeLogger:
    def __init__(self):
        self.exceptions = []

    def exception(self, *args, **kwargs):
        self.exceptions.append((args, kwargs))
        return None


def build_archive_client(
    tmp_path,
    *,
    role="REVIEWER",
    import_api_key="import-key",
):
    app = FastAPI()
    logger = FakeLogger()
    archive_tasks = {}
    scheduled = []
    identity = {"user": "alice"}
    settings = SimpleNamespace(
        api_url="https://dependency-track.example/api",
        api_key="review-key",
        import_api_key=import_api_key,
        backend_selection=SimpleNamespace(id="dependency-track", label="Dependency-Track"),
    )

    class FakeDTClient:
        instances = []

        def __init__(self, api_url, **kwargs):
            self.api_url = api_url
            self.kwargs = kwargs
            self.__class__.instances.append(self)

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

    service_deps = ProjectArchiveServiceDeps(
        cache_manager=object(),
        logger=logger,
        sort_projects_by_version=lambda versions: versions,
        version="1.0.0",
        build_commit="abc",
        archive_path_provider=lambda: str(tmp_path),
    )
    route_deps = ProjectArchiveRouteDeps(
        archive_tasks=archive_tasks,
        service_deps=service_deps,
        logger=logger,
        get_user_role=lambda _user: role,
        dt_settings_cls=lambda: settings,
        get_dt_client_cls=lambda: FakeDTClient,
        create_tracked_task=lambda coro: scheduled.append(coro),
        archive_path_provider=lambda: str(tmp_path),
    )
    app.include_router(
        create_project_archive_router(
            route_deps,
            current_user_dependency=lambda: identity["user"],
        ),
        prefix="/api",
    )
    return SimpleNamespace(
        client=TestClient(app),
        deps=route_deps,
        tasks=archive_tasks,
        scheduled=scheduled,
        identity=identity,
        settings=settings,
        dt_client_cls=FakeDTClient,
        logger=logger,
    )


def run_scheduled(context):
    assert context.scheduled
    asyncio.run(context.scheduled.pop(0))


def test_project_archive_tasks_are_scoped_to_user():
    deps = SimpleNamespace(archive_tasks={"task-1": {"_owner": "alice"}})

    assert _task_for_user(deps, "task-1", "alice") is deps.archive_tasks["task-1"]
    assert _task_for_user(deps, "task-1", "bob") is None


def test_project_archive_routes_require_reviewer(tmp_path):
    app = FastAPI()
    service_deps = ProjectArchiveServiceDeps(
        cache_manager=object(),
        logger=FakeLogger(),
        sort_projects_by_version=lambda versions: versions,
        version="1.0.0",
        build_commit="abc",
        archive_path_provider=lambda: str(tmp_path),
    )
    route_deps = ProjectArchiveRouteDeps(
        archive_tasks={},
        service_deps=service_deps,
        logger=FakeLogger(),
        get_user_role=lambda _user: "ANALYST",
        dt_settings_cls=lambda: object(),
        get_dt_client_cls=lambda: object,
        create_tracked_task=lambda _coro: None,
        archive_path_provider=lambda: str(tmp_path),
    )
    app.include_router(
        create_project_archive_router(
            route_deps,
            current_user_dependency=lambda: "analyst",
        ),
        prefix="/api",
    )

    response = TestClient(app).get("/api/project-archives/snapshots")

    assert response.status_code == 403


def test_archive_error_mapping_preserves_safe_client_contract():
    assert _archive_http_error(ProjectArchiveVersionError("new schema")).status_code == 422
    assert _archive_http_error(ProjectArchiveChecksumError("bad digest")).status_code == 422
    assert _archive_http_error(ProjectArchiveValidationError("bad archive")).status_code == 400

    internal = _archive_http_error(ProjectArchiveError("/private/path failed"))
    assert internal.status_code == 500
    assert internal.detail == "Project archive operation failed"


def test_task_status_is_owner_scoped_and_hides_private_fields(tmp_path):
    context = build_archive_client(tmp_path)
    context.tasks["task-1"] = {
        "id": "task-1",
        "_owner": "alice",
        "_archive_path": "/private/archive.zip",
        "status": "completed",
        "result": {"filename": "archive.zip"},
    }

    response = context.client.get("/api/project-archives/tasks/task-1")
    assert response.status_code == 200
    assert response.json() == {
        "id": "task-1",
        "status": "completed",
        "result": {"filename": "archive.zip"},
    }

    context.identity["user"] = "bob"
    assert context.client.get("/api/project-archives/tasks/task-1").status_code == 404
    event_response = context.client.get("/api/project-archives/tasks/task-1/events")
    assert event_response.status_code == 200
    assert event_response.json() == {"status": "not_found"}


def test_task_download_requires_completed_owned_existing_archive(tmp_path):
    context = build_archive_client(tmp_path)
    archive_path = tmp_path / f"export{ARCHIVE_FILE_SUFFIX}"
    archive_path.write_bytes(b"archive-content")
    context.tasks["task-1"] = {
        "id": "task-1",
        "_owner": "alice",
        "_archive_path": str(archive_path),
        "status": "pending",
        "result": {"filename": archive_path.name},
    }

    url = "/api/project-archives/tasks/task-1/download"
    assert context.client.get(url).status_code == 409

    context.tasks["task-1"]["status"] = "completed"
    response = context.client.get(url)
    assert response.status_code == 200
    assert response.content == b"archive-content"
    assert archive_path.name in response.headers["content-disposition"]

    archive_path.unlink()
    assert context.client.get(url).status_code == 404

    context.identity["user"] = "bob"
    assert context.client.get(url).status_code == 404


def test_export_task_uses_review_credential_and_sanitizes_result(tmp_path, monkeypatch):
    context = build_archive_client(tmp_path)
    archive_path = tmp_path / f"export{ARCHIVE_FILE_SUFFIX}"
    captured = {}

    async def fake_export(service_deps, client, **kwargs):
        captured.update(kwargs)
        return {
            "archive_path": str(archive_path),
            "filename": archive_path.name,
            "manifest": {"sensitive": "large-internal-payload"},
        }

    monkeypatch.setattr(archive_routes, "export_project_archive", fake_export)

    response = context.client.post(
        "/api/project-archives/exports",
        json={"project_name": "Platform", "versions": ["1.0"], "refresh": False},
    )
    assert response.status_code == 200
    task_id = response.json()["task_id"]
    assert context.tasks[task_id]["status"] == "pending"

    run_scheduled(context)

    task = context.tasks[task_id]
    assert task["status"] == "completed"
    assert task["progress"] == 100
    assert "manifest" not in task["result"]
    assert task["_archive_path"] == str(archive_path)
    assert captured == {
        "project_name": "Platform",
        "versions": ["1.0"],
        "refresh": False,
        "created_by": "alice",
        "reason": "manual",
    }
    assert context.dt_client_cls.instances[0].kwargs["api_key"] == "review-key"


def test_export_failure_is_recorded_without_crashing_request(tmp_path, monkeypatch):
    context = build_archive_client(tmp_path)

    async def fake_export(*args, **kwargs):
        raise RuntimeError("backend unavailable")

    monkeypatch.setattr(archive_routes, "export_project_archive", fake_export)
    response = context.client.post(
        "/api/project-archives/exports",
        json={"project_name": "Platform"},
    )
    task_id = response.json()["task_id"]

    run_scheduled(context)

    assert context.tasks[task_id]["status"] == "failed"
    assert context.tasks[task_id]["error"] == "backend unavailable"
    assert context.logger.exceptions


def test_import_upload_enforces_size_before_creating_task(tmp_path, monkeypatch):
    context = build_archive_client(tmp_path)
    monkeypatch.setenv("DTVP_PROJECT_ARCHIVE_UPLOAD_MAX_BYTES", "1024")

    response = context.client.post(
        "/api/project-archives/imports",
        files={"file": ("archive.zip", b"x" * 1025, "application/zip")},
    )

    assert response.status_code == 413
    assert context.tasks == {}
    assert context.scheduled == []


def test_import_upload_maps_validation_error_and_removes_task(tmp_path, monkeypatch):
    context = build_archive_client(tmp_path)

    def reject_upload(*args, **kwargs):
        raise ProjectArchiveValidationError("Uploaded file is not a valid ZIP archive")

    monkeypatch.setattr(archive_routes, "store_uploaded_archive", reject_upload)
    response = context.client.post(
        "/api/project-archives/imports",
        files={"file": ("archive.zip", b"not-a-zip", "application/zip")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Uploaded file is not a valid ZIP archive"
    assert context.tasks == {}
    assert context.logger.exceptions


def test_import_preview_uses_review_credential(tmp_path, monkeypatch):
    context = build_archive_client(tmp_path)
    archive_path = tmp_path / "uploads" / "task-upload.zip"
    captured = {}

    def fake_store(*args, **kwargs):
        return str(archive_path)

    async def fake_preview(service_deps, client, **kwargs):
        captured.update(kwargs)
        return {"project_name": "Platform", "versions": ["1.0"]}

    monkeypatch.setattr(archive_routes, "store_uploaded_archive", fake_store)
    monkeypatch.setattr(archive_routes, "preview_project_archive", fake_preview)

    response = context.client.post(
        "/api/project-archives/imports",
        files={"file": ("archive.zip", b"zip", "application/zip")},
    )
    task_id = response.json()["task_id"]
    run_scheduled(context)

    assert context.tasks[task_id]["status"] == "completed"
    assert context.tasks[task_id]["result"]["project_name"] == "Platform"
    assert captured == {"archive_path": str(archive_path)}
    assert context.dt_client_cls.instances[0].kwargs["api_key"] == "review-key"


@pytest.mark.parametrize(
    ("kind", "status", "extra", "expected_detail"),
    [
        ("import_preview", "pending", {}, "Archive task is running"),
        ("import_preview", "failed", {}, "Archive preview is not ready"),
        ("export", "completed", {}, "Task is not an archive import"),
        ("import_apply", "completed", {"_preview_result": {}}, "Archive import cannot be applied again"),
        ("import_apply", "failed", {}, "Archive import cannot be applied again"),
    ],
)
def test_apply_rejects_invalid_task_transitions(
    tmp_path,
    kind,
    status,
    extra,
    expected_detail,
):
    context = build_archive_client(tmp_path)
    context.tasks["task-1"] = {
        "id": "task-1",
        "_owner": "alice",
        "_archive_path": str(tmp_path / "upload.zip"),
        "kind": kind,
        "status": status,
        "result": {"preview": True},
        **extra,
    }

    response = context.client.post(
        "/api/project-archives/imports/task-1/apply",
        json={"mode": "create_missing"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == expected_detail
    assert context.scheduled == []


def test_apply_requires_dedicated_import_credential(tmp_path):
    context = build_archive_client(tmp_path, import_api_key=None)
    context.tasks["task-1"] = {
        "id": "task-1",
        "_owner": "alice",
        "_archive_path": str(tmp_path / "upload.zip"),
        "kind": "import_preview",
        "status": "completed",
        "result": {"preview": True},
    }

    response = context.client.post(
        "/api/project-archives/imports/task-1/apply",
        json={"mode": "update"},
    )

    assert response.status_code == 503
    assert "dedicated Dependency-Track archive-import credential" in response.json()[
        "detail"
    ]
    assert context.tasks["task-1"]["kind"] == "import_preview"


def test_apply_uses_import_credential_prevents_replay_and_allows_failed_retry(
    tmp_path,
    monkeypatch,
):
    context = build_archive_client(tmp_path)
    archive_path = tmp_path / "upload.zip"
    archive_path.write_bytes(b"archive")
    context.tasks["task-1"] = {
        "id": "task-1",
        "_owner": "alice",
        "_archive_path": str(archive_path),
        "kind": "import_preview",
        "status": "completed",
        "result": {"preview": True},
    }

    async def fail_apply(*args, **kwargs):
        raise RuntimeError("temporary import failure")

    monkeypatch.setattr(archive_routes, "apply_project_archive", fail_apply)
    first = context.client.post(
        "/api/project-archives/imports/task-1/apply",
        json={"mode": "update"},
    )
    assert first.status_code == 200
    run_scheduled(context)
    assert context.tasks["task-1"]["status"] == "failed"
    assert context.tasks["task-1"]["_preview_result"] == {"preview": True}

    captured = {}

    async def succeed_apply(service_deps, client, **kwargs):
        captured.update(kwargs)
        return {"created": 1, "updated": 2}

    monkeypatch.setattr(archive_routes, "apply_project_archive", succeed_apply)
    retry = context.client.post(
        "/api/project-archives/imports/task-1/apply",
        json={"mode": "create_missing"},
    )
    assert retry.status_code == 200
    run_scheduled(context)

    assert captured == {
        "archive_path": str(archive_path),
        "mode": "create_missing",
    }
    assert context.tasks["task-1"]["status"] == "completed"
    assert context.tasks["task-1"]["result"] == {"created": 1, "updated": 2}
    assert all(
        instance.kwargs["api_key"] == "import-key"
        for instance in context.dt_client_cls.instances
    )

    replay = context.client.post(
        "/api/project-archives/imports/task-1/apply",
        json={"mode": "create_missing"},
    )
    assert replay.status_code == 409


def test_apply_task_is_owner_scoped(tmp_path):
    context = build_archive_client(tmp_path)
    context.tasks["task-1"] = {
        "id": "task-1",
        "_owner": "alice",
        "_archive_path": str(tmp_path / "upload.zip"),
        "kind": "import_preview",
        "status": "completed",
    }
    context.identity["user"] = "bob"

    response = context.client.post(
        "/api/project-archives/imports/task-1/apply",
        json={"mode": "update"},
    )

    assert response.status_code == 404


def test_snapshot_routes_list_download_and_return_404_for_missing(tmp_path, monkeypatch):
    context = build_archive_client(tmp_path)
    filename = f"snapshot{ARCHIVE_FILE_SUFFIX}"
    archive_path = tmp_path / filename
    archive_path.write_bytes(b"snapshot")
    monkeypatch.setattr(
        archive_routes,
        "list_project_archives",
        lambda path: [{"filename": filename, "size": 8}],
    )

    listing = context.client.get("/api/project-archives/snapshots")
    assert listing.json() == [{"filename": filename, "size": 8}]

    download = context.client.get(
        f"/api/project-archives/snapshots/{filename}/download"
    )
    assert download.status_code == 200
    assert download.content == b"snapshot"

    missing = context.client.get(
        f"/api/project-archives/snapshots/missing{ARCHIVE_FILE_SUFFIX}/download"
    )
    assert missing.status_code == 404
    assert missing.json()["detail"] == "Archive not found"

    wrong_suffix = context.client.get(
        "/api/project-archives/snapshots/not-an-archive.zip/download"
    )
    assert wrong_suffix.status_code == 404
