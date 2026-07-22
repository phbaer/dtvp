from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from dtvp.project_archive_routes import (
    ProjectArchiveRouteDeps,
    _task_for_user,
    create_project_archive_router,
)
from dtvp.project_archive_services import ProjectArchiveServiceDeps


class FakeLogger:
    def exception(self, *args, **kwargs):
        return None


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
