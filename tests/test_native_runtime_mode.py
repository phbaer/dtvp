"""Explicit native-only cutover disables compatibility work without deleting history."""

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text

from dtvp.config import Settings
from dtvp.db import engine_for
from dtvp.jobs import NATIVE_JOB_KINDS, work_once
from dtvp.main import create_app
from dtvp.models import Finding, Job, Release
from tests.conftest import login
from tests.test_knowledge_api import body, imported, product


@pytest.fixture(params=["sqlite"] + (["postgres"] if os.getenv("DTVP_TEST_DATABASE_URL") else []))
def app(tmp_path, request):
    url = "sqlite:///:memory:"
    if request.param == "postgres":
        url = os.environ["DTVP_TEST_DATABASE_URL"]
        if not url.rsplit("/", 1)[-1].endswith("_test"):
            pytest.fail("Disposable test database name must end in _test")
        engine = engine_for(url)
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
        engine.dispose()
    return create_app(
        Settings(
            _env_file=None,
            playground=True,
            legacy_review_enabled=False,
            database_url=url,
            artifact_dir=tmp_path / "artifacts",
            frontend_dir=tmp_path / "absent",
        )
    )


def test_native_only_hides_legacy_contracts_but_retains_shared_and_migration_services(
    analyst, app, bom
):
    assert analyst.get('/api/v2/me').json()['legacy_review_enabled'] is False
    schema = analyst.get('/openapi.json').json()['paths']
    for path in (
        '/api/v2/findings', '/api/v2/snapshots', '/api/v2/jobs', '/api/v2/statistics',
        '/api/v2/findings/{finding_id}/analyses',
        '/api/v2/findings/{finding_id}/rescoring',
        '/api/v2/projects/{project_id}/releases',
        '/api/v2/releases/{release_id}/metadata',
        '/api/v2/releases/{release_id}/attachments',
        '/api/v2/snapshots/{snapshot_id}/exports/vex',
        '/api/v2/playground/replay/{scenario}',
        '/api/v2/playground/scale',
    ):
        if path == '/api/v2/jobs':
            assert 'get' in schema[path] and 'post' not in schema[path]
        else:
            assert path not in schema
    assert analyst.get('/api/v2/findings').status_code == 404
    assert analyst.post('/api/v2/snapshots', json={}).status_code == 404
    assert analyst.get('/api/v2/workspaces').status_code == 200
    assert analyst.get('/api/v2/cvss/metrics/3.1').status_code == 200
    project_id = product(analyst)
    assert analyst.get(f'/api/v2/projects/{project_id}/rescore-policy').status_code == 200
    assert '/api/v3/projects/{project_id}/versions/{version}/migration/v2/preview' in schema
    head = imported(analyst, project_id, 'native-1', body(bom))
    assert analyst.get(
        f'/api/v3/projects/{project_id}/states/{head}/license-worklist'
    ).status_code == 200
    assert analyst.get('/api/v2/jobs').status_code == 200
    with app.state.sessions() as db:
        # Turning off the old interface does not remove its retained SQL data.
        assert db.scalar(select(func.count()).select_from(Finding)) > 0


def test_native_only_worker_fails_old_queued_jobs_before_external_calls(analyst, app, monkeypatch):
    actor_id = analyst.get("/api/v2/me").json()["id"]
    with app.state.sessions.begin() as db:
        release = db.scalar(select(Release))
        job = Job(project_id=release.project_id, actor_id=actor_id, kind='import-dt', payload={})
        db.add(job)
        db.flush()
        job_id = job.id
    monkeypatch.setattr('dtvp.jobs.client', lambda: pytest.fail('No legacy outbound call allowed'))
    assert work_once(app.state.sessions, app.state.artifacts, app.state.settings)
    with app.state.sessions() as db:
        job = db.get(Job, job_id)
        assert job.status == 'failed'
        assert 'Legacy review is disabled' in job.error
    assert analyst.post(f'/api/v2/jobs/{job_id}/retry').status_code == 410
    assert analyst.post(f'/api/v2/jobs/{job_id}/cancel').status_code == 200


@pytest.mark.parametrize('kind', sorted(NATIVE_JOB_KINDS))
def test_shared_retry_never_requeues_native_jobs_as_legacy(analyst, app, kind):
    actor_id = analyst.get("/api/v2/me").json()["id"]
    with app.state.sessions.begin() as db:
        release = db.scalar(select(Release))
        job = Job(project_id=release.project_id, actor_id=actor_id, kind=kind, payload={}, status='failed')
        db.add(job)
        db.flush()
        job_id = job.id
    result = analyst.post(f'/api/v2/jobs/{job_id}/retry')
    assert result.status_code == 409
    assert 'native job retry endpoint' in result.json()['detail']


def test_compatibility_mode_stays_default(tmp_path):
    settings = Settings(
        _env_file=None, playground=True, database_url='sqlite:///:memory:',
        artifact_dir=tmp_path / 'default', frontend_dir=tmp_path / 'absent'
    )
    with TestClient(create_app(settings)) as client:
        login(client)
        assert client.get('/api/v2/me').json()['legacy_review_enabled'] is True
        assert client.get('/api/v2/findings').status_code == 200
