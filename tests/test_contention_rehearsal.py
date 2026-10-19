"""Concurrent import rehearsal never writes outside a new synthetic playground product."""

import json
import threading

import httpx
import pytest

from scripts.knowledge_contention_rehearsal import rehearse
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app

app = knowledge_app


def server(*, broken=None):
    calls, lock, current, receipts = [], threading.Lock(), None, {}

    def handle(request):
        nonlocal current
        with lock:
            calls.append(request)
            path = request.url.path
            if path.endswith('/login'):
                return httpx.Response(200, json={}, headers={'set-cookie': 'dtvp_csrf=synthetic'})
            if path.endswith('/me'):
                return httpx.Response(200, json={'playground': True, 'workspaces': [{'id': 'team', 'capabilities': ['write']}]})
            if path == '/api/v1/projects':
                assert json.loads(request.content)['name'].startswith('[SYNTHETIC]')
                return httpx.Response(201, json={'id': 'new-synthetic'})
            if path.endswith('/workspace'):
                assert request.url.params['expected'] == current
                return httpx.Response(200, json={'state': current})
            assert path == '/api/v1/projects/new-synthetic/versions/contention/imports'
            body = json.loads(request.content)
            if body['request_id'] in receipts:
                result = receipts[body['request_id']]
                return httpx.Response(201, json={**result, 'publication': 'wrong'} if broken == 'replay' else result)
            if body['expected'] != current:
                return httpx.Response(409, json={'detail': 'Changed head'})
            current = str(len(receipts) + 1).zfill(64)
            result = {'committed': True, 'projection': 'current', 'publication': current, 'updates': [{'target': current}]}
            receipts[body['request_id']] = result
            if broken == 'uncertain':
                return httpx.Response(503, json={'detail': 'Uncertain publication'})
            if broken == 'projection':
                return httpx.Response(202, json={**result, 'projection': 'pending'})
            return httpx.Response(201, json=result)

    return calls, handle


def test_competing_requests_exact_replay_and_retained_inputs(tmp_path):
    calls, handle = server()
    with httpx.Client(base_url='http://synthetic.test', transport=httpx.MockTransport(handle)) as client:
        report = rehearse(client, rounds=3, writers=3, output=tmp_path)
    assert report['passed']
    assert len(report['rounds']) == 3
    assert all(row['statuses'].count(201) == 1 and row['statuses'].count(409) == 2 for row in report['rounds'])
    assert json.loads((tmp_path / 'report.json').read_bytes()) == report
    captures = list(tmp_path.glob('round-*-requests.json'))
    assert len(captures) == 3
    assert len([request for request in calls if request.method == 'POST' and request.url.path.endswith('/imports')]) == 12


@pytest.mark.parametrize('broken', ['uncertain', 'projection', 'replay'])
def test_failed_or_uncertain_round_stops_without_new_baseline_or_repin(broken, tmp_path):
    _, handle = server(broken=broken)
    with httpx.Client(base_url='http://synthetic.test', transport=httpx.MockTransport(handle)) as client:
        report = rehearse(client, rounds=3, writers=2, output=tmp_path)
    assert not report['passed']
    assert len(report['rounds']) == 1
    assert (tmp_path / 'round-01-requests.json').exists()
    assert not (tmp_path / 'round-02-requests.json').exists()


def test_production_and_invalid_bounds_are_rejected_before_inventory_writes():
    calls = []

    def handle(request):
        calls.append(request.url.path)
        return httpx.Response(200, json={} if request.url.path.endswith('/login') else {'playground': False}, headers={'set-cookie': 'dtvp_csrf=synthetic'})

    with httpx.Client(base_url='http://synthetic.test', transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(ValueError, match='80 competing'):
            rehearse(client, rounds=20, writers=8)
        assert calls == []
        with pytest.raises(ValueError, match='isolated playground'):
            rehearse(client)
    assert calls == ['/api/v1/playground/login', '/api/v1/me']


def test_real_postgres_concurrent_publications_keep_existing_projects(client, app, tmp_path):
    if app.state.engine.dialect.name != 'postgresql':
        pytest.skip('Concurrent SQL projection qualification requires disposable PostgreSQL')
    login(client, 'administrator')
    before = {row['id'] for row in client.get('/api/v1/projects').json()}
    report = rehearse(client, rounds=3, writers=3, output=tmp_path)
    assert report['passed'], report
    after = {row['id'] for row in client.get('/api/v1/projects').json()}
    assert after == before | {report['project_id']}
