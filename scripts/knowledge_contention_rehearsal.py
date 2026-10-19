"""Bounded concurrent-import rehearsal; writes only to a new synthetic playground product."""

import argparse
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx

from dtvp.api_contract import API_PREFIX
from dtvp.storage import canonical, digest
from scripts.knowledge_pipeline_rehearsal import checked, login


def rehearse(client, *, rounds=3, writers=2, output=None):
    if type(rounds) is not int or type(writers) is not int or not 1 <= rounds <= 20 or not 2 <= writers <= 8 or rounds * writers > 80:
        raise ValueError('Use 1–20 rounds, 2–8 writers and at most 80 competing requests')
    login(client, 'administrator')
    me = checked(client.get(f'{API_PREFIX}/me'))
    team = next((row['id'] for row in me['workspaces'] if 'write' in row['capabilities']), None)
    if team is None:
        raise ValueError('A writable playground team is required')
    project = checked(client.post(f'{API_PREFIX}/projects', json={
        'workspace_id': team, 'name': '[SYNTHETIC] Import contention ' + uuid4().hex[:12],
    }))['id']
    base = f'{API_PREFIX}/projects/{project}'
    endpoint = base + '/versions/contention/imports'
    report = {
        'format': 'dtvp.import-contention-rehearsal/1', 'synthetic': True,
        'project_id': project, 'version': 'contention', 'requested_rounds': rounds,
        'writers': writers, 'rounds': [], 'passed': False,
        'acceptance': 'synthetic_concurrency_contract_only',
        'limitations': [
            'This creates one new synthetic playground product; existing products and approvals are untouched.',
            'Successful CAS/replay does not establish production capacity, mixed-workload latency or deployment acceptance.',
            'Projection-pending or uncertain publication stops the rehearsal; captured requests must be investigated.',
        ],
    }

    def retain(name, value):
        if output is not None:
            with (Path(output) / name).open('xb') as stream:
                stream.write(canonical(value))
                stream.flush()
                os.fsync(stream.fileno())

    retain('session.json', {key: value for key, value in report.items() if key != 'rounds'})
    expected = None
    for number in range(1, rounds + 1):
        requests = []
        for writer in range(writers):
            requests.append({
                'request_id': str(uuid4()), 'expected': expected, 'source': 'synthetic-ci',
                'build_number': number, 'occurred_at': datetime.now(UTC).isoformat(),
                'completeness': 'complete',
                'sbom': {
                    'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
                    'metadata': {'component': {'type': 'application', 'bom-ref': 'app', 'name': 'Synthetic contention product'}},
                    'components': [{'type': 'library', 'bom-ref': 'lib', 'name': 'synthetic-lib', 'version': f'{number}.{writer}'}],
                    'dependencies': [{'ref': 'app', 'dependsOn': ['lib']}, {'ref': 'lib', 'dependsOn': []}],
                },
            })
        retain(f'round-{number:02d}-requests.json', {'endpoint': endpoint, 'requests': requests})
        barrier = threading.Barrier(writers, timeout=30)

        def publish(payload):
            try:
                barrier.wait()
                response = client.post(endpoint, json=payload, timeout=30)
                return {'status': response.status_code, 'result': response.json()}
            except (httpx.HTTPError, ValueError, threading.BrokenBarrierError):
                return {'status': 'uncertain', 'result': None}

        with ThreadPoolExecutor(max_workers=writers) as executor:
            results = list(executor.map(publish, requests))
        retain(f'round-{number:02d}-responses.json', results)
        successes = [index for index, row in enumerate(results) if row['status'] == 201 and isinstance(row['result'], dict) and row['result'].get('committed') is True and row['result'].get('projection') == 'current']
        observation = {'round': number, 'expected': expected, 'statuses': [row['status'] for row in results], 'verified': False}
        report['rounds'].append(observation)
        if len(successes) != 1 or sum(row['status'] == 409 for row in results) != writers - 1:
            observation['diagnostic'] = 'Expected exactly one current commit and conflicts for all other writers; inspect captured requests'
            break
        winner = successes[0]
        receipt = results[winner]['result']
        target = receipt['updates'][0]['target']
        replay = client.post(endpoint, json=requests[winner], timeout=30)
        replayed = checked(replay)
        current = checked(client.get(base + '/versions/contention/workspace', params={'expected': target, 'limit': 1}))
        if replayed.get('publication') != receipt['publication'] or replayed.get('updates') != receipt['updates'] or replayed.get('projection') != 'current' or current.get('state') != target:
            observation['diagnostic'] = 'Replay or pinned workspace differs from the winning publication'
            break
        observation.update({'verified': True, 'state': target, 'publication': receipt['publication'], 'request_sha256': digest(canonical(requests[winner]))})
        expected = target
    report['passed'] = len(report['rounds']) == rounds and all(row['verified'] for row in report['rounds'])
    retain('report.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:8900')
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--writers', type=int, default=2)
    parser.add_argument('--output', type=Path, required=True, help='New private directory for captured requests and results')
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    with httpx.Client(base_url=args.url, timeout=30, follow_redirects=False) as client:
        report = rehearse(client, rounds=args.rounds, writers=args.writers, output=args.output)
    print(json.dumps({'project_id': report['project_id'], 'passed': report['passed'], 'output': str(args.output)}))
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
