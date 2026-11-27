import { describe, expect, it } from 'vitest'
import { ALL_COMPONENTS, formatRelativeTime, mergeEvidenceRows, unusableEvidenceId } from '../codeEvidence'
import type { CodeAnalysisResultRecord, CodeEvidence } from '../api'

const run = (id: string, component: string, finishedAt: string, extra: Partial<CodeAnalysisResultRecord> = {}) => ({
    analysis_run_id: id,
    vuln_id: 'CVE-1',
    component_name: component,
    source: 'manual',
    finished_at: finishedAt,
    summary: { verdict: 'Not Affected', confidence: 'High', executive_summary: { assessment: `Summary ${id}` } },
    ...extra,
}) as unknown as CodeAnalysisResultRecord

const evidence = (id: string, overrides: Partial<CodeEvidence> = {}): CodeEvidence => ({
    kind: 'agent',
    evidence_id: id,
    project_name: 'App',
    vuln_id: 'CVE-1',
    scope: 'components',
    targets: [{ component: 'lib-a', finding_uuid: 'f1' }],
    title: `Title ${id}`,
    body_markdown: 'Body',
    references: [],
    suggested_state: null,
    author: { username: 'alice', agent_label: 'bot', token_id: 'tok', authority: 'ANALYST' },
    created_at: '2026-07-02T00:00:00Z',
    withdrawn: null,
    applications: [],
    ...overrides,
})

describe('mergeEvidenceRows', () => {
    it('groups by component, newest first, with earlier analyzer runs apart', () => {
        const groups = mergeEvidenceRows(
            [
                run('old', 'lib-a', '2026-07-01T00:00:00Z'),
                run('new', 'lib-a', '2026-07-03T00:00:00Z', { used_in_assessment: true }),
                run('bench', 'lib-a', '2026-07-04T00:00:00Z', { source: 'benchmark' }),
                run('b', 'LIB-B', '2026-07-01T00:00:00Z'),
            ],
            [
                evidence('ev_a', { applications: [{ finding_uuid: 'f1', applied_by: 'rita', applied_at: 'x' }] }),
                evidence('ev_all', { scope: 'vulnerability', targets: [] }),
            ],
            ['lib-a', 'lib-b'],
        )
        expect(groups.map(group => group.label)).toEqual([ALL_COMPONENTS, 'lib-a', 'lib-b'])
        const libA = groups[1]
        expect(libA.rows.map(row => row.id)).toEqual(['new', 'ev_a'])
        expect(libA.earlier.map(row => row.id)).toEqual(['old'])
        expect(libA.rows[1]).toMatchObject({ kind: 'agent', sourceLabel: 'Agent: bot', used: true, author: 'alice' })
        expect(libA.rows[0]).toMatchObject({ kind: 'analyzer', title: 'Summary new', decision: 'Not Affected', confidence: 'High', used: true })
        expect(libA.earlier[0]).toMatchObject({ kind: 'analyzer', used: false })
        expect(groups[2].rows[0].id).toBe('b')
    })

    it('uses dependency names for agents while preserving application scope for analyzers', () => {
        const groups = mergeEvidenceRows(
            [run('est-run', 'vp-est-srv', '2026-07-01T00:00:00Z'), run('auth-run', 'vp-auth-server', '2026-07-01T00:00:00Z')],
            [evidence('est-evidence', { targets: [{ component: 'node-forge', finding_uuid: 'est-6156' }] })],
            ['vp-est-srv'],
            { agentComponentNames: ['node-forge'] },
        )
        expect(groups.map(group => group.label)).toEqual(['node-forge', 'vp-est-srv'])
        expect(groups.flatMap(group => group.rows.map(row => row.id))).toEqual(['est-evidence', 'est-run'])
    })

    it('keeps only the scope and filters by source', () => {
        const records = [run('a', 'lib-a', '2026-07-01T00:00:00Z'), run('x', 'other', '2026-07-01T00:00:00Z')]
        const agents = [evidence('ev_other', { targets: [{ component: 'other' }] }), evidence('ev_a')]
        const scoped = mergeEvidenceRows(records, agents, ['lib-a'])
        expect(scoped.flatMap(group => group.rows.map(row => row.id))).toEqual(['ev_a', 'a'])
        expect(mergeEvidenceRows(records, agents, ['lib-a'], { filter: 'agent' }).flatMap(g => g.rows.map(r => r.kind))).toEqual(['agent'])
        expect(mergeEvidenceRows(records, agents, ['lib-a'], { filter: 'analyzer' }).flatMap(g => g.rows.map(r => r.kind))).toEqual(['analyzer'])
    })
})

describe('unusableEvidenceId', () => {
    it('names the evidence a rejected save could not use', () => {
        expect(unusableEvidenceId('Code evidence ev_1 was withdrawn and cannot be used')).toBe('ev_1')
        expect(unusableEvidenceId('Unknown code evidence ev_9')).toBe('ev_9')
        expect(unusableEvidenceId('Code evidence ev_3 belongs to another project')).toBe('ev_3')
        expect(unusableEvidenceId('Code evidence is not available')).toBeNull()
        expect(unusableEvidenceId(undefined)).toBeNull()
    })
})

describe('formatRelativeTime', () => {
    it('is short and falls back to the date', () => {
        const now = Date.parse('2026-07-10T12:00:00Z')
        expect(formatRelativeTime('2026-07-10T11:59:30Z', now)).toBe('just now')
        expect(formatRelativeTime('2026-07-10T11:00:00Z', now)).toBe('1 h ago')
        expect(formatRelativeTime('2026-07-08T12:00:00Z', now)).toBe('2 d ago')
        expect(formatRelativeTime('2026-01-01T00:00:00Z', now)).toBe('2026-01-01')
        expect(formatRelativeTime('', now)).toBe('unknown time')
    })
})
