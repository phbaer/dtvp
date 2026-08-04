import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref } from 'vue'
import VulnGroupCard from '../VulnGroupCard.vue'
import CodeAnalysisPanel from '../CodeAnalysisPanel.vue'
import defaultRescoreRules from '../../../../data/rescore_rules.json'
import type { CodeAnalysisAssessResponse } from '../../lib/api'

vi.mock('../../lib/api', () => ({
    updateAssessment: vi.fn((payload: any) => Promise.resolve(payload.instances.map((instance: any) => ({
        status: 'success',
        uuid: instance.finding_uuid,
        new_state: payload.state,
        new_details: payload.details,
    })))),
    getAssessmentDetails: vi.fn(() => Promise.resolve([])),
    getKnownUsers: vi.fn(() => Promise.resolve([])),
    codeAnalysisBenchmarkResult: vi.fn(),
    codeAnalysisDeleteResult: vi.fn(),
    codeAnalysisGetPrompts: vi.fn(() => Promise.resolve({ bundles: [] })),
    codeAnalysisGetResult: vi.fn(),
    codeAnalysisListVulnerabilityResults: vi.fn(() => Promise.resolve([])),
}))

import { updateAssessment } from '../../lib/api'

const makeResult = (component: string, verdict: string, adjusted?: { score: number, vector: string }): CodeAnalysisAssessResponse => ({
    assessment: {
        affected: verdict.toLowerCase() === 'affected',
        verdict,
        confidence: 'high',
        exposure: verdict.toLowerCase() === 'affected' ? 'reachable' : 'none',
        summary: `Summary for ${component}.`,
        reasoning: `Reasoning for ${component}.`,
        ...(adjusted
            ? {
                adjusted_cvss: {
                    original_score: 9.8,
                    adjusted_score: adjusted.score,
                    adjusted_vector: adjusted.vector,
                    reasons: [],
                    summary: '',
                    version_affected: true,
                },
            }
            : {}),
    },
    steps: [],
} as CodeAnalysisAssessResponse)

describe('VulnGroupCard apply-all analyzer assessments', () => {
    const group = {
        id: 'CVE-2026-4242',
        title: 'Multi component vulnerability',
        description: 'Affects two owned components.',
        severity: 'CRITICAL',
        cvss: 9.8,
        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        tags: ['TEAM-A', 'TEAM-B'],
        affected_versions: [
            {
                project_name: 'App1',
                project_version: '1.0',
                project_uuid: 'p1',
                components: [
                    {
                        project_name: 'App1',
                        project_version: '1.0',
                        project_uuid: 'p1',
                        component_name: 'lib-a',
                        component_version: '1.0',
                        component_uuid: 'c1',
                        vulnerability_uuid: 'v1',
                        finding_uuid: 'f1',
                        analysis_state: 'NOT_SET',
                        is_suppressed: false,
                        analysis_comments: [],
                        tags: ['TEAM-A'],
                        is_direct_dependency: true,
                    },
                    {
                        project_name: 'App1',
                        project_version: '1.0',
                        project_uuid: 'p1',
                        component_name: 'lib-b',
                        component_version: '2.0',
                        component_uuid: 'c2',
                        vulnerability_uuid: 'v1',
                        finding_uuid: 'f2',
                        analysis_state: 'NOT_SET',
                        is_suppressed: false,
                        analysis_comments: [],
                        tags: ['TEAM-B'],
                        is_direct_dependency: true,
                    },
                ],
            },
        ],
    }

    const mountCard = (rescoreRules?: Record<string, any>) => mount(VulnGroupCard, {
        props: { group: JSON.parse(JSON.stringify(group)) },
        global: {
            provide: {
                user: ref({ role: 'REVIEWER', username: 'tester' }),
                teamMapping: ref({ 'lib-a': ['TEAM-A'], 'lib-b': ['TEAM-B'] }),
                ...(rescoreRules ? { rescoreRules: ref(rescoreRules) } : {}),
            },
            stubs: { teleport: true },
        },
    })

    beforeEach(() => {
        vi.clearAllMocks()
    })

    const emitApplyAll = async (
        wrapper: ReturnType<typeof mountCard>,
        runs: Array<Record<string, any>>,
    ) => {
        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        wrapper.getComponent(CodeAnalysisPanel).vm.$emit('apply-all-results', runs)
        await flushPromises()
    }

    const applyAll = async (wrapper: ReturnType<typeof mountCard>) => emitApplyAll(wrapper, [
        { component: 'lib-a', result: makeResult('lib-a', 'not affected', { score: 0, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N' }), runId: 'run-a' },
        { component: 'lib-b', result: makeResult('lib-b', 'affected', { score: 8.2, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H' }), runId: 'run-b' },
    ])

    const applyAllNotAffected = async (wrapper: ReturnType<typeof mountCard>) => emitApplyAll(wrapper, [
        { component: 'lib-a', result: makeResult('lib-a', 'not affected', { score: 0, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N' }), runId: 'run-a' },
        { component: 'lib-b', result: makeResult('lib-b', 'not affected'), runId: 'run-b' },
    ])

    it('stages one draft per team and the worst assessment as the global one', async () => {
        const wrapper = mountCard()
        await applyAll(wrapper)

        const vm = wrapper.vm as any
        expect(vm.selectedTeam).toBe('')
        expect(vm.state).toBe('EXPLOITABLE')
        expect(vm.pendingVector).toBe('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H')
        // The score is recalculated from the worst analyzer vector.
        expect(vm.pendingScore).toBe(8.1)

        expect(vm.teamDrafts.get('TEAM-A')).toEqual(expect.objectContaining({
            state: 'NOT_AFFECTED',
            justification: 'CODE_NOT_PRESENT',
            details: expect.stringContaining('Summary for lib-a.'),
        }))
        expect(vm.teamDrafts.get('TEAM-B')).toEqual(expect.objectContaining({
            state: 'EXPLOITABLE',
            details: expect.stringContaining('Summary for lib-b.'),
        }))
        expect(vm.teamDrafts.get('TEAM-A').details).not.toContain('Summary for lib-b.')

        const banner = wrapper.get('[data-testid="code-analysis-draft-banner"]').text()
        expect(banner).toContain('Applied 2 analyzer assessments to 2 teams (TEAM-A, TEAM-B).')
        expect(banner).toContain('worst result: EXPLOITABLE')
    })

    it('writes every team block and the global worst state in a single update', async () => {
        const wrapper = mountCard()
        await applyAll(wrapper)

        await wrapper.get('[data-testid="sticky-tab-apply-button"]').trigger('click')
        await flushPromises()
        await wrapper.findAll('button').find(button => button.text() === 'Submit')?.trigger('click')
        await flushPromises()

        expect(updateAssessment).toHaveBeenCalledTimes(1)
        const payload = vi.mocked(updateAssessment).mock.calls[0]?.[0] as any

        expect(payload.state).toBe('EXPLOITABLE')
        expect(payload.analysis_run_ids).toEqual(['run-a', 'run-b'])
        expect(payload.details).toMatch(/\[Team: General\] \[State: EXPLOITABLE\]/)
        expect(payload.details).toMatch(/\[Team: TEAM-A\] \[State: NOT_AFFECTED\]/)
        expect(payload.details).toMatch(/\[Team: TEAM-B\] \[State: EXPLOITABLE\]/)
        expect(payload.details).toContain('[Rescored: 8.1]')
        expect(payload.details).toContain('[Rescored Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H]')
        expect(payload.details).toContain('Summary for lib-a.')
        expect(payload.details).toContain('Summary for lib-b.')
    })

    it('reports analyzed components without a team mapping', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: JSON.parse(JSON.stringify(group)) },
            global: {
                provide: {
                    user: ref({ role: 'REVIEWER', username: 'tester' }),
                    teamMapping: ref({ 'lib-a': ['TEAM-A'] }),
                },
                stubs: { teleport: true },
            },
        })
        await applyAll(wrapper)

        const banner = wrapper.get('[data-testid="code-analysis-draft-banner"]').text()
        expect(banner).toContain('Applied 2 analyzer assessments to 1 team (TEAM-A).')
        expect(banner).toContain('No team is mapped for lib-b.')
        expect((wrapper.vm as any).state).toBe('EXPLOITABLE')
    })

    it('applies the configured rescore rules to a global not-affected state', async () => {
        const wrapper = mountCard(defaultRescoreRules as Record<string, any>)
        await applyAllNotAffected(wrapper)

        const vm = wrapper.vm as any
        expect(vm.state).toBe('NOT_AFFECTED')
        // The rule owns the vector: analyzer metrics never replace the base ones,
        // and the configured modifiers are added on top.
        expect(vm.pendingVector).toContain('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
        for (const metric of ['CR:L', 'IR:L', 'AR:L', 'MAC:H', 'MAV:P', 'MPR:H', 'MUI:R', 'MC:N', 'MI:N', 'MA:N']) {
            expect(vm.pendingVector).toContain(metric)
        }
        expect(vm.pendingScore).toBe(0)

        await wrapper.get('[data-testid="sticky-tab-apply-button"]').trigger('click')
        await flushPromises()
        await wrapper.findAll('button').find(button => button.text() === 'Submit')?.trigger('click')
        await flushPromises()

        const payload = vi.mocked(updateAssessment).mock.calls[0]?.[0] as any
        expect(payload.details).toContain('[Rescored: 0.0]')
        expect(payload.details).toContain(`[Rescored Vector: ${vm.pendingVector}]`)
    })

    it('keeps the analyzer rescore for states without a configured rule', async () => {
        const wrapper = mountCard(defaultRescoreRules as Record<string, any>)
        await applyAll(wrapper)

        const vm = wrapper.vm as any
        expect(vm.state).toBe('EXPLOITABLE')
        expect(vm.pendingVector).toBe('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H')
        expect(vm.pendingScore).toBe(8.1)
    })
})
