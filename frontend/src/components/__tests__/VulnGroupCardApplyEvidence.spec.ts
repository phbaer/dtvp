import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref } from 'vue'
import VulnGroupCard from '../VulnGroupCard.vue'
import CodeAnalysisPanel from '../CodeAnalysisPanel.vue'

vi.mock('../../lib/api', async () => {
    const { renderAssessmentFields } = await import('../../lib/__tests__/assessmentFieldsText')
    return {
        updateAssessment: vi.fn((payload: any) => Promise.resolve(payload.instances.map((instance: any) => ({
            status: 'success',
            uuid: instance.finding_uuid,
            new_state: payload.state,
            new_details: renderAssessmentFields(payload.fields),
        })))),
        getAssessmentDetails: vi.fn(() => Promise.resolve([])),
        getKnownUsers: vi.fn(() => Promise.resolve([])),
        codeAnalysisBenchmarkResult: vi.fn(),
        codeAnalysisGetPrompts: vi.fn(() => Promise.resolve({ bundles: [] })),
        codeAnalysisGetResult: vi.fn(),
        codeAnalysisListVulnerabilityResults: vi.fn(() => Promise.resolve([])),
        listCodeEvidence: vi.fn(() => Promise.resolve({ items: [], withdrawn_count: 0 })),
        withdrawCodeEvidence: vi.fn(),
    }
})

import { updateAssessment } from '../../lib/api'
import { renderAssessmentFields } from '../../lib/__tests__/assessmentFieldsText'

const RATIONALE = 'The affected parser is absent from the tested application path. No remote exposure was established.'

describe('VulnGroupCard applies agent code evidence', () => {
    const group = {
        id: 'CVE-2026-4242',
        title: 'One component vulnerability',
        description: 'Affects one owned component.',
        severity: 'HIGH',
        cvss: 8.1,
        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
        tags: ['TEAM-A'],
        affected_versions: [{
            project_name: 'App1',
            project_version: '1.0',
            project_uuid: 'p1',
            components: [{
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
            }],
        }],
    }

    const mountCard = () => mount(VulnGroupCard, {
        props: { group: JSON.parse(JSON.stringify(group)) },
        global: {
            provide: {
                user: ref({ role: 'REVIEWER', username: 'rita' }),
                teamMapping: ref({ 'lib-a': ['TEAM-A'] }),
            },
            stubs: { teleport: true },
        },
    })

    const applyEvidence = async (wrapper: ReturnType<typeof mountCard>, payload: Record<string, any>) => {
        if (!wrapper.findComponent(CodeAnalysisPanel).exists()) {
            await wrapper.find('.cursor-pointer').trigger('click')
            await flushPromises()
        }
        wrapper.getComponent(CodeAnalysisPanel).vm.$emit('apply-evidence', { title: 'Parser evidence', ...payload })
        await flushPromises()
    }

    const save = async (wrapper: ReturnType<typeof mountCard>) => {
        await wrapper.get('[data-testid="assessment-submit-button"]').trigger('click')
        await flushPromises()
        await wrapper.findAll('button').find(button => button.text() === 'Submit')?.trigger('click')
        await flushPromises()
    }

    beforeEach(() => {
        vi.clearAllMocks()
    })

    it('tells the evidence panel which findings are reported now', async () => {
        const wrapper = mountCard()
        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()
        expect(wrapper.getComponent(CodeAnalysisPanel).props('reportedFindingUuids')).toEqual(['f1'])
    })

    it('appends standalone rationale and keeps the state unless a suggestion was chosen', async () => {
        const wrapper = mountCard()
        await applyEvidence(wrapper, { evidenceId: 'ev_1', summary: RATIONALE })

        const vm = wrapper.vm as any
        expect(vm.details).toBe(RATIONALE)
        expect(vm.state).toBe('NOT_SET')
        expect(vm.codeEvidenceIds).toEqual(['ev_1'])
        expect(vm.activeDetailTab).toBe('review')
        expect(wrapper.get('[data-testid="code-analysis-draft-banner"]').text())
            .toContain('Supporting evidence selected. Review the assessment rationale before saving.')

        vm.details = 'Our own reasoning.'
        await applyEvidence(wrapper, {
            evidenceId: 'ev_2',
            summary: 'A second consumer uses only the local trust store.',
            state: 'NOT_AFFECTED',
            justification: 'CODE_NOT_REACHABLE',
        })
        expect(vm.details).toBe('Our own reasoning.\n\nA second consumer uses only the local trust store.')
        expect(vm.state).toBe('NOT_AFFECTED')
        expect(vm.justification).toBe('CODE_NOT_REACHABLE')
        expect(vm.codeEvidenceIds).toEqual(['ev_1', 'ev_2'])
    })

    it('sends explicit team evidence selections with the save and resets them after it', async () => {
        const wrapper = mountCard()
        await applyEvidence(wrapper, { evidenceId: 'ev_1', summary: RATIONALE })
        const vm = wrapper.vm as any
        vm.state = 'IN_TRIAGE'
        await flushPromises()

        await save(wrapper)

        expect(updateAssessment).toHaveBeenCalledTimes(1)
        const payload = vi.mocked(updateAssessment).mock.calls[0]?.[0] as any
        expect(payload.code_evidence_by_team.General).toEqual(['ev_1'])
        expect(renderAssessmentFields(payload.fields)).toContain(RATIONALE)
        expect(vm.codeEvidenceIds).toEqual([])
    })

    it('keeps selected evidence when the rationale is edited', async () => {
        const wrapper = mountCard()
        await applyEvidence(wrapper, { evidenceId: 'ev_1', summary: RATIONALE })
        await applyEvidence(wrapper, {
            evidenceId: 'ev_2',
            summary: 'A second consumer uses only the local trust store.',
        })
        const vm = wrapper.vm as any
        // An analyzer result (or the analyst) replaced the text; only ev_2 stays cited.
        vm.details = 'Analyzer says not reachable.\n\nCode evidence ev_2 from bot (alice, 2026-07-07): Second'
        vm.state = 'IN_TRIAGE'
        await flushPromises()

        await save(wrapper)

        const payload = vi.mocked(updateAssessment).mock.calls[0]?.[0] as any
        expect(payload.code_evidence_by_team.General).toEqual(['ev_1', 'ev_2'])
    })

    it('removes the explicit selection without changing rationale text', async () => {
        const wrapper = mountCard()
        await applyEvidence(wrapper, { evidenceId:'ev_1', summary:RATIONALE })
        const vm = wrapper.vm as any
        vm.state = 'IN_TRIAGE'
        await flushPromises()
        await wrapper.get('button[aria-label="Remove supporting evidence Parser evidence"]').trigger('click')
        expect(vm.details).toBe(RATIONALE)
        expect(vm.codeEvidenceIds).toEqual([])
        await save(wrapper)
        expect((vi.mocked(updateAssessment).mock.calls[0]?.[0] as any).code_evidence_by_team.General).toEqual([])
    })

    it('opens supporting evidence inside DTVP without inserting a reference in the rationale', async () => {
        const wrapper = mountCard()
        await applyEvidence(wrapper, { evidenceId:'ev_1', summary:RATIONALE })
        await wrapper.get('[data-testid="assessment-supporting-evidence"] button.text-cyan-300').trigger('click')
        await flushPromises()
        const vm = wrapper.vm as any
        expect(vm.requestedEvidenceId).toBe('ev_1')
        expect(vm.activeDetailTab).toBe('analysis')
        expect(vm.details).toBe(RATIONALE)
    })

    it('keeps team and global selections separate', async () => {
        const wrapper = mountCard()
        const vm = wrapper.vm as any
        vm.selectedTeam = 'TEAM-A'
        await flushPromises()
        await applyEvidence(wrapper, { evidenceId:'ev_team', summary:RATIONALE })
        expect(vm.codeEvidenceIds).toEqual(['ev_team'])
        vm.selectedTeam = ''
        await flushPromises()
        expect(vm.codeEvidenceIds).toEqual([])
        expect(vm.codeEvidenceByTeam['TEAM-A']).toEqual(['ev_team'])
    })

    it('drops withdrawn evidence after a rejected save and keeps the draft', async () => {
        const wrapper = mountCard()
        await applyEvidence(wrapper, { evidenceId: 'ev_1', summary: RATIONALE })
        const vm = wrapper.vm as any
        vm.details = `Our own reasoning.\n\n${RATIONALE}`
        vm.state = 'IN_TRIAGE'
        await flushPromises()
        vi.mocked(updateAssessment).mockRejectedValueOnce({
            response: { status: 422, data: { detail: 'Code evidence ev_1 was withdrawn and cannot be used' } },
        })

        await save(wrapper)

        expect(wrapper.text()).toContain('Code evidence removed')
        expect(wrapper.text()).toContain('Code evidence ev_1 was withdrawn and cannot be used')
        expect(vm.codeEvidenceIds).toEqual([])
        expect(vm.details).toContain('Our own reasoning.')
        expect(vm.state).toBe('IN_TRIAGE')
        await wrapper.findAll('button').find(button => button.text() === 'Close')?.trigger('click')
        await flushPromises()

        await save(wrapper)

        expect(updateAssessment).toHaveBeenCalledTimes(2)
        const retry = vi.mocked(updateAssessment).mock.calls[1]?.[0] as any
        expect(retry.code_evidence_by_team.General).toEqual([])
    })
})
