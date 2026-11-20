import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { ref } from 'vue'
import VulnGroupCard from '../VulnGroupCard.vue'
import VulnGroupAssessmentDetails from '../VulnGroupAssessmentDetails.vue'
import CustomSelect from '../CustomSelect.vue'
import ssvcModel from '../../../../dtvp/resources/ssvc/deployer-1.0.0.json'

vi.mock('../../lib/api', async () => {
    // The server renders the stored text from the fields a save sends.
    const { renderAssessmentFields } = await import('../../lib/__tests__/assessmentFieldsText')
    return {
        getSsvcModels: vi.fn(() => Promise.resolve([ssvcModel])),
        getSsvcExploitation: vi.fn(() => Promise.resolve({ enabled: true, sources: [], suggestion: null, auto_fill: false, retry_after: 0 })),
        updateAssessment: vi.fn((payload: any) => Promise.resolve(payload.instances.map((instance: any) => ({
            status: 'success',
            uuid: instance.finding_uuid,
            new_state: payload.state,
            new_details: renderAssessmentFields(payload.fields),
            queued: true,
            sync_status: 'pending',
            update_id: `update-${instance.finding_uuid}`,
            revision: 1,
        })))),
        getDependencyChains: vi.fn().mockResolvedValue({ paths: [], total: 0, limit: 10, offset: 0 }),
        getAssessmentDetails: vi.fn(() => Promise.resolve([])),
        getKnownUsers: vi.fn(() => Promise.resolve([])),
    }
})

vi.mock('../DependencyChainViewer.vue', () => ({
    default: { template: '<div />', props: ['projectUuid', 'componentUuid', 'projectName'] },
}))

import { updateAssessment } from '../../lib/api'

const GENERAL = '--- [Team: General] [State: EXPLOITABLE] [Assessed By: rita] [Justification: NOT_SET] ---\nReachable.'
const SECURITY = '--- [Team: Security] [State: EXPLOITABLE] [Assessed By: bob] [Justification: NOT_SET] ---\nConfirmed.'

const group = (details: string) => ({
    id: 'CVE-2023-1234',
    title: 'Test Vulnerability',
    description: 'A bad vulnerability',
    severity: 'HIGH',
    cvss: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    tags: ['Security'],
    aliases: [],
    affected_versions: [{
        project_name: 'App1',
        project_version: '1.0',
        project_uuid: 'p1',
        components: [{
            project_name: 'App1',
            project_version: '1.0',
            project_uuid: 'p1',
            component_name: 'lib',
            component_version: '1.0',
            component_uuid: 'c1',
            vulnerability_uuid: 'v1',
            finding_uuid: 'f1',
            analysis_state: details ? 'EXPLOITABLE' : 'NOT_SET',
            analysis_details: details,
            is_suppressed: false,
            analysis_comments: [],
            tags: ['Security'],
            is_direct_dependency: false,
        }],
    }],
})

const mountCard = async (details: string, role = 'REVIEWER') => {
    const wrapper = mount(VulnGroupCard, {
        props: { group: group(details) as any },
        global: { provide: { user: ref({ role, username: 'rita' }) }, stubs: { teleport: true } },
    })
    await wrapper.find('.cursor-pointer').trigger('click')
    const reviewTab = wrapper.findAll('[role="tab"]').find(tab => tab.text().includes('Assessment'))
    await reviewTab?.trigger('click')
    await flushPromises()
    return wrapper
}

const responseSelect = (wrapper: Awaited<ReturnType<typeof mountCard>>) =>
    wrapper.find('[data-testid="analysis-response-field"]').findComponent(CustomSelect)

const save = async (wrapper: Awaited<ReturnType<typeof mountCard>>) => {
    const saving = (wrapper.vm as any).handleUpdate(false)
    await flushPromises()
    ;(wrapper.vm as any).handleReviewConfirm()
    await saving
    await flushPromises()
    return vi.mocked(updateAssessment).mock.calls.at(-1)?.[0] as any
}

describe('the response of the Global assessment in the form', () => {
    beforeEach(() => {
        vi.clearAllMocks()
    })

    it('offers the response on the Global form next to the justification, filled from the assessment', async () => {
        const wrapper = await mountCard(`[Response: UPDATE]\n\n${GENERAL}\n\n${SECURITY}`)
        const vm = wrapper.vm as any
        vm.selectedTeam = ''
        await wrapper.vm.$nextTick()

        const select = responseSelect(wrapper)
        expect(select.exists()).toBe(true)
        expect(select.props('modelValue')).toBe('UPDATE')
        expect(select.props('options').map((option: any) => option.label)).toEqual([
            'Not set', 'Update', 'Rollback', 'Workaround available', 'Will not fix', 'Can not fix',
        ])
        expect(wrapper.get('label[for="response-select"]').text()).toBe('Response')
        // Loaded, not edited.
        expect(vm.formTouched).toBe(false)
        // The tag is the field: it is in no rationale the form shows.
        expect(vm.details).toBe('Reachable.')
        wrapper.unmount()
    })

    it('does not offer it for a team assessment or to an analyst', async () => {
        const wrapper = await mountCard(`[Response: UPDATE]\n\n${GENERAL}\n\n${SECURITY}`)
        ;(wrapper.vm as any).selectedTeam = 'Security'
        await wrapper.vm.$nextTick()
        expect(wrapper.find('[data-testid="analysis-response-field"]').exists()).toBe(false)
        expect((wrapper.vm as any).details).toBe('Confirmed.')
        wrapper.unmount()

        const analyst = await mountCard(`[Response: UPDATE]\n\n${GENERAL}\n\n${SECURITY}`, 'ANALYST')
        for (const team of ['', 'Security']) {
            ;(analyst.vm as any).selectedTeam = team
            await analyst.vm.$nextTick()
            expect(analyst.find('[data-testid="analysis-response-field"]').exists()).toBe(false)
        }
        analyst.unmount()
    })

    it('marks the form as touched when it changes and sends it in the fields', async () => {
        const wrapper = await mountCard(`${GENERAL}\n\n${SECURITY}`)
        const vm = wrapper.vm as any
        vm.selectedTeam = ''
        await wrapper.vm.$nextTick()
        expect(responseSelect(wrapper).props('modelValue')).toBe('NOT_SET')
        expect(vm.formTouched).toBe(false)

        responseSelect(wrapper).vm.$emit('update:modelValue', 'WORKAROUND_AVAILABLE')
        await wrapper.vm.$nextTick()
        expect(vm.formTouched).toBe(true)
        expect(wrapper.get('[data-testid="assessment-submit-button"]').attributes('disabled')).toBeUndefined()

        const sent = await save(wrapper)
        expect(sent.fields.response).toBe('WORKAROUND_AVAILABLE')
        expect(sent.team).toBeUndefined()
        expect(sent.fields.teams.map((team: any) => team.team)).toEqual(['General', 'Security'])
        // Saved: the form shows the stored value and is clean again.
        expect(vm.response).toBe('WORKAROUND_AVAILABLE')
        expect(vm.responseTouched).toBe(false)
        expect(vm.formTouched).toBe(false)
        wrapper.unmount()
    })

    it('removes the response when it is set back to not set', async () => {
        const wrapper = await mountCard(`[Response: UPDATE]\n\n${GENERAL}`)
        ;(wrapper.vm as any).selectedTeam = ''
        await wrapper.vm.$nextTick()
        responseSelect(wrapper).vm.$emit('update:modelValue', 'NOT_SET')
        await wrapper.vm.$nextTick()

        const sent = await save(wrapper)
        expect(sent.fields).toHaveProperty('response', null)
        expect((wrapper.vm as any).response).toBe('NOT_SET')
        wrapper.unmount()
    })

    it('resets an unsaved choice when the draft is discarded or the assessment is loaded again', async () => {
        const wrapper = await mountCard(`[Response: UPDATE]\n\n${GENERAL}`)
        const vm = wrapper.vm as any
        vm.selectedTeam = ''
        await wrapper.vm.$nextTick()
        responseSelect(wrapper).vm.$emit('update:modelValue', 'ROLLBACK')
        await wrapper.vm.$nextTick()
        expect(vm.response).toBe('ROLLBACK')
        expect(vm.hasUnsavedDraft).toBe(true)

        vm.discardUnsavedDraft()
        await wrapper.vm.$nextTick()
        expect(vm.response).toBe('UPDATE')
        expect(vm.formTouched).toBe(false)
        expect(vm.hasUnsavedDraft).toBe(false)

        // Loading the group again fills it with what is stored now.
        await wrapper.setProps({ group: group(`[Response: CAN_NOT_FIX]\n\n${GENERAL}`) as any })
        await flushPromises()
        expect(vm.response).toBe('CAN_NOT_FIX')
        await wrapper.setProps({ group: group(GENERAL) as any })
        await flushPromises()
        expect(vm.response).toBe('NOT_SET')
        wrapper.unmount()
    })

    it('keeps an unsaved choice across team tabs and does not send it with a team save', async () => {
        const wrapper = await mountCard(`[Response: UPDATE]\n\n${GENERAL}\n\n${SECURITY}`)
        const vm = wrapper.vm as any
        vm.selectedTeam = ''
        await wrapper.vm.$nextTick()
        responseSelect(wrapper).vm.$emit('update:modelValue', 'ROLLBACK')
        await wrapper.vm.$nextTick()

        vm.selectedTeam = 'Security'
        await wrapper.vm.$nextTick()
        expect(wrapper.get('[data-testid="unsaved-response-hint"]').text()).toContain('return to the global assessment')
        const sent = await save(wrapper)
        expect(sent.team).toBe('Security')
        expect(sent.fields).not.toHaveProperty('response')
        expect(vm.response).toBe('ROLLBACK')
        expect(vm.responseTouched).toBe(true)

        vm.selectedTeam = ''
        await wrapper.vm.$nextTick()
        expect(responseSelect(wrapper).props('modelValue')).toBe('ROLLBACK')
        expect((await save(wrapper)).fields.response).toBe('ROLLBACK')
        expect(vm.responseTouched).toBe(false)
        wrapper.unmount()
    })

    it('is on the form in the assessment workspace without opening a tab', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: group(`[Response: UPDATE]\n\n${GENERAL}\n\n${SECURITY}`) as any, inModal: true, workspace: true, workspaceAvailable: true },
            global: { provide: { user: ref({ role: 'REVIEWER', username: 'rita' }) }, stubs: { teleport: true } },
        })
        await flushPromises()

        expect((wrapper.vm as any).activeDetailTab).toBe('overview')
        expect((wrapper.vm as any).selectedTeam).toBe('')
        const pane = wrapper.get('[data-testid="workspace-assessment-pane"]')
        expect(pane.find('[data-testid="analysis-response-field"]').exists()).toBe(true)
        expect(wrapper.get('#vuln-CVE-2023-1234-detail-panel-review').attributes('style') || '').not.toContain('display: none')
        expect(responseSelect(wrapper).props('modelValue')).toBe('UPDATE')
        wrapper.unmount()
    })
})

describe('the response where the Global assessment is displayed', () => {
    const mountDetails = (details: string) => mount(VulnGroupAssessmentDetails, {
        props: {
            assessment: { state: 'EXPLOITABLE', details, comments: [], instances: [] },
            showDependencies: false,
        },
    })

    it('shows it with the Global assessment, read-only', () => {
        const wrapper = mountDetails(`[Response: WILL_NOT_FIX]\n\n${GENERAL}\n\n${SECURITY}`)
        const shown = wrapper.findAll('[data-testid="assessment-response"]')
        expect(shown).toHaveLength(1)
        expect(shown[0]?.text()).toBe('· Response: Will not fix')
        expect(wrapper.find('select').exists()).toBe(false)
        // Not part of any rationale.
        expect(wrapper.text()).not.toContain('[Response')
    })

    it('shows it on its own line when there is no Global assessment, and nothing without a response', () => {
        const teamOnly = mountDetails(`[Response: UPDATE]\n\n${SECURITY}`)
        expect(teamOnly.get('[data-testid="assessment-response"]').text()).toBe('Response: Update')
        expect(mountDetails(`${GENERAL}\n\n${SECURITY}`).find('[data-testid="assessment-response"]').exists()).toBe(false)
    })
})
