import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import AssessmentHistory from '../AssessmentHistory.vue'
import ClearAssessmentModal from '../ClearAssessmentModal.vue'
import { seenAnalysis } from '../../lib/assessmentSubmission'
import * as api from '../../lib/api'

vi.mock('../../lib/api', () => ({
    getAssessmentHistory: vi.fn(),
}))

const instance = (suffix: string, extra: Record<string, unknown> = {}) => ({
    project_name: 'App',
    project_version: suffix,
    project_uuid: `p-${suffix}`,
    component_name: 'lib',
    component_version: '1.0',
    component_uuid: 'c1',
    vulnerability_uuid: 'v1',
    finding_uuid: `f-${suffix}`,
    analysis_state: 'NOT_SET',
    is_suppressed: false,
    ...extra,
}) as any

const revision = (overrides: Record<string, unknown> = {}) => ({
    revision: 1,
    analysisState: 'NOT_AFFECTED',
    analysisDetails: 'First text',
    isSuppressed: false,
    origin: 'individual-assessment',
    author: 'alice',
    created_at: '2026-11-17T08:00:00+00:00',
    ...overrides,
})

describe('seenAnalysis', () => {
    it('sends what the open view showed for findings without a recorded server state', () => {
        const seen = seenAnalysis(
            [
                instance('1.0', { analysis_state: 'IN_TRIAGE', analysis_details: 'Shown text', is_suppressed: true }),
                instance('2.0', { analysis_details: 'Shown but reloaded' }),
                instance('3.0'), // a list row: its text is not loaded
            ],
            { 'f-2.0': { analysisState: 'NOT_AFFECTED', analysisDetails: 'From reload', dtvpRevision: 4 } },
        )

        expect(seen).toEqual({
            'f-1.0': { analysisState: 'IN_TRIAGE', analysisDetails: 'Shown text', isSuppressed: true },
            'f-2.0': { analysisState: 'NOT_AFFECTED', analysisDetails: 'From reload', dtvpRevision: 4 },
        })
    })

    it('includes an empty shown assessment, which is also something to compare against', () => {
        expect(seenAnalysis([instance('1.0', { analysis_details: '' })], {})).toEqual({
            'f-1.0': { analysisState: 'NOT_SET', analysisDetails: '', isSuppressed: false },
        })
    })
})

describe('AssessmentHistory', () => {
    beforeEach(() => {
        vi.clearAllMocks()
    })

    it('loads only when opened and merges a save that covered several findings', async () => {
        vi.mocked(api.getAssessmentHistory).mockImplementation(async (target: any) => target.project_uuid === 'p-1.0'
            ? [
                revision({ revision: 2, origin: 'import', author: null, analysisState: 'EXPLOITABLE', analysisDetails: 'From DT', created_at: '2026-11-17T09:00:00+00:00' }),
                revision(),
            ]
            : [revision()])
        const wrapper = mount(AssessmentHistory, { props: { instances: [instance('1.0'), instance('2.0')] } })
        expect(api.getAssessmentHistory).not.toHaveBeenCalled()

        await wrapper.get('[data-testid="assessment-history-toggle"]').trigger('click')
        await flushPromises()

        const entries = wrapper.findAll('[data-testid="assessment-history-entry"]')
        expect(entries).toHaveLength(2)
        expect(entries[0]!.text()).toContain('Changed in Dependency-Track')
        expect(entries[0]!.text()).toContain('EXPLOITABLE')
        expect(entries[0]!.text()).toContain('1.0 · lib@1.0')
        expect(entries[1]!.text()).toContain('Saved')
        expect(entries[1]!.text()).toContain('by alice')
        expect(entries[1]!.text()).toContain('all 2 findings')
        expect(entries[1]!.text()).not.toContain('First text')

        await entries[1]!.get('[data-testid="assessment-history-entry-toggle"]').trigger('click')
        expect(entries[1]!.text()).toContain('First text')
    })

    it('labels deletions, reloads when told to, and reports an empty history', async () => {
        vi.mocked(api.getAssessmentHistory).mockResolvedValue([])
        const wrapper = mount(AssessmentHistory, { props: { instances: [instance('1.0')], refreshKey: 0 } })
        await wrapper.get('[data-testid="assessment-history-toggle"]').trigger('click')
        await flushPromises()
        expect(wrapper.get('[data-testid="assessment-history-empty"]').text()).toContain('No assessment has been recorded')

        vi.mocked(api.getAssessmentHistory).mockResolvedValue([
            revision({ origin: 'assessment-deletion', analysisState: 'NOT_SET', analysisDetails: '', author: 'rita' }),
        ])
        await wrapper.setProps({ refreshKey: 1 })
        await flushPromises()

        const entry = wrapper.get('[data-testid="assessment-history-entry"]')
        expect(entry.text()).toContain('Cleared')
        expect(entry.text()).toContain('by rita')
        await entry.get('[data-testid="assessment-history-entry-toggle"]').trigger('click')
        expect(entry.text()).toContain('(No assessment text)')
    })

    it('limits how many findings it loads and says so; reports failures', async () => {
        vi.mocked(api.getAssessmentHistory).mockResolvedValue([])
        const many = Array.from({ length: 35 }, (_value, index) => instance(`1.${index}`))
        const wrapper = mount(AssessmentHistory, { props: { instances: many } })
        await wrapper.get('[data-testid="assessment-history-toggle"]').trigger('click')
        await flushPromises()
        expect(api.getAssessmentHistory).toHaveBeenCalledTimes(30)
        expect(wrapper.get('[data-testid="assessment-history-truncated"]').text()).toContain('first 30 of 35')

        vi.mocked(api.getAssessmentHistory).mockRejectedValue(new Error('offline'))
        const failing = mount(AssessmentHistory, { props: { instances: [instance('1.0')] } })
        await failing.get('[data-testid="assessment-history-toggle"]').trigger('click')
        await flushPromises()
        expect(failing.get('[role="alert"]').text()).toContain('offline')
    })
})

describe('ClearAssessmentModal', () => {
    const mountModal = (props: Record<string, unknown>) => mount(ClearAssessmentModal, {
        props: { show: false, team: 'Team A', assessedTeams: ['General', 'Team A'], isReviewer: false, findingCount: 2, versions: ['1.0', '2.0'], components: ['lib-a'], ...props } as any,
        global: { stubs: { teleport: true } },
    })

    it('lets an analyst clear only the open team assessment, saying for which findings and versions', async () => {
        const wrapper = mountModal({})
        await wrapper.setProps({ show: true })

        expect(wrapper.find('[data-testid="clear-scope"]').exists()).toBe(true)
        expect(wrapper.find('[data-testid="clear-all"]').exists()).toBe(false)
        expect(wrapper.text()).toContain('Only the Team A assessment')
        expect(wrapper.get('[data-testid="clear-applies-to"]').text())
            .toContain('all 2 findings of lib-a in versions 1.0, 2.0')
        expect(wrapper.text()).toContain('Dependency-Track is cleared as well')
        expect(wrapper.text()).toContain('What remains of the assessment goes to review')
        expect(wrapper.text()).toContain('Clear assessment')

        await wrapper.get('[data-testid="clear-confirm"]').trigger('click')
        expect(wrapper.emitted('confirm')).toEqual([['Team A']])
    })

    it('lets a reviewer clear the Global assessment or everything', async () => {
        const wrapper = mountModal({ team: '', isReviewer: true })
        await wrapper.setProps({ show: true })
        expect(wrapper.text()).toContain('Only the Global assessment')
        expect(wrapper.text()).toContain('The SSVC decision and the response stored with it are removed too')
        expect(wrapper.text()).not.toContain('goes to review')

        await wrapper.get('[data-testid="clear-all"]').setValue(true)
        await wrapper.get('[data-testid="clear-confirm"]').trigger('click')
        expect(wrapper.emitted('confirm')).toEqual([[null]])
    })

    it('offers nothing an analyst may not clear and shows server errors', async () => {
        const wrapper = mountModal({ team: '', error: 'There is no such assessment to clear' })
        await wrapper.setProps({ show: true })

        expect(wrapper.get('[data-testid="clear-nothing"]').text()).toContain('only reviewers can clear the Global assessment')
        expect(wrapper.get('[data-testid="clear-confirm"]').attributes('disabled')).toBeDefined()
        expect(wrapper.get('[role="alert"]').text()).toContain('no such assessment')
    })

    it('defaults to the whole assessment when the open team has none', async () => {
        const wrapper = mountModal({ team: 'Team Z', isReviewer: true })
        await wrapper.setProps({ show: true })
        expect(wrapper.find('[data-testid="clear-scope"]').exists()).toBe(false)
        await wrapper.get('[data-testid="clear-confirm"]').trigger('click')
        expect(wrapper.emitted('confirm')).toEqual([[null]])
    })
})
