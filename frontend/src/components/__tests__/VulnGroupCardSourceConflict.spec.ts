import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import VulnGroupCard from '../VulnGroupCard.vue'
import ConflictResolutionModal from '../ConflictResolutionModal.vue'
import { getGroupInconsistencyReasons } from '../../lib/assessment-helpers'
import { INCONSISTENCY_REASON_OPTIONS } from '../../lib/inconsistency'
import ssvcModel from '../../../../dtvp/resources/ssvc/deployer-1.0.0.json'

vi.mock('../../lib/api', () => ({
    getSsvcModels: vi.fn(() => Promise.resolve([ssvcModel])),
    getSsvcExploitation: vi.fn(() => Promise.resolve({ enabled: true, sources: [], suggestion: null, auto_fill: false, retry_after: 0 })),
    updateAssessment: vi.fn(),
    getDependencyChains: vi.fn().mockResolvedValue({ paths: [], total: 0, limit: 10, offset: 0 }),
    getAssessmentDetails: vi.fn(),
    getKnownUsers: vi.fn(() => Promise.resolve([])),
    resolveAssessmentConflicts: vi.fn(),
}))

vi.mock('../DependencyChainViewer.vue', () => ({
    default: { template: '<div />', props: ['projectUuid', 'componentUuid', 'projectName'] },
}))

import { getAssessmentDetails, resolveAssessmentConflicts } from '../../lib/api'

const component = {
    project_name: 'App1',
    project_version: '1.0',
    project_uuid: 'p1',
    component_name: 'lib',
    component_version: '1.0',
    component_uuid: 'c1',
    vulnerability_uuid: 'v1',
    finding_uuid: 'f1',
    analysis_state: 'NOT_AFFECTED',
    analysis_details: 'Mine',
    is_suppressed: false,
    analysis_comments: [],
    tags: ['Security'],
    is_direct_dependency: false,
}

const group = () => ({
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
        components: [{ ...component }],
    }],
})

const detail = (analysis: Record<string, unknown>) => [{
    finding_uuid: 'f1',
    project_uuid: 'p1',
    component_uuid: 'c1',
    vulnerability_uuid: 'v1',
    analysis,
    error: null,
}]

const diverged = {
    analysisState: 'NOT_AFFECTED',
    analysisDetails: 'Mine',
    isSuppressed: false,
    dtvpRevision: 1,
    dtvpSyncStatus: 'diverged',
    dtvpRemote: { analysisState: 'EXPLOITABLE', analysisDetails: 'Theirs', isSuppressed: false },
}

const mountExpanded = async () => {
    const wrapper = mount(VulnGroupCard, {
        props: { group: group() as any },
        global: { provide: { user: { value: { username: 'tester' } } }, stubs: { teleport: true } },
    })
    await wrapper.find('.cursor-pointer').trigger('click')
    await flushPromises()
    return wrapper
}

describe('conflict between DTVP and Dependency-Track', () => {
    beforeEach(() => {
        vi.clearAllMocks()
    })

    it('counts as an inconsistency with a readable label', () => {
        const conflicted = group() as any
        conflicted.affected_versions[0].components[0].sync_status = 'diverged'
        expect(getGroupInconsistencyReasons(conflicted)).toContain('SOURCE_CONFLICT')
        expect(getGroupInconsistencyReasons(group() as any)).not.toContain('SOURCE_CONFLICT')
        expect(INCONSISTENCY_REASON_OPTIONS.find(option => option.value === 'SOURCE_CONFLICT')?.label)
            .toBe('Conflict with Dependency-Track')
    })

    it('shows both versions and takes the Dependency-Track one on request', async () => {
        vi.mocked(getAssessmentDetails)
            .mockResolvedValueOnce(detail(diverged))
            .mockResolvedValue(detail({ analysisState: 'EXPLOITABLE', analysisDetails: 'Theirs', isSuppressed: false, dtvpRevision: 2, dtvpSyncStatus: 'synced' }))
        vi.mocked(resolveAssessmentConflicts).mockResolvedValue([])
        const wrapper = await mountExpanded()

        const banner = wrapper.get('[data-testid="assessment-source-conflict"]')
        expect(banner.text()).toContain('Changed here and in Dependency-Track')
        expect(wrapper.find('[data-testid="assessment-persistence-status"]').exists()).toBe(false)
        await banner.trigger('click')

        const modal = wrapper.findAllComponents(ConflictResolutionModal).find(m => m.props('title') === 'Changed here and in Dependency-Track')!
        expect(modal.props('show')).toBe(true)
        expect(modal.text()).toContain('Dependency-Track')
        expect(modal.text()).toContain('Theirs')
        expect(modal.text()).toContain('DTVP (not exported)')
        expect(modal.text()).toContain('Mine')
        expect(modal.text()).toContain('App1 1.0 - lib')

        await modal.get('[data-testid="conflict-use-server"]').trigger('click')
        await flushPromises()

        expect(resolveAssessmentConflicts).toHaveBeenCalledWith(
            [expect.objectContaining({ finding_uuid: 'f1', project_uuid: 'p1', component_uuid: 'c1', vulnerability_uuid: 'v1' })],
            'remote',
        )
        expect(wrapper.find('[data-testid="assessment-source-conflict"]').exists()).toBe(false)
        expect(modal.props('show')).toBe(false)
        // The list is told the way a save tells it. `update` would re-run the
        // whole project query and rebuild the open detail view.
        expect(wrapper.emitted('update')).toBeFalsy()
        expect(wrapper.emitted('update:assessment')).toEqual([[{
            dtvp_results: [expect.objectContaining({
                uuid: 'f1',
                new_state: 'EXPLOITABLE',
                new_details: 'Theirs',
                sync_status: 'synced',
                revision: 2,
                source_assessment: null,
            })],
        }]])
    })

    it('shows the conflict as soon as the vulnerability is opened', async () => {
        // No reload has happened: the state arrives with the vulnerability detail.
        vi.mocked(getAssessmentDetails).mockResolvedValue([])
        const opened = group() as any
        Object.assign(opened.affected_versions[0].components[0], {
            sync_status: 'diverged',
            source_assessment: diverged.dtvpRemote,
        })
        const wrapper = mount(VulnGroupCard, {
            props: { group: opened },
            global: { provide: { user: { value: { username: 'tester' } } }, stubs: { teleport: true } },
        })
        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        await wrapper.get('[data-testid="assessment-source-conflict"]').trigger('click')
        const modal = wrapper.findAllComponents(ConflictResolutionModal).find(m => m.props('title') === 'Changed here and in Dependency-Track')!
        expect(modal.text()).toContain('Theirs')
        expect(modal.text()).toContain('Mine')
    })

    it('keeps the DTVP version on request', async () => {
        vi.mocked(getAssessmentDetails)
            .mockResolvedValueOnce(detail(diverged))
            .mockResolvedValue(detail({ ...diverged, dtvpSyncStatus: 'pending', dtvpRemote: undefined }))
        vi.mocked(resolveAssessmentConflicts).mockResolvedValue([])
        const wrapper = await mountExpanded()
        await wrapper.get('[data-testid="assessment-source-conflict"]').trigger('click')
        const modal = wrapper.findAllComponents(ConflictResolutionModal).find(m => m.props('title') === 'Changed here and in Dependency-Track')!

        await modal.get('[data-testid="conflict-overwrite"]').trigger('click')
        await flushPromises()

        expect(resolveAssessmentConflicts).toHaveBeenCalledWith(expect.any(Array), 'local')
        expect(wrapper.get('[data-testid="assessment-persistence-status"]').text())
            .toContain('Saved locally — syncing to Dependency-Track')
    })

    it('keeps the dialog open and explains a failed resolution', async () => {
        vi.mocked(getAssessmentDetails).mockResolvedValue(detail(diverged))
        vi.mocked(resolveAssessmentConflicts).mockRejectedValue({ response: { data: { detail: 'No open conflict for: p1:c1:v1' } } })
        const wrapper = await mountExpanded()
        await wrapper.get('[data-testid="assessment-source-conflict"]').trigger('click')
        const modal = wrapper.findAllComponents(ConflictResolutionModal).find(m => m.props('title') === 'Changed here and in Dependency-Track')!

        await modal.get('[data-testid="conflict-use-server"]').trigger('click')
        await flushPromises()

        expect(modal.props('show')).toBe(true)
        expect(modal.text()).toContain('No open conflict for: p1:c1:v1')
        expect(wrapper.emitted('update')).toBeFalsy()
    })

    it('keeps the original wording for save conflicts', () => {
        const wrapper = mount(ConflictResolutionModal, {
            props: { show: true, conflictData: [] },
            global: { stubs: { teleport: true } },
        })
        expect(wrapper.text()).toContain('Conflict Detected')
        expect(wrapper.text()).toContain('Force Overwrite')
        expect(wrapper.text()).toContain('Discard My Changes (Use Server)')
    })
})
