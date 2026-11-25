import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import VulnGroupCard from '../VulnGroupCard.vue'
import ssvcModel from '../../../../dtvp/resources/ssvc/deployer-1.0.0.json'

vi.mock('../../lib/api', () => ({
    getSsvcModels: vi.fn(() => Promise.resolve([ssvcModel])),
    getSsvcExploitation: vi.fn(() => Promise.resolve({ enabled: true, sources: [], suggestion: null, auto_fill: false, retry_after: 0 })),
    updateAssessment: vi.fn(),
    getDependencyChains: vi.fn().mockResolvedValue({ paths: [], total: 0, limit: 10, offset: 0 }),
    getAssessmentDetails: vi.fn(),
    getKnownUsers: vi.fn(() => Promise.resolve([])),
}))

vi.mock('../DependencyChainViewer.vue', () => ({
    default: { template: '<div />', props: ['projectUuid', 'componentUuid', 'projectName'] },
}))

import { getAssessmentDetails } from '../../lib/api'

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

const theirs = { analysisState: 'EXPLOITABLE', analysisDetails: 'Theirs', isSuppressed: false }
const analysis = (overrides: Record<string, unknown>) => ({
    analysisState: 'NOT_AFFECTED',
    analysisDetails: 'Mine',
    isSuppressed: false,
    dtvpRevision: 1,
    ...overrides,
})

const mountExpanded = async () => {
    const wrapper = mount(VulnGroupCard, {
        props: { group: group() as any },
        global: { provide: { user: { value: { username: 'tester' } } }, stubs: { teleport: true } },
    })
    await wrapper.find('.cursor-pointer').trigger('click')
    await flushPromises()
    return wrapper
}

describe('Dependency-Track holding a different value than River', () => {
    beforeEach(() => {
        vi.clearAllMocks()
    })

    it('says that Dependency-Track is out of date while the export waits, without asking for a choice', async () => {
        vi.mocked(getAssessmentDetails).mockResolvedValue(detail(analysis({ dtvpSyncStatus: 'pending', dtvpRemote: theirs })))
        const wrapper = await mountExpanded()

        const status = wrapper.get('[data-testid="assessment-persistence-status"]')
        expect(status.text()).toBe('Saved locally — Dependency-Track is out of date')
        expect(status.attributes('title')).toContain('The next export overwrites it')
        expect(wrapper.find('[data-testid="assessment-source-conflict"]').exists()).toBe(false)
        expect(wrapper.find('[data-testid="conflict-use-server"]').exists()).toBe(false)
    })

    it('keeps the error of a failing export next to the note', async () => {
        vi.mocked(getAssessmentDetails).mockResolvedValue(detail(analysis({
            dtvpSyncStatus: 'error', dtvpSyncError: 'Dependency-Track did not keep the exported assessment', dtvpRemote: theirs,
        })))
        const wrapper = await mountExpanded()

        const status = wrapper.get('[data-testid="assessment-persistence-status"]')
        expect(status.text()).toBe('Saved locally — Dependency-Track is out of date, export is retrying')
        expect(status.attributes('title')).toBe('Dependency-Track did not keep the exported assessment')
    })

    it('shows the plain syncing note when Dependency-Track is not known to differ, and nothing once synchronized', async () => {
        vi.mocked(getAssessmentDetails).mockResolvedValue(detail(analysis({ dtvpSyncStatus: 'pending' })))
        let wrapper = await mountExpanded()
        expect(wrapper.get('[data-testid="assessment-persistence-status"]').text()).toBe('Saved locally — syncing to Dependency-Track')
        wrapper.unmount()

        vi.mocked(getAssessmentDetails).mockResolvedValue(detail(analysis({ dtvpSyncStatus: 'synced' })))
        wrapper = await mountExpanded()
        expect(wrapper.find('[data-testid="assessment-persistence-status"]').exists()).toBe(false)
    })
})
