import { describe, it, expect, vi, beforeEach } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { getGroupedVulns, getStatistics } from '../../lib/api'
import { useRoute } from 'vue-router'
import { defaultAnalysisFilters, defaultLifecycleFilters, defaultStatusFilters, mountProjectView, updateProjectViewState } from './projectViewTestUtils'

vi.mock('../../lib/api', () => ({
    getGroupedVulns: vi.fn(),
    getStatistics: vi.fn(() => Promise.resolve({
        severity_counts: {},
        state_counts: {},
        total_unique: 0,
        total_findings: 0,
        affected_projects_count: 0,
        version_counts: {},
        version_severity_counts: {},
        major_version_severity_counts: {},
        major_version_counts: {},
        major_version_details: {},
    })),
    getCacheStatus: vi.fn(() => Promise.resolve({ fully_cached: false, last_refreshed_at: null, projects: 0, active_projects: 0, cached_findings: 0, cached_boms: 0, cached_analyses: 0, pending_updates: 0 })),
    getTeamMapping: vi.fn(() => Promise.resolve({})),
    getRescoreRules: vi.fn(() => Promise.resolve({ transitions: [] })),
    getTMRescoreProposals: vi.fn(() => Promise.resolve({ proposals: {} }))
}))

const replaceSpy = vi.fn(() => Promise.resolve())
vi.mock('vue-router', () => ({
    useRoute: vi.fn(() => ({ params: {}, query: {} })),
    useRouter: vi.fn(() => ({ replace: replaceSpy })),
    RouterLink: { template: '<a><slot /></a>' }
}))

// Mock child component
vi.mock('../../components/VulnGroupCard.vue', () => ({
    default: {
        template: '<div class="vuln-group-card" data-testid="group-card"></div>',
        props: ['group']
    }
}))

describe('ProjectView.vue', () => {
    const writeTextSpy = vi.fn(() => Promise.resolve())

    beforeEach(() => {
        vi.clearAllMocks()
        Object.defineProperty(navigator, 'clipboard', {
            value: { writeText: writeTextSpy },
            writable: true,
            configurable: true
        })
        vi.mocked(useRoute).mockReturnValue({
            params: { name: 'TestProject' }, query: {}
        } as any)
    })

    it('fetches vulnerabilities on mount', async () => {
        const mockGroups = [{ id: '1', title: 'Vuln 1' }]
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject' })

        await updateProjectViewState(wrapper, { statusFilters: defaultStatusFilters })

        expect(getGroupedVulns).toHaveBeenCalledWith('TestProject', undefined, expect.any(Function))
        // Child component should be rendered
        expect(wrapper.findAll('.vuln-group-card')).toHaveLength(1)
    })

    it('handles error state', async () => {
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => { })
        vi.mocked(getGroupedVulns).mockRejectedValue(new Error('Failed'))

        const wrapper = await mountProjectView({ routeName: 'TestProject' })

        expect(wrapper.text()).toContain('Failed to load vulnerabilities')
        consoleSpy.mockRestore()
    })

    it('handles empty state', async () => {
        vi.mocked(getGroupedVulns).mockResolvedValue([])

        const wrapper = await mountProjectView({ routeName: 'TestProject' })

        expect(wrapper.text()).toContain('No vulnerabilities found')
    })

    it('filters by direct dependency and versions', async () => {
        const mockGroups = [
            {
                id: '1',
                title: 'Direct vuln',
                affected_versions: [
                    { project_version: '1.0', components: [{ is_direct_dependency: true }] }
                ]
            },
            {
                id: '2',
                title: 'Transitive vuln',
                affected_versions: [
                    { project_version: '2.0', components: [{ is_direct_dependency: false }] }
                ]
            }
        ]
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject' })

        expect(wrapper.findAll('.vuln-group-card').length).toBe(2)

        ;(wrapper.vm as any).dependencyFilter = ['DIRECT']
        await flushPromises()
        expect(wrapper.findAll('.vuln-group-card').length).toBe(1)

        ;(wrapper.vm as any).dependencyFilter = ['DIRECT', 'TRANSITIVE', 'UNKNOWN']
        ;(wrapper.vm as any).versionFilterInput = '1.0'
        await flushPromises()
        expect(wrapper.findAll('.vuln-group-card').length).toBe(1)

        ;(wrapper.vm as any).versionFilterInput = '2.0'
        await flushPromises()
        expect(wrapper.findAll('.vuln-group-card').length).toBe(1)

        ;(wrapper.vm as any).versionFilterInput = '1.0,2.0'
        await flushPromises()
        expect(wrapper.findAll('.vuln-group-card').length).toBe(2)

        // Verify dependency relationship badge counts
        expect(wrapper.text()).toContain('Direct')
        expect(wrapper.text()).toContain('Transitive')

        // Query update should occur for state-driven filters
        expect(replaceSpy).toHaveBeenCalled()
        const lastCall = replaceSpy.mock.calls[replaceSpy.mock.calls.length - 1] as any[] | undefined
        const latestQuery = lastCall?.[0]?.query
        expect(latestQuery).toMatchObject({ versions: '1.0,2.0' })
    })

    it('copies the current filter URL to clipboard', async () => {
        vi.mocked(getGroupedVulns).mockResolvedValue([{ id: '1', affected_versions: [] } as any])

        const wrapper = await mountProjectView({ routeName: 'TestProject' })

        const copyBtn = wrapper.findAll('button').find(b => b.text().includes('Copy filter URL'))
        expect(copyBtn).toBeDefined()
        if (!copyBtn) {
            throw new Error('Copy button not found')
        }

        await copyBtn.trigger('click')

        expect(writeTextSpy).toHaveBeenCalled()
    })

    it('updates local state on assessment update', async () => {
        const mockGroup = {
            id: '1',
            title: 'Vuln 1',
            rescored_cvss: null,
            affected_versions: [
                {
                    components: [
                        { analysis_state: 'NOT_SET' }
                    ]
                }
            ]
        }
        vi.mocked(getGroupedVulns).mockResolvedValue([mockGroup] as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject' })

        // Ensure visible
        await updateProjectViewState(wrapper, {
            lifecycleFilters: defaultLifecycleFilters,
            analysisFilters: defaultAnalysisFilters,
        })

        const updateData = {
            rescored_cvss: 5.0,
            rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            analysis_state: 'EXPLOITABLE',
            analysis_details: 'Details',
            is_suppressed: false
        }

        await wrapper.findComponent({ name: 'VulnGroupCard' }).vm.$emit('update:assessment', updateData)

        expect(mockGroup.rescored_cvss).toBe(5.0)
        expect(mockGroup.affected_versions?.[0]?.components?.[0]?.analysis_state).toBe('EXPLOITABLE')
    })

    it('refreshes statistics when assessment update occurs in statistics mode', async () => {
        const mockGroup = {
            id: '1',
            title: 'Vuln 1',
            rescored_cvss: null,
            affected_versions: [{ components: [{ analysis_state: 'NOT_SET' }] }]
        }
        vi.mocked(getGroupedVulns).mockResolvedValue([mockGroup] as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject' })

        ;(wrapper.vm as any).viewMode = 'analysis'
        ;(wrapper.vm as any).stats = { total_unique: 0 } // mark stats loaded

        const updateData = {
            rescored_cvss: 5.0,
            rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            analysis_state: 'EXPLOITABLE',
            analysis_details: 'Details',
            is_suppressed: false
        }

        await wrapper.findComponent({ name: 'VulnGroupCard' }).vm.$emit('update:assessment', updateData)

        // Not in statistics mode yet, so update should only mark dirty, not fetch.
        expect(getStatistics).not.toHaveBeenCalled()

        ;(wrapper.vm as any).viewMode = 'statistics'
        await flushPromises()

        expect(getStatistics).toHaveBeenCalled()
    })

    it('does not fetch if route param name is undefined', async () => {
        vi.mocked(useRoute).mockReturnValue({
            params: {}, query: {}
        } as any)

        await mountProjectView({ routeName: undefined })
        expect(getGroupedVulns).not.toHaveBeenCalled()
    })

    it('handles _all_ project name context', async () => {
        vi.mocked(useRoute).mockReturnValue({
            params: { name: '_all_' }, query: {}
        } as any)

        const wrapper = await mountProjectView({ routeName: '_all_', flush: false })

        expect(wrapper.text()).toContain('Starting global search')
        // "All Projects" text is rendered in App.vue header, not inside ProjectView

        await flushPromises()

        expect(getGroupedVulns).toHaveBeenCalledWith('', undefined, expect.any(Function))
    })
})
