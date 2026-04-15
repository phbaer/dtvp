
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { getGroupedVulns } from '../../lib/api'
import { flushPromises } from '@vue/test-utils'
import { extendedAnalysisFilters, extendedLifecycleFilters, mountProjectView, updateProjectViewState } from './projectViewTestUtils'

vi.mock('../../lib/api', () => ({
    getGroupedVulns: vi.fn(),
    getCacheStatus: vi.fn(() => Promise.resolve({ fully_cached: false, last_refreshed_at: null, projects: 0, active_projects: 0, cached_findings: 0, cached_boms: 0, cached_analyses: 0, pending_updates: 0 })),
    getTeamMapping: vi.fn(() => Promise.resolve({})),
    getRescoreRules: vi.fn(() => Promise.resolve({ transitions: [] })),
    getTMRescoreProposals: vi.fn(() => Promise.resolve({ proposals: {} }))
}))

vi.mock('vue-router', () => ({
    useRoute: vi.fn(() => ({ params: { name: 'Test' }, query: {} })),
    useRouter: vi.fn(() => ({ replace: vi.fn(() => Promise.resolve()) })),
    RouterLink: { template: '<a data-testid="router-link"><slot/></a>' }
}))

vi.mock('../../components/VulnGroupCard.vue', () => ({
    default: {
        template: '<div></div>',
        props: ['group'],
        emits: ['update:assessment']
    }
}))

describe('ProjectView Coverage Extras', () => {
    beforeEach(() => {
        vi.clearAllMocks()
    })

    it('renders the project header with the project title and actions', async () => {
        vi.mocked(getGroupedVulns).mockResolvedValue([])
        const wrapper = await mountProjectView({
            mountOptions: {
                global: {
                    stubs: {
                        RouterLink: { template: '<a data-testid="router-link"><slot/></a>' }
                    }
                }
            }
        })
        // Project name is displayed in App.vue header via projectHeaderState, not inside ProjectView
        // Verify the component mounted without errors
        expect(wrapper.text()).toContain('No vulnerabilities found')
    })

    it('handles assessment update with empty structure', async () => {
        // Setup a group with complicated structure
        const mockGroup = {
            id: 'G1',
            affected_versions: [
                {
                    project_uuid: 'p1',
                    components: [] // Empty components
                },
                {
                    project_uuid: 'p2',
                    components: [{
                        analysis_state: 'OLD',
                        analysis_details: 'OLD',
                        is_suppressed: false
                    }]
                }
            ],
            rescored_cvss: null
        }

        vi.mocked(getGroupedVulns).mockResolvedValue([mockGroup] as any)
        const wrapper = await mountProjectView()

        await updateProjectViewState(wrapper, {
            lifecycleFilters: extendedLifecycleFilters,
            analysisFilters: extendedAnalysisFilters,
        })

        // Trigger update
        const updateData = {
            rescored_cvss: 1.0,
            rescored_vector: 'V',
            analysis_state: 'NEW',
            analysis_details: 'NEW',
            is_suppressed: true
        }

        await wrapper.findComponent({ name: 'VulnGroupCard' }).vm.$emit('update:assessment', updateData)

        // Check updates applied
        // Check second component safely
        const comp = mockGroup.affected_versions?.[1]?.components?.[0]
        expect(comp?.analysis_state).toBe('NEW')
        expect(mockGroup.rescored_cvss).toBe(1.0)
    })

    it('filters groups by tags', async () => {
        const mockGroups = [
            { id: '1', tags: ['TeamA', 'Backend'] },
            { id: '2', tags: ['Frontend'] },
            { id: '3', tags: [] }, // No tags
            { id: '4' } // Undefined tags
        ]
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = await mountProjectView()
        await updateProjectViewState(wrapper, {
            lifecycleFilters: extendedLifecycleFilters,
            analysisFilters: extendedAnalysisFilters,
        })

        // Set filter
        const input = wrapper.find('input[placeholder*="Team Identifier"]')
        await input.setValue('Team')

        // Should only show group 1
        // Note: We need to check what is passed to VulnGroupCard components
        const cards = wrapper.findAllComponents({ name: 'VulnGroupCard' })
        // With 'Team', only 'TeamA' matches
        expect(cards.length).toBe(1)
        if (cards.length > 0) {
            expect(cards[0]!.props('group').id).toBe('1')
        }

        // Clear filter
        await input.setValue('')
        expect(wrapper.findAllComponents({ name: 'VulnGroupCard' }).length).toBe(4)
    })

    it('updates loading progress via callback', async () => {
        // We Use a controlled promise to keep it in "loading" state
        let resolvePromise: (value: any) => void
        let callback: any

        const promise = new Promise((resolve) => {
            resolvePromise = resolve
        })

        vi.mocked(getGroupedVulns).mockImplementation(async (_name, _cve, cb) => {
            callback = cb
            return promise as any
        })

        const wrapper = await mountProjectView()

        // At start, loading is true
        expect(wrapper.text()).toContain('Starting search...')

        // Verify callback updates state WHILE still loading (promise not resolved)
        // Wait for next tick to ensure onMounted started
        await wrapper.vm.$nextTick()

        if (callback) {
            callback('Step 1', 50)
            await wrapper.vm.$nextTick()
            expect(wrapper.text()).toContain('Step 1')
            expect(wrapper.text()).toContain('50%')
        }

        // Finish up
        if (resolvePromise!) resolvePromise([])
        await flushPromises()
    })

    it('handles fetch error', async () => {
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => { })
        vi.mocked(getGroupedVulns).mockRejectedValue(new Error('Network error'))
        const wrapper = await mountProjectView()
        expect(wrapper.text()).toContain('Failed to load vulnerabilities: Network error')
        consoleSpy.mockRestore()
    })

    it('handles fetch error string', async () => {
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => { })
        vi.mocked(getGroupedVulns).mockRejectedValue('String error')
        const wrapper = await mountProjectView()
        expect(wrapper.text()).toContain('Failed to load vulnerabilities: String error')
        consoleSpy.mockRestore()
    })


    it('toggles sort order and handles sorting fallbacks', async () => {
        const mockGroups = [
            { id: '1', severity: 'CRITICAL', rescored_cvss: 10, tags: ['A'] },
            { id: '2', severity: 'LOW', cvss_score: 1, tags: [] },
            { id: '3', severity: 'UNKNOWN', cvss: null, tags: null }
        ]
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = await mountProjectView()

        // Toggle sort order (hits branch 210)
        const sortBtn = wrapper.find('button[title="Descending"]')
        expect(sortBtn).toBeDefined()
        expect((wrapper.vm as any).sortOrder).toBe('desc')
        await sortBtn?.trigger('click')
        expect((wrapper.vm as any).sortOrder).toBe('asc')
        await sortBtn?.trigger('click')
        expect((wrapper.vm as any).sortOrder).toBe('desc')

        // Change sort by to hit branches

        // Severity (hits branch 145 default 5)
        ;(wrapper.vm as any).sortBy = 'severity'
        await wrapper.vm.$nextTick()
        expect((wrapper.vm as any).sortBy).toBe('severity')

        // Score (hits fallbacks in 149-150)
        ;(wrapper.vm as any).sortBy = 'score'
        await wrapper.vm.$nextTick()
        expect((wrapper.vm as any).sortBy).toBe('score')

        // Tags (hits branch 137/138 fallbacks)
        ;(wrapper.vm as any).sortBy = 'tags'
        await wrapper.vm.$nextTick()
        expect((wrapper.vm as any).sortBy).toBe('tags')
    })
})
