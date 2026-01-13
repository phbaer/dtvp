
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import ProjectView from '../ProjectView.vue'
import { getGroupedVulns } from '../../lib/api'

vi.mock('../../lib/api', () => ({
    getGroupedVulns: vi.fn()
}))

vi.mock('vue-router', () => ({
    useRoute: vi.fn(() => ({ params: { name: 'Test' } })),
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

    it('renders the back link explicitly', async () => {
        vi.mocked(getGroupedVulns).mockResolvedValue([])
        const wrapper = mount(ProjectView, {
            global: {
                components: {
                    RouterLink: { template: '<a data-testid="router-link"><slot/></a>' }
                },
                mocks: {
                    $route: { params: { name: 'Test' } }
                }
            }
        })
        expect(wrapper.find('[data-testid="router-link"]').exists()).toBe(true)
        expect(wrapper.text()).toContain('Back to Dashboard')
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
        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: {
                    $route: { params: { name: 'Test' } }
                }
            }
        })

        await flushPromises()

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

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: 'Test' } } }
            }
        })
        await flushPromises()

        // Set filter
        const input = wrapper.find('input[placeholder="Filter by Team Tag..."]')
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

        vi.mocked(getGroupedVulns).mockImplementation(async (_name, cb) => {
            callback = cb
            return promise as any
        })

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: 'Test' } } }
            }
        })

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
        vi.mocked(getGroupedVulns).mockRejectedValue(new Error('Network error'))
        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: 'Test' } } }
            }
        })
        await flushPromises()
        expect(wrapper.text()).toContain('Failed to load vulnerabilities: Network error')
    })

    it('handles fetch error string', async () => {
        vi.mocked(getGroupedVulns).mockRejectedValue('String error')
        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: 'Test' } } }
            }
        })
        await flushPromises()
        expect(wrapper.text()).toContain('Failed to load vulnerabilities: String error')
    })

    it('paginates visible groups', async () => {
        const mockGroups = Array.from({ length: 25 }, (_, i) => ({ id: `${i}`, tags: [] }))
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: 'Test' } } }
            }
        })
        await flushPromises()

        expect(wrapper.findAllComponents({ name: 'VulnGroupCard' }).length).toBe(20)
        expect(wrapper.text()).toContain('Load More')

        await wrapper.find('button.bg-gray-700').trigger('click')

        expect(wrapper.findAllComponents({ name: 'VulnGroupCard' }).length).toBe(25)
        expect(wrapper.text()).not.toContain('Load More')
    })
})
