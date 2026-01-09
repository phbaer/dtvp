
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
})
