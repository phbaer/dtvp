import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import ProjectView from '../ProjectView.vue'
import { getGroupedVulns } from '../../lib/api'
import { useRoute } from 'vue-router'

vi.mock('../../lib/api', () => ({
    getGroupedVulns: vi.fn()
}))

vi.mock('vue-router', () => ({
    useRoute: vi.fn(),
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
    beforeEach(() => {
        vi.clearAllMocks()
        vi.mocked(useRoute).mockReturnValue({
            params: { name: 'TestProject' }
        } as any)
    })

    it('fetches vulnerabilities on mount', async () => {
        const mockGroups = [{ id: '1', title: 'Vuln 1' }]
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = mount(ProjectView, {
            global: {
                stubs: {
                    RouterLink: true
                },
                mocks: {
                    $route: { params: { name: 'TestProject' } }
                }
            }
        })

        expect(wrapper.text()).toContain('Starting search')

        await flushPromises()

        expect(getGroupedVulns).toHaveBeenCalledWith('TestProject', expect.any(Function))
        // Child component should be rendered
        expect(wrapper.findAll('.vuln-group-card')).toHaveLength(1)
    })

    it('handles error state', async () => {
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => { })
        vi.mocked(getGroupedVulns).mockRejectedValue(new Error('Failed'))

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: {
                    $route: { params: { name: 'TestProject' } }
                }
            }
        })

        await flushPromises()

        expect(wrapper.text()).toContain('Failed to load vulnerabilities')
        consoleSpy.mockRestore()
    })

    it('handles empty state', async () => {
        vi.mocked(getGroupedVulns).mockResolvedValue([])

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: {
                    $route: { params: { name: 'TestProject' } }
                }
            }
        })

        await flushPromises()

        expect(wrapper.text()).toContain('No vulnerabilities found')
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

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: {
                    $route: { params: { name: 'TestProject' } }
                }
            }
        })

        await flushPromises()

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

    it('does not fetch if route param name is undefined', async () => {
        vi.mocked(useRoute).mockReturnValue({
            params: {}
        } as any)

        mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: {
                    $route: { params: {} }
                }
            }
        })

        await flushPromises()
        expect(getGroupedVulns).not.toHaveBeenCalled()
    })

    it('handles _all_ project name context', async () => {
        vi.mocked(useRoute).mockReturnValue({
            params: { name: '_all_' }
        } as any)

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: {
                    $route: { params: { name: '_all_' } }
                }
            }
        })

        expect(wrapper.text()).toContain('Starting global search')
        expect(wrapper.get('h2').text()).toContain('Vulnerabilities for All Projects')

        await flushPromises()

        expect(getGroupedVulns).toHaveBeenCalledWith('', expect.any(Function))
    })
})
