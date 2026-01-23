import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import Dashboard from '../Dashboard.vue'
import { getProjects } from '../../lib/api'

vi.mock('../../lib/api', () => ({
    getProjects: vi.fn()
}))

describe('Dashboard.vue', () => {
    beforeEach(() => {
        vi.clearAllMocks()
    })

    it('renders correctly', () => {
        const wrapper = mount(Dashboard, {
            global: { stubs: { RouterLink: { template: '<a :href="to"><slot /></a>', props: ['to'] } } }
        })
        expect(wrapper.text()).toContain('Find a Project')
    })

    it('fetches projects on search', async () => {
        // Mock response
        const mockProjects = [
            { uuid: '1', name: 'Test Project', version: '1.0' }
        ]
        vi.mocked(getProjects).mockResolvedValue(mockProjects as any)

        const wrapper = mount(Dashboard, {
            global: { stubs: { RouterLink: { template: '<a :href="to"><slot /></a>', props: ['to'] } } }
        })

        // Set query
        await wrapper.find('input').setValue('Test')
        await wrapper.find('form').trigger('submit')

        // Skip loading assertion as it might be too fast
        await flushPromises()

        expect(getProjects).toHaveBeenCalledWith('Test')
        expect(wrapper.text()).toContain('Test Project')
        expect(wrapper.text()).not.toContain('No projects found')
    })

    it('displays empty state when no results', async () => {
        vi.mocked(getProjects).mockResolvedValue([])

        const wrapper = mount(Dashboard, {
            global: { stubs: { RouterLink: { template: '<a :href="to"><slot /></a>', props: ['to'] } } }
        })

        await wrapper.find('input').setValue('NonExistent')
        await wrapper.find('form').trigger('submit')

        await flushPromises()

        expect(getProjects).toHaveBeenCalled()
        expect(wrapper.text()).toContain('No projects found')
    })

    it('handles error', async () => {
        vi.mocked(getProjects).mockRejectedValue(new Error('Fetch error'))

        // Mock window.alert
        const alertMock = vi.spyOn(window, 'alert').mockImplementation(() => { })
        const consoleError = vi.spyOn(console, 'error').mockImplementation(() => { })

        const wrapper = mount(Dashboard, {
            global: { stubs: { RouterLink: { template: '<a><slot /></a>' } } }
        })

        await wrapper.find('input').setValue('Error')
        await wrapper.find('form').trigger('submit')

        await flushPromises()

        expect(consoleError).toHaveBeenCalled()
        expect(alertMock).toHaveBeenCalledWith('Failed to fetch projects')
    })
})
