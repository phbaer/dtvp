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

    const mockProjects = [
        { uuid: '1', name: 'App A', version: '1.0', classifier: 'APPLICATION' },
        { uuid: '2', name: 'App A', version: '1.1', classifier: 'APPLICATION' },
        { uuid: '3', name: 'Lib B', version: '2.0', classifier: 'LIBRARY' },
        { uuid: '4', name: 'Other C', version: '1.0', classifier: null } // Test missing classifier
    ]

    it('fetches projects on mount', async () => {
        vi.mocked(getProjects).mockResolvedValue(mockProjects as any)

        const wrapper = mount(Dashboard, {
            global: { stubs: { RouterLink: { template: '<a :href="to"><slot /></a>', props: ['to'] } } }
        })

        // Initial loading state might be visible briefly
        expect(getProjects).toHaveBeenCalledWith('')

        await flushPromises()

        expect(wrapper.text()).not.toContain('Loading projects...')
        expect(wrapper.text()).toContain('APPLICATION')
        expect(wrapper.text()).toContain('LIBRARY')
        expect(wrapper.text()).toContain('Unclassified')
    })

    it('groups projects by classifier and name', async () => {
        vi.mocked(getProjects).mockResolvedValue(mockProjects as any)
        const wrapper = mount(Dashboard, {
            global: { stubs: { RouterLink: { template: '<a :href="to"><slot /></a>', props: ['to'] } } }
        })
        await flushPromises()

        // Check headers
        const headers = wrapper.findAll('h3').map(h => h.text())
        expect(headers).toContain('APPLICATION')
        expect(headers).toContain('LIBRARY')

        // App A should appear once as a card
        expect(wrapper.text()).toContain('App A')

        // Project Name should be a link
        const appALink = wrapper.findAll('a').find(a => a.text() === 'App A')
        expect(appALink).toBeDefined()
        expect(appALink?.attributes('href')).toBe('/project/App A')

        // Versions should be present but not links (our valid stub makes links <a>, so we check they are NOT <a> if we weren't stubbing router-link, 
        // but here we just check text presence and structure)
        // With RouterLink stubbed as <a>, the versions are now <span> so they won't be found as <a>
        const versionLinks = wrapper.findAll('a').filter(a => a.text().startsWith('v'))
        expect(versionLinks.length).toBe(0)

        expect(wrapper.text()).toContain('v1.0')
        expect(wrapper.text()).toContain('v1.1')
    })

    it('filters projects via search input', async () => {
        vi.mocked(getProjects).mockResolvedValue(mockProjects as any)
        const wrapper = mount(Dashboard, {
            global: { stubs: { RouterLink: { template: '<a :href="to"><slot /></a>', props: ['to'] } } }
        })
        await flushPromises()

        const input = wrapper.find('input')
        await input.setValue('Lib')

        expect(wrapper.text()).toContain('Lib B')
        expect(wrapper.text()).not.toContain('App A')
    })

    it('displays empty state when no results from filter', async () => {
        vi.mocked(getProjects).mockResolvedValue(mockProjects as any)
        const wrapper = mount(Dashboard, {
            global: { stubs: { RouterLink: { template: '<a :href="to"><slot /></a>', props: ['to'] } } }
        })
        await flushPromises()

        await wrapper.find('input').setValue('NonExistent')

        expect(wrapper.text()).toContain('No projects found matching your filter')
    })

    it('handles fetch error', async () => {
        vi.mocked(getProjects).mockRejectedValue(new Error('Fetch error'))
        const consoleError = vi.spyOn(console, 'error').mockImplementation(() => { })
        const alertMock = vi.spyOn(window, 'alert').mockImplementation(() => { })

        mount(Dashboard, {
            global: { stubs: { RouterLink: { template: '<a><slot /></a>' } } }
        })
        await flushPromises()

        expect(consoleError).toHaveBeenCalled()
        expect(alertMock).toHaveBeenCalledWith('Failed to fetch projects')
    })
})
