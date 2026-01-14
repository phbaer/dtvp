
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import DependencyChainViewer from '../DependencyChainViewer.vue'
import { getDependencyChains } from '../../lib/api'

vi.mock('../../lib/api', () => ({
    getDependencyChains: vi.fn()
}))

vi.mock('../DependencyPathList.vue', () => ({
    default: { template: '<div data-testid="path-list">{{ paths.length }} paths</div>', props: ['paths'] }
}))

describe('DependencyChainViewer', () => {
    const defaultProps = {
        projectUuid: 'p1',
        componentUuid: 'c1',
        projectName: 'Test Project'
    }

    beforeEach(() => {
        vi.clearAllMocks()
    })

    it('renders initial closed state', () => {
        const wrapper = mount(DependencyChainViewer, { props: defaultProps })
        expect(wrapper.text()).toContain('Show Dependency Chains')
        expect(wrapper.text()).not.toContain('Loading')
    })

    it('loads chains when toggled open', async () => {
        let resolvePromise: (value: any) => void
        const promise = new Promise(resolve => { resolvePromise = resolve })
        vi.mocked(getDependencyChains).mockReturnValue(promise as any)

        const wrapper = mount(DependencyChainViewer, { props: defaultProps })

        await wrapper.find('button').trigger('click')
        expect(wrapper.text()).toContain('Hide Dependency Chains')
        expect(wrapper.text()).toContain('Loading dependency chains...')

        resolvePromise!(['A->B', 'C->D'])
        await flushPromises()

        expect(wrapper.text()).not.toContain('Loading dependency chains...')
        expect(getDependencyChains).toHaveBeenCalledWith('p1', 'c1')
        expect(wrapper.find('[data-testid="path-list"]').text()).toContain('2 paths')
        expect(wrapper.text()).toContain('(2)')
    })



    it('handles API errors', async () => {
        vi.mocked(getDependencyChains).mockRejectedValue(new Error('API Error'))

        const wrapper = mount(DependencyChainViewer, { props: defaultProps })
        await wrapper.find('button').trigger('click')
        await flushPromises()

        expect(wrapper.text()).toContain('API Error')
    })

    it('handles API errors with default message', async () => {
        vi.mocked(getDependencyChains).mockRejectedValue('Unknown string error')

        const wrapper = mount(DependencyChainViewer, { props: defaultProps })
        await wrapper.find('button').trigger('click')
        await flushPromises()

        expect(wrapper.text()).toContain('Failed to load chains')
    })

    it('shows empty state', async () => {
        vi.mocked(getDependencyChains).mockResolvedValue([])

        const wrapper = mount(DependencyChainViewer, { props: defaultProps })
        await wrapper.find('button').trigger('click')
        await flushPromises()

        expect(wrapper.text()).toContain('No dependency chains found')
    })

    it('does not reload if already loaded when toggling', async () => {
        vi.mocked(getDependencyChains).mockResolvedValue(['A'])
        const wrapper = mount(DependencyChainViewer, { props: defaultProps })

        // Open
        await wrapper.find('button').trigger('click')
        await flushPromises()
        expect(getDependencyChains).toHaveBeenCalledTimes(1)

        // Close
        await wrapper.find('button').trigger('click')
        expect(wrapper.text()).toContain('Show Dependency Chains')

        // Open again - should not call API again
        await wrapper.find('button').trigger('click')
        expect(getDependencyChains).toHaveBeenCalledTimes(1)
    })
})
