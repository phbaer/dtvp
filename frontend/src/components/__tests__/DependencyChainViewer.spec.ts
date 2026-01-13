
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

        resolvePromise!({
            paths: ['A->B', 'C->D'],
            total: 2,
            limit: 10,
            offset: 0
        })
        await flushPromises()

        expect(wrapper.text()).not.toContain('Loading dependency chains...')
        expect(getDependencyChains).toHaveBeenCalledWith('p1', 'c1', 10, 0)
        expect(wrapper.find('[data-testid="path-list"]').text()).toContain('2 paths')
        expect(wrapper.text()).toContain('(2)')
    })

    it('handles pagination (load more)', async () => {
        // First page - instant load
        vi.mocked(getDependencyChains).mockResolvedValueOnce({
            paths: ['A->B'],
            total: 2,
            limit: 1,
            offset: 0
        })

        const wrapper = mount(DependencyChainViewer, { props: defaultProps })

        // Open
        await wrapper.find('button').trigger('click')
        await flushPromises()

        expect(wrapper.text()).toContain('Load More (1 remaining)')

        // Second page - delayed load
        let resolvePromise: (value: any) => void
        const promise = new Promise(resolve => { resolvePromise = resolve })
        vi.mocked(getDependencyChains).mockReturnValueOnce(promise as any)

        // Click Load More
        const loadMoreBtn = wrapper.findAll('button').find(b => b.text().includes('Load More'))
        await loadMoreBtn?.trigger('click')

        expect(wrapper.text()).toContain('Loading more...')

        resolvePromise!({
            paths: ['C->D'],
            total: 2,
            limit: 1,
            offset: 1
        })
        await flushPromises()

        // Should append paths
        expect(getDependencyChains).toHaveBeenCalledTimes(2)
        expect(getDependencyChains).toHaveBeenLastCalledWith('p1', 'c1', 10, 1) // offset updated
        expect(wrapper.find('[data-testid="path-list"]').text()).toContain('2 paths')
        expect(wrapper.text()).not.toContain('Load More')
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
        vi.mocked(getDependencyChains).mockResolvedValue({
            paths: [],
            total: 0,
            limit: 10,
            offset: 0
        })

        const wrapper = mount(DependencyChainViewer, { props: defaultProps })
        await wrapper.find('button').trigger('click')
        await flushPromises()

        expect(wrapper.text()).toContain('No dependency chains found')
    })

    it('does not reload if already loaded when toggling', async () => {
        vi.mocked(getDependencyChains).mockResolvedValue({
            paths: ['A'],
            total: 1,
            limit: 10,
            offset: 0
        })
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
