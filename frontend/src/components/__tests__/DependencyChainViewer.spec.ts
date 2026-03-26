
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

    it('auto-loads chains on mount', async () => {
        vi.mocked(getDependencyChains).mockResolvedValue(['A->B', 'C->D'])

        const wrapper = mount(DependencyChainViewer, { props: defaultProps })
        await flushPromises()

        expect(getDependencyChains).toHaveBeenCalledWith('p1', 'c1')
        expect(wrapper.find('[data-testid="path-list"]').text()).toContain('2 paths')
    })

    it('uses pre-loaded paths without API call', async () => {
        const wrapper = mount(DependencyChainViewer, {
            props: { ...defaultProps, paths: ['X->Y'] }
        })
        await flushPromises()

        expect(getDependencyChains).not.toHaveBeenCalled()
        expect(wrapper.find('[data-testid="path-list"]').text()).toContain('1 paths')
    })

    it('handles API errors', async () => {
        vi.mocked(getDependencyChains).mockRejectedValue(new Error('API Error'))

        const wrapper = mount(DependencyChainViewer, { props: defaultProps })
        await flushPromises()

        expect(wrapper.text()).toContain('API Error')
    })

    it('handles API errors with default message', async () => {
        vi.mocked(getDependencyChains).mockRejectedValue('Unknown string error')

        const wrapper = mount(DependencyChainViewer, { props: defaultProps })
        await flushPromises()

        expect(wrapper.text()).toContain('Failed to load chains')
    })

    it('shows empty state', async () => {
        vi.mocked(getDependencyChains).mockResolvedValue([])

        const wrapper = mount(DependencyChainViewer, { props: defaultProps })
        await flushPromises()

        expect(wrapper.text()).toContain('No dependency chains found')
    })

    it('does not reload if paths are provided later via prop', async () => {
        vi.mocked(getDependencyChains).mockResolvedValue(['A'])
        const wrapper = mount(DependencyChainViewer, { props: defaultProps })
        await flushPromises()

        expect(getDependencyChains).toHaveBeenCalledTimes(1)

        // Simulate paths arriving via prop update
        await wrapper.setProps({ paths: ['X->Y', 'Z->W'] })
        await flushPromises()

        // Should not call API again
        expect(getDependencyChains).toHaveBeenCalledTimes(1)
    })
})
