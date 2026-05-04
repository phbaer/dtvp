import { flushPromises, mount } from '@vue/test-utils'
import { computed, defineComponent, nextTick } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useCacheStatus } from '../useCacheStatus'

vi.mock('../api', () => ({
    getCacheStatus: vi.fn(),
}))

describe('useCacheStatus', () => {
    beforeEach(() => {
        vi.resetModules()
        vi.clearAllMocks()
        vi.useFakeTimers()
    })

    afterEach(() => {
        vi.useRealTimers()
    })

    it('loads cache status on mount and exposes the derived labels', async () => {
        const api = await import('../api')
        vi.mocked(api.getCacheStatus).mockResolvedValue({
            fully_cached: true,
            last_refreshed_at: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
            projects: 1,
            active_projects: 1,
            cached_findings: 2,
            cached_boms: 3,
            cached_analyses: 4,
            pending_updates: 0,
        })

        const Harness = defineComponent({
            setup() {
                return useCacheStatus()
            },
            template: `
                <div>
                    <span data-testid="label">{{ cacheStatusLabel }}</span>
                    <span data-testid="age">{{ cacheStatusAge }}</span>
                    <span data-testid="state">{{ cacheStatusState }}</span>
                </div>
            `,
        })

        const wrapper = mount(Harness)
        await flushPromises()
        await nextTick()

        expect(api.getCacheStatus).toHaveBeenCalledTimes(1)
        expect(wrapper.get('[data-testid="label"]').text()).toBe('Cache in sync')
        expect(wrapper.get('[data-testid="state"]').text()).toBe('cached')
        expect(wrapper.get('[data-testid="age"]').text()).toContain('updated 5m ago')

        wrapper.unmount()
    })

    it('refreshes when the page becomes visible again', async () => {
        const api = await import('../api')
        vi.mocked(api.getCacheStatus)
            .mockResolvedValueOnce({
                fully_cached: false,
                last_refreshed_at: null,
                projects: 0,
                active_projects: 0,
                cached_findings: 0,
                cached_boms: 0,
                cached_analyses: 0,
                pending_updates: 0,
            })
            .mockResolvedValueOnce({
                fully_cached: true,
                last_refreshed_at: new Date().toISOString(),
                projects: 1,
                active_projects: 1,
                cached_findings: 1,
                cached_boms: 1,
                cached_analyses: 1,
                pending_updates: 0,
            })

        const visibilitySpy = vi.spyOn(document, 'visibilityState', 'get')
        visibilitySpy.mockReturnValue('hidden')

        const Harness = defineComponent({
            setup() {
                const cache = useCacheStatus()
                return {
                    state: computed(() => cache.cacheStatusState.value),
                }
            },
            template: '<span data-testid="state">{{ state }}</span>',
        })

        const wrapper = mount(Harness)
        await flushPromises()
        await nextTick()

        expect(wrapper.get('[data-testid="state"]').text()).toBe('partial')

        visibilitySpy.mockReturnValue('visible')
        document.dispatchEvent(new Event('visibilitychange'))
        await flushPromises()
        await nextTick()

        expect(api.getCacheStatus).toHaveBeenCalledTimes(2)
        expect(wrapper.get('[data-testid="state"]').text()).toBe('cached')

        wrapper.unmount()
        visibilitySpy.mockRestore()
    })
})