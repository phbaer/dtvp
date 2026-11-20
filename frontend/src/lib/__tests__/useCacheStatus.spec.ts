import { flushPromises, mount } from '@vue/test-utils'
import { computed, defineComponent, nextTick } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useCacheStatus } from '../useCacheStatus'
import * as liveEvents from '../eventStream'

vi.mock('../api', () => ({
    getCacheStatus: vi.fn(),
}))

vi.mock('../eventStream', async () => {
    const { createFakeEventStreamModule } = await import('./fakeEventStreamTestUtils')
    return createFakeEventStreamModule()
})

const fakeStream = liveEvents as unknown as {
    emit: (type: string, data?: unknown) => void
    status: { value: string }
    reset: () => void
}

const someStatus = () => ({
    fully_cached: true,
    last_refreshed_at: new Date().toISOString(),
    projects: 1,
    active_projects: 1,
    cached_findings: 1,
    cached_boms: 1,
    cached_analyses: 1,
    pending_updates: 0,
})

const Plain = defineComponent({
    setup() {
        return useCacheStatus()
    },
    template: '<span>{{ cacheStatusLabel }}</span>',
})

describe('useCacheStatus', () => {
    beforeEach(() => {
        vi.resetModules()
        vi.clearAllMocks()
        vi.useFakeTimers()
        fakeStream.reset()
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

    it('refetches once, debounced, after live events', async () => {
        const api = await import('../api')
        vi.mocked(api.getCacheStatus).mockResolvedValue(someStatus())
        fakeStream.status.value = 'live'
        const wrapper = mount(Plain)
        await flushPromises()
        expect(api.getCacheStatus).toHaveBeenCalledTimes(1)

        fakeStream.emit('projects.changed', { added: [] })
        fakeStream.emit('export.state', { pending: 1 })
        fakeStream.emit('source.state', { dt: 'down' })
        await vi.advanceTimersByTimeAsync(999)
        expect(api.getCacheStatus).toHaveBeenCalledTimes(1)
        await vi.advanceTimersByTimeAsync(1)
        expect(api.getCacheStatus).toHaveBeenCalledTimes(2)

        wrapper.unmount()
        fakeStream.emit('resync', { reason: 'restart' })
        await vi.advanceTimersByTimeAsync(5_000)
        expect(api.getCacheStatus).toHaveBeenCalledTimes(2)
    })

    it('follows a background refresh while live within one debounce', async () => {
        const api = await import('../api')
        const first = new Date(Date.now() - 10 * 60 * 1000).toISOString()
        vi.mocked(api.getCacheStatus).mockResolvedValue({ ...someStatus(), last_refreshed_at: first })
        fakeStream.status.value = 'live'
        const wrapper = mount(Plain)
        await flushPromises()
        expect((wrapper.vm as any).cacheStatusText).toContain('updated 10m ago')

        vi.mocked(api.getCacheStatus).mockResolvedValue({ ...someStatus(), last_refreshed_at: new Date().toISOString() })
        fakeStream.emit('cache.refreshed', { last_refreshed_at: new Date().toISOString() })
        await vi.advanceTimersByTimeAsync(1_000)
        await flushPromises()
        expect(api.getCacheStatus).toHaveBeenCalledTimes(2)
        expect((wrapper.vm as any).cacheStatusText).toContain('updated < 1 min ago')
        wrapper.unmount()
    })

    it('polls every 30 seconds while the stream is not live', async () => {
        const api = await import('../api')
        vi.mocked(api.getCacheStatus).mockResolvedValue(someStatus())
        fakeStream.status.value = 'polling'
        const wrapper = mount(Plain)
        await flushPromises()
        await vi.advanceTimersByTimeAsync(30_000)
        expect(api.getCacheStatus).toHaveBeenCalledTimes(2)
        wrapper.unmount()
    })

    it('only refetches for safety while live, and polls again when the stream drops', async () => {
        const api = await import('../api')
        vi.mocked(api.getCacheStatus).mockResolvedValue(someStatus())
        fakeStream.status.value = 'live'
        const wrapper = mount(Plain)
        await flushPromises()

        await vi.advanceTimersByTimeAsync(30_000)
        expect(api.getCacheStatus).toHaveBeenCalledTimes(1)
        await vi.advanceTimersByTimeAsync(270_000)
        expect(api.getCacheStatus).toHaveBeenCalledTimes(2)

        fakeStream.status.value = 'connecting'
        await nextTick()
        await vi.advanceTimersByTimeAsync(30_000)
        expect(api.getCacheStatus).toHaveBeenCalledTimes(3)
        wrapper.unmount()
    })
})
