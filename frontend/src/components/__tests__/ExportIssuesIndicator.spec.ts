import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import ExportIssuesIndicator from '../ExportIssuesIndicator.vue'
import * as api from '../../lib/api'
import * as liveEvents from '../../lib/eventStream'

vi.mock('../../lib/api', () => ({ getCacheStatus: vi.fn() }))
vi.mock('../../lib/eventStream', async () => {
    const { createFakeEventStreamModule } = await import('../../lib/__tests__/fakeEventStreamTestUtils')
    return createFakeEventStreamModule()
})

const fakeStream = liveEvents as unknown as {
    emit: (type: string, data?: unknown) => void
    status: { value: string }
    reset: () => void
}

const status = (overrides: Record<string, unknown> = {}) => ({
    fully_cached: true,
    last_refreshed_at: null,
    projects: 1,
    active_projects: 0,
    cached_findings: 0,
    cached_boms: 0,
    cached_analyses: 0,
    pending_updates: 0,
    ...overrides,
}) as any

describe('ExportIssuesIndicator', () => {
    beforeEach(() => {
        vi.useFakeTimers()
        vi.clearAllMocks()
        fakeStream.reset()
    })
    afterEach(() => {
        vi.useRealTimers()
    })

    it('stays out of the way while exports are healthy, even with changes waiting', async () => {
        vi.mocked(api.getCacheStatus).mockResolvedValue(status({ pending_updates: 3 }))
        const wrapper = mount(ExportIssuesIndicator)
        await flushPromises()
        expect(wrapper.find('[data-testid="export-issues-indicator"]').exists()).toBe(false)
        wrapper.unmount()
    })

    it('warns about failing exports and opens the queue', async () => {
        vi.mocked(api.getCacheStatus).mockResolvedValue(status({
            pending_updates: 11,
            failed_exports: 10,
            oldest_pending_at: '2026-11-02T04:31:29+00:00',
        }))
        const wrapper = mount(ExportIssuesIndicator)
        await flushPromises()

        const indicator = wrapper.get('[data-testid="export-issues-indicator"]')
        expect(indicator.text()).toContain('Export: 10 failing')
        expect(indicator.attributes('title')).toContain('waiting since')
        await indicator.trigger('click')
        expect(wrapper.emitted('open')).toHaveLength(1)
        wrapper.unmount()
    })

    it('keeps checking and clears once the problems are gone; survives an outage', async () => {
        vi.mocked(api.getCacheStatus).mockResolvedValueOnce(status({ failed_exports: 2 }))
        const wrapper = mount(ExportIssuesIndicator)
        await flushPromises()
        expect(wrapper.find('[data-testid="export-issues-indicator"]').exists()).toBe(true)

        vi.mocked(api.getCacheStatus).mockRejectedValueOnce(new Error('offline'))
        await vi.advanceTimersByTimeAsync(60_000)
        expect(wrapper.find('[data-testid="export-issues-indicator"]').exists()).toBe(true)

        vi.mocked(api.getCacheStatus).mockResolvedValue(status())
        await vi.advanceTimersByTimeAsync(60_000)
        expect(wrapper.find('[data-testid="export-issues-indicator"]').exists()).toBe(false)

        wrapper.unmount()
        const calls = vi.mocked(api.getCacheStatus).mock.calls.length
        await vi.advanceTimersByTimeAsync(180_000)
        expect(vi.mocked(api.getCacheStatus).mock.calls.length).toBe(calls)
    })

    it('follows export.state without a request while live', async () => {
        vi.mocked(api.getCacheStatus).mockResolvedValue(status())
        fakeStream.status.value = 'live'
        const wrapper = mount(ExportIssuesIndicator)
        await flushPromises()
        expect(api.getCacheStatus).toHaveBeenCalledTimes(1)
        expect(wrapper.find('[data-testid="export-issues-indicator"]').exists()).toBe(false)

        fakeStream.emit('export.state', { pending: 3, failed: 2, oldest_pending_at: '2026-11-02T04:31:29+00:00' })
        await flushPromises()
        const indicator = wrapper.get('[data-testid="export-issues-indicator"]')
        expect(indicator.text()).toContain('Export: 2 failing')
        expect(indicator.attributes('title')).toContain('waiting since')

        // No polling while the stream is live.
        await vi.advanceTimersByTimeAsync(180_000)
        expect(api.getCacheStatus).toHaveBeenCalledTimes(1)

        fakeStream.emit('export.state', { pending: 0, failed: 0, oldest_pending_at: null })
        await flushPromises()
        expect(wrapper.find('[data-testid="export-issues-indicator"]').exists()).toBe(false)
        wrapper.unmount()
    })

    it('refetches on hello and resync, and polls once the stream is down', async () => {
        vi.mocked(api.getCacheStatus).mockResolvedValue(status())
        fakeStream.status.value = 'live'
        const wrapper = mount(ExportIssuesIndicator)
        await flushPromises()

        fakeStream.emit('resync', { reason: 'restart' })
        await flushPromises()
        expect(api.getCacheStatus).toHaveBeenCalledTimes(2)

        fakeStream.status.value = 'polling'
        await flushPromises()
        await vi.advanceTimersByTimeAsync(60_000)
        expect(api.getCacheStatus).toHaveBeenCalledTimes(3)
        wrapper.unmount()
    })

    it('loads when a tab hidden at mount and at resync becomes visible while live', async () => {
        let hidden = true
        const hiddenSpy = vi.spyOn(document, 'hidden', 'get').mockImplementation(() => hidden)
        try {
            vi.mocked(api.getCacheStatus).mockResolvedValue(status({ failed_exports: 4 }))
            fakeStream.status.value = 'live'
            const wrapper = mount(ExportIssuesIndicator)
            await flushPromises()
            fakeStream.emit('resync', { reason: 'restart' })
            await flushPromises()
            expect(api.getCacheStatus).not.toHaveBeenCalled()

            hidden = false
            document.dispatchEvent(new Event('visibilitychange'))
            await flushPromises()
            expect(api.getCacheStatus).toHaveBeenCalledTimes(1)
            expect(wrapper.get('[data-testid="export-issues-indicator"]').text()).toContain('Export: 4 failing')

            // Nothing was skipped since, so the next visibility change is free.
            document.dispatchEvent(new Event('visibilitychange'))
            await flushPromises()
            expect(api.getCacheStatus).toHaveBeenCalledTimes(1)
            wrapper.unmount()
        } finally {
            hiddenSpy.mockRestore()
        }
    })

    it('keeps a newer event over an older response', async () => {
        let answer!: (value: any) => void
        vi.mocked(api.getCacheStatus).mockReturnValue(new Promise(resolve => { answer = resolve }))
        fakeStream.status.value = 'live'
        const wrapper = mount(ExportIssuesIndicator)
        fakeStream.emit('export.state', { pending: 2, failed: 2, oldest_pending_at: null })
        answer(status({ failed_exports: 0 }))
        await flushPromises()
        expect(wrapper.get('[data-testid="export-issues-indicator"]').text()).toContain('Export: 2 failing')
        wrapper.unmount()
    })
})
