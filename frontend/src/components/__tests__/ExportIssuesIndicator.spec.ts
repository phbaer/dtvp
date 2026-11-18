import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import ExportIssuesIndicator from '../ExportIssuesIndicator.vue'
import * as api from '../../lib/api'

vi.mock('../../lib/api', () => ({ getCacheStatus: vi.fn() }))

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

    it('warns about failing exports and conflicts and opens the queue', async () => {
        vi.mocked(api.getCacheStatus).mockResolvedValue(status({
            pending_updates: 11,
            failed_exports: 10,
            diverged_assessments: 1,
            oldest_pending_at: '2026-11-02T04:31:29+00:00',
        }))
        const wrapper = mount(ExportIssuesIndicator)
        await flushPromises()

        const indicator = wrapper.get('[data-testid="export-issues-indicator"]')
        expect(indicator.text()).toContain('10 failing, 1 in conflict')
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
})
