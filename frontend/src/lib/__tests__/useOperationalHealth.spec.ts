import { computed, defineComponent } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { useOperationalHealth } from '../useOperationalHealth'

vi.mock('../api', () => ({
    getOperationalHealth: vi.fn(),
}))

describe('useOperationalHealth', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        vi.useFakeTimers()
        vi.setSystemTime(new Date('2026-05-07T10:06:00+00:00'))
    })

    afterEach(() => {
        vi.useRealTimers()
    })

    it('exposes a persistent warning flag only after a second warning poll', async () => {
        const api = await import('../api')
        vi.mocked(api.getOperationalHealth)
            .mockResolvedValueOnce({
                status: 'warning',
                checked_at: '2026-05-07T10:05:00+00:00',
                checks: {
                    pending_updates_backlog: { name: 'pending_updates_backlog', status: 'warning', count: 1, oldest_age_seconds: 61 },
                    knowledge_store_write_backlog: { name: 'knowledge_store_write_backlog', status: 'ok' },
                    knowledge_store_orphans: { name: 'knowledge_store_orphans', status: 'ok' },
                    knowledge_store_maintenance_freshness: { name: 'knowledge_store_maintenance_freshness', status: 'ok' },
                },
            } as any)
            .mockResolvedValueOnce({
                status: 'warning',
                checked_at: '2026-05-07T10:05:30+00:00',
                checks: {
                    pending_updates_backlog: { name: 'pending_updates_backlog', status: 'warning', count: 1, oldest_age_seconds: 91 },
                    knowledge_store_write_backlog: { name: 'knowledge_store_write_backlog', status: 'ok' },
                    knowledge_store_orphans: { name: 'knowledge_store_orphans', status: 'ok' },
                    knowledge_store_maintenance_freshness: { name: 'knowledge_store_maintenance_freshness', status: 'ok' },
                },
            } as any)

        const Harness = defineComponent({
            setup() {
                return useOperationalHealth(computed(() => true))
            },
            template: `
                <div>
                    <span data-testid="visible">{{ persistentWarningVisible }}</span>
                    <span data-testid="checked">{{ checkedAtAgeLabel }}</span>
                </div>
            `,
        })

        const wrapper = mount(Harness)
        await flushPromises()
        expect(wrapper.get('[data-testid="visible"]').text()).toBe('false')

        await vi.advanceTimersByTimeAsync(30_000)
        await flushPromises()
        expect(wrapper.get('[data-testid="visible"]').text()).toBe('true')
        expect(wrapper.get('[data-testid="checked"]').text()).toContain('checked 1m ago')

        wrapper.unmount()
    })
})