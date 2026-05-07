import { computed, ref } from 'vue'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import OperationalHealthIndicator from '../OperationalHealthIndicator.vue'
import { getOperationalHealth } from '../../lib/api'

vi.mock('../../lib/api', () => ({
    getOperationalHealth: vi.fn(),
}))

describe('OperationalHealthIndicator', () => {
    afterEach(() => {
        vi.useRealTimers()
    })

    beforeEach(() => {
        vi.clearAllMocks()
    })

    it('shows warning state for reviewers', async () => {
        vi.mocked(getOperationalHealth).mockResolvedValue({
            status: 'warning',
            checked_at: '2026-05-07T10:05:00+00:00',
            checks: {
                    pending_updates_backlog: {
                        name: 'pending_updates_backlog',
                        status: 'warning',
                        count: 3,
                        oldest_age_seconds: 412,
                    },
                knowledge_store_write_backlog: { name: 'knowledge_store_write_backlog', status: 'ok' },
                knowledge_store_orphans: { name: 'knowledge_store_orphans', status: 'warning' },
                knowledge_store_maintenance_freshness: { name: 'knowledge_store_maintenance_freshness', status: 'ok' },
            },
        } as any)

        const wrapper = mount(OperationalHealthIndicator, {
            global: {
                provide: {
                    realRole: computed(() => 'REVIEWER'),
                },
                stubs: {
                    'router-link': {
                        template: '<a><slot /></a>',
                    },
                },
            },
        })

        await flushPromises()

        const indicator = wrapper.find('[data-testid="operational-health-indicator"]')
        const panel = wrapper.find('[data-testid="operational-health-panel"]')

        expect(getOperationalHealth).toHaveBeenCalled()
        expect(wrapper.text()).toContain('Ops')
        expect(wrapper.text()).toContain('2 warnings')
        expect(indicator.attributes('title')).toContain('2 warnings')
        expect(indicator.attributes('title')).toContain('Pending DT updates backlog: 3 queued, oldest 412s.')
        expect(panel.text()).toContain('Active Warnings')
        expect(panel.text()).toContain('Pending DT updates backlog: 3 queued, oldest 412s.')
        expect(panel.text()).toContain('Orphaned retained assessments: 0 records detected.')
    })

    it('stays hidden for analysts', async () => {
        const wrapper = mount(OperationalHealthIndicator, {
            global: {
                provide: {
                    realRole: computed(() => 'ANALYST'),
                },
                stubs: {
                    'router-link': {
                        template: '<a><slot /></a>',
                    },
                },
            },
        })

        await flushPromises()

        expect(getOperationalHealth).not.toHaveBeenCalled()
        expect(wrapper.find('[data-testid="operational-health-indicator"]').exists()).toBe(false)
    })

    it('starts polling when the role becomes reviewer', async () => {
        vi.useFakeTimers()
        vi.mocked(getOperationalHealth).mockResolvedValue({
            status: 'ok',
            checked_at: '2026-05-07T10:05:00+00:00',
            checks: {
                pending_updates_backlog: { name: 'pending_updates_backlog', status: 'ok' },
                knowledge_store_write_backlog: { name: 'knowledge_store_write_backlog', status: 'ok' },
                knowledge_store_orphans: { name: 'knowledge_store_orphans', status: 'ok' },
                knowledge_store_maintenance_freshness: { name: 'knowledge_store_maintenance_freshness', status: 'ok' },
            },
        } as any)

        const role = ref('ANALYST')
        mount(OperationalHealthIndicator, {
            global: {
                provide: {
                    realRole: role,
                },
                stubs: {
                    'router-link': {
                        template: '<a><slot /></a>',
                    },
                },
            },
        })

        await flushPromises()
        expect(getOperationalHealth).not.toHaveBeenCalled()

        role.value = 'REVIEWER'
        await flushPromises()
        expect(getOperationalHealth).toHaveBeenCalledTimes(1)

        await vi.advanceTimersByTimeAsync(30_000)
        expect(getOperationalHealth).toHaveBeenCalledTimes(2)
    })
})