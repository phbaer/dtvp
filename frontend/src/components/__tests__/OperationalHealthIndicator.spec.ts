import { computed, ref } from 'vue'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import OperationalHealthIndicator from '../OperationalHealthIndicator.vue'
import { getOperationalHealth } from '../../lib/api'

vi.mock('../../lib/api', () => ({
    getOperationalHealth: vi.fn(),
}))

const routerLinkStub = {
    template: "<a v-bind='$attrs' :data-to='typeof to === \"string\" ? to : JSON.stringify(to)'><slot /></a>",
    props: ['to'],
}

describe('OperationalHealthIndicator', () => {
    afterEach(() => {
        vi.useRealTimers()
    })

    beforeEach(() => {
        vi.clearAllMocks()
        vi.setSystemTime(new Date('2026-05-07T10:06:00+00:00'))
    })

    it('shows warning state for reviewers', async () => {
        vi.useFakeTimers()
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
                    'router-link': routerLinkStub,
                },
            },
        })

        await flushPromises()

        const indicator = wrapper.find('[data-testid="operational-health-indicator"]')
        const panel = wrapper.find('[data-testid="operational-health-panel"]')

        expect(getOperationalHealth).toHaveBeenCalled()
        expect(wrapper.text()).toContain('Ops')
        expect(wrapper.text()).toContain('2 warnings')
        expect(wrapper.text()).toContain('checked 1m ago')
        expect(indicator.attributes('title')).toContain('2 warnings')
        expect(indicator.attributes('title')).toContain('checked 1m ago')
        expect(indicator.attributes('title')).toContain('Pending DT updates backlog: 3 queued, oldest 412s.')
        expect(panel.text()).toContain('Active Warnings')
        expect(panel.text()).toContain('checked 1m ago')
        expect(panel.text()).toContain('Pending DT updates backlog: 3 queued, oldest 412s.')
        expect(panel.text()).toContain('Orphaned retained assessments: 0 records detected.')
        const warningLinks = wrapper.findAll('[data-warning-target]')
        expect(warningLinks).toHaveLength(2)
        expect(warningLinks[0]?.attributes('data-warning-target')).toBe('#cache-status')
        expect(warningLinks[0]?.attributes('data-to')).toContain('"hash":"#cache-status"')
        expect(warningLinks[1]?.attributes('data-warning-target')).toBe('#knowledge-store-status')
    })

    it('stays hidden for analysts', async () => {
        const wrapper = mount(OperationalHealthIndicator, {
            global: {
                provide: {
                    realRole: computed(() => 'ANALYST'),
                },
                stubs: {
                    'router-link': routerLinkStub,
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
                    'router-link': routerLinkStub,
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