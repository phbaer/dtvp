import { computed } from 'vue'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import OperationalHealthBanner from '../OperationalHealthBanner.vue'
import { getOperationalHealth } from '../../lib/api'

vi.mock('../../lib/api', () => ({
    getOperationalHealth: vi.fn(),
}))

const routerLinkStub = {
    template: "<a v-bind='$attrs' :data-to='typeof to === \"string\" ? to : JSON.stringify(to)'><slot /></a>",
    props: ['to'],
}

describe('OperationalHealthBanner', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        vi.useFakeTimers()
        vi.setSystemTime(new Date('2026-05-07T10:06:00+00:00'))
    })

    afterEach(() => {
        vi.useRealTimers()
    })

    it('appears only after warnings persist across multiple polls', async () => {
        vi.mocked(getOperationalHealth)
            .mockResolvedValueOnce({
                status: 'warning',
                severity: 'critical',
                checked_at: '2026-05-07T10:05:00+00:00',
                checks: {
                    pending_updates_backlog: {
                        name: 'pending_updates_backlog',
                        status: 'warning',
                        severity: 'critical',
                        remediation: 'Let the pending Dependency-Track updates drain.',
                        count: 3,
                        oldest_age_seconds: 412,
                    },
                    knowledge_store_write_backlog: { name: 'knowledge_store_write_backlog', status: 'ok', severity: 'ok', remediation: 'Check the writer.' },
                    knowledge_store_orphans: { name: 'knowledge_store_orphans', status: 'warning', severity: 'warning', remediation: 'Run maintenance.', count: 1 },
                    knowledge_store_maintenance_freshness: { name: 'knowledge_store_maintenance_freshness', status: 'ok', severity: 'ok', remediation: 'Run maintenance.' },
                },
            } as any)
            .mockResolvedValueOnce({
                status: 'warning',
                severity: 'critical',
                checked_at: '2026-05-07T10:05:30+00:00',
                checks: {
                    pending_updates_backlog: {
                        name: 'pending_updates_backlog',
                        status: 'warning',
                        severity: 'critical',
                        remediation: 'Let the pending Dependency-Track updates drain.',
                        count: 3,
                        oldest_age_seconds: 430,
                    },
                    knowledge_store_write_backlog: { name: 'knowledge_store_write_backlog', status: 'ok', severity: 'ok', remediation: 'Check the writer.' },
                    knowledge_store_orphans: { name: 'knowledge_store_orphans', status: 'warning', severity: 'warning', remediation: 'Run maintenance.', count: 1 },
                    knowledge_store_maintenance_freshness: { name: 'knowledge_store_maintenance_freshness', status: 'ok', severity: 'ok', remediation: 'Run maintenance.' },
                },
            } as any)

        const wrapper = mount(OperationalHealthBanner, {
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
        expect(wrapper.find('[data-testid="operational-health-banner"]').exists()).toBe(false)

        await vi.advanceTimersByTimeAsync(30_000)
        await flushPromises()

        const banner = wrapper.get('[data-testid="operational-health-banner"]')
        expect(banner.text()).toContain('Critical operational warnings are still active')
        expect(banner.text()).toContain('2 active')
        expect(banner.text()).toContain('1 critical')
        expect(banner.text()).toContain('checked 1m ago')
        expect(banner.text()).toContain('Action: Let the pending Dependency-Track updates drain.')
        expect(banner.classes()).toContain('bg-red-500/10')
        const links = wrapper.findAll('[data-warning-target]')
        expect(links).toHaveLength(2)
        expect(links[0]?.attributes('data-warning-target')).toBe('#cache-status')
        expect(links[1]?.attributes('data-warning-target')).toBe('#knowledge-store-status')

        wrapper.unmount()
    })

    it('orders critical warning links before warning-level links', async () => {
        vi.mocked(getOperationalHealth)
            .mockResolvedValueOnce({
                status: 'warning',
                severity: 'critical',
                checked_at: '2026-05-07T10:05:00+00:00',
                checks: {
                    pending_updates_backlog: {
                        name: 'pending_updates_backlog',
                        status: 'warning',
                        severity: 'warning',
                        remediation: 'Let the pending Dependency-Track updates drain.',
                        count: 3,
                        oldest_age_seconds: 412,
                    },
                    knowledge_store_write_backlog: { name: 'knowledge_store_write_backlog', status: 'ok', severity: 'ok', remediation: 'Check the writer.' },
                    knowledge_store_orphans: {
                        name: 'knowledge_store_orphans',
                        status: 'warning',
                        severity: 'critical',
                        remediation: 'Run maintenance.',
                        count: 1,
                    },
                    knowledge_store_maintenance_freshness: { name: 'knowledge_store_maintenance_freshness', status: 'ok', severity: 'ok', remediation: 'Run maintenance.' },
                },
            } as any)
            .mockResolvedValueOnce({
                status: 'warning',
                severity: 'critical',
                checked_at: '2026-05-07T10:05:30+00:00',
                checks: {
                    pending_updates_backlog: {
                        name: 'pending_updates_backlog',
                        status: 'warning',
                        severity: 'warning',
                        remediation: 'Let the pending Dependency-Track updates drain.',
                        count: 3,
                        oldest_age_seconds: 430,
                    },
                    knowledge_store_write_backlog: { name: 'knowledge_store_write_backlog', status: 'ok', severity: 'ok', remediation: 'Check the writer.' },
                    knowledge_store_orphans: {
                        name: 'knowledge_store_orphans',
                        status: 'warning',
                        severity: 'critical',
                        remediation: 'Run maintenance.',
                        count: 1,
                    },
                    knowledge_store_maintenance_freshness: { name: 'knowledge_store_maintenance_freshness', status: 'ok', severity: 'ok', remediation: 'Run maintenance.' },
                },
            } as any)

        const wrapper = mount(OperationalHealthBanner, {
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
        await vi.advanceTimersByTimeAsync(30_000)
        await flushPromises()

        const links = wrapper.findAll('[data-warning-target]')
        expect(links[0]?.attributes('data-warning-target')).toBe('#knowledge-store-status')
        expect(links[1]?.attributes('data-warning-target')).toBe('#cache-status')

        wrapper.unmount()
    })

    it('can be dismissed for the current warning set', async () => {
        vi.mocked(getOperationalHealth)
            .mockResolvedValueOnce({
                status: 'warning',
                severity: 'warning',
                checked_at: '2026-05-07T10:05:00+00:00',
                checks: {
                    pending_updates_backlog: { name: 'pending_updates_backlog', status: 'warning', severity: 'warning', remediation: 'Let the pending Dependency-Track updates drain.', count: 1, oldest_age_seconds: 61 },
                    knowledge_store_write_backlog: { name: 'knowledge_store_write_backlog', status: 'ok', severity: 'ok', remediation: 'Check the writer.' },
                    knowledge_store_orphans: { name: 'knowledge_store_orphans', status: 'ok', severity: 'ok', remediation: 'Run maintenance.' },
                    knowledge_store_maintenance_freshness: { name: 'knowledge_store_maintenance_freshness', status: 'ok', severity: 'ok', remediation: 'Run maintenance.' },
                },
            } as any)
            .mockResolvedValueOnce({
                status: 'warning',
                severity: 'warning',
                checked_at: '2026-05-07T10:05:30+00:00',
                checks: {
                    pending_updates_backlog: { name: 'pending_updates_backlog', status: 'warning', severity: 'warning', remediation: 'Let the pending Dependency-Track updates drain.', count: 1, oldest_age_seconds: 91 },
                    knowledge_store_write_backlog: { name: 'knowledge_store_write_backlog', status: 'ok', severity: 'ok', remediation: 'Check the writer.' },
                    knowledge_store_orphans: { name: 'knowledge_store_orphans', status: 'ok', severity: 'ok', remediation: 'Run maintenance.' },
                    knowledge_store_maintenance_freshness: { name: 'knowledge_store_maintenance_freshness', status: 'ok', severity: 'ok', remediation: 'Run maintenance.' },
                },
            } as any)

        const wrapper = mount(OperationalHealthBanner, {
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
        await vi.advanceTimersByTimeAsync(30_000)
        await flushPromises()

        await wrapper.get('button').trigger('click')
        expect(wrapper.find('[data-testid="operational-health-banner"]').exists()).toBe(false)

        wrapper.unmount()
    })
})