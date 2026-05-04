import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import Statistics from '../Statistics.vue'
import { getStatistics } from '../../lib/api'
import { useRoute } from 'vue-router'
import flushPromises from 'flush-promises'
import type { RouteLocationNormalizedLoaded } from 'vue-router'
import type { Statistics as StatisticsPayload } from '../../types'

vi.mock('../../lib/api', () => ({
    getStatistics: vi.fn(),
}))

vi.mock('vue-router', () => ({
    useRoute: vi.fn(),
}))

describe('Statistics.vue', () => {
    const getStatisticsMock = vi.mocked(getStatistics)
    const useRouteMock = vi.mocked(useRoute)
    const buildRoute = (query: Record<string, string> = {}): RouteLocationNormalizedLoaded => ({
        fullPath: '/',
        hash: '',
        matched: [],
        meta: {},
        name: undefined,
        params: {},
        path: '/',
        query,
        redirectedFrom: undefined,
    })

    beforeEach(() => {
        getStatisticsMock.mockReset()
        useRouteMock.mockReset()
    })

    it('renders statistics and project header on successful load', async () => {
        useRouteMock.mockReturnValue(buildRoute({ name: 'Example App', id: 'CVE-2024-0001' }))
        getStatisticsMock.mockResolvedValue({
            severity_counts: { CRITICAL: 2 },
            state_counts: { EXPLOITABLE: 2 },
            total_unique: 2,
            total_findings: 2,
            affected_projects_count: 1,
            version_counts: { '1.0.0': 2 },
        } satisfies StatisticsPayload)

        const wrapper = mount(Statistics, {
            global: {
                stubs: {
                    ProjectStatistics: true,
                },
            },
        })

        await flushPromises()

        expect(wrapper.text()).toContain('Statistics')
        expect(wrapper.text()).toContain('Project: Example App')
        expect(wrapper.text()).toContain('Filtered by')
        expect(getStatisticsMock).toHaveBeenCalledWith('Example App', 'CVE-2024-0001')
        expect(wrapper.findComponent({ name: 'ProjectStatistics' }).exists()).toBe(true)
    })

    it('shows an error message when statistics fail to load', async () => {
        useRouteMock.mockReturnValue(buildRoute())
        getStatisticsMock.mockRejectedValue(new Error('Backend unavailable'))

        const wrapper = mount(Statistics, {
            global: {
                stubs: {
                    ProjectStatistics: true,
                },
            },
        })

        await flushPromises()

        expect(wrapper.text()).toContain('Failed to load statistics: Backend unavailable')
    })
})
