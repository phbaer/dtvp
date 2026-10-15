import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import ProjectStatistics from '../ProjectStatistics.vue'
import DonutChart from '../DonutChart.vue'
import type { TaskVulnGroupListCounts } from '../../lib/api'

const stats = {
    total_unique: 4, total_findings: 4, affected_projects_count: 1,
    severity_counts: { CRITICAL: 3, MEDIUM: 1 },
    state_counts: { EXPLOITABLE: 3, NOT_SET: 1 }, version_counts: {},
}
const filtered: TaskVulnGroupListCounts = {
    total: 1, original_severity: { LOW: 1 }, analysis: { NOT_SET: 1 },
    lifecycle: {}, inconsistency_reason: {}, cvss_version_mismatch: 0,
    dependency_relationship: { direct: 1, transitive: 0, unknown: 0 },
    versions: {}, tags: {}, assignees: {}, components: {},
}

describe('ProjectStatistics distributions', () => {
    it('uses project/global statistics when no review filter counts are supplied', () => {
        const wrapper = mount(ProjectStatistics, { props: { stats } })
        const charts = wrapper.findAllComponents(DonutChart)
        expect(charts).toHaveLength(2)
        expect(charts[0]!.findAll('[data-testid="donut-slice"]').map(slice => slice.attributes('stroke-dasharray'))).toEqual(['75 25', '25 75'])
        expect(charts[1]!.get('svg > title').text()).toContain('4 vulnerabilities')
    })

    it('uses only current filtered distributions and refreshes to zero results', async () => {
        const wrapper = mount(ProjectStatistics, { props: { stats, distributionCounts: filtered } })
        expect(wrapper.text()).toContain('Distributions for current filters · 1 vulnerabilities')
        const charts = wrapper.findAllComponents(DonutChart)
        expect(charts[0]!.get('[data-testid="donut-slice"] title').text()).toBe('LOW: 1 (100.0%)')
        expect(charts[1]!.get('[data-testid="donut-slice"] title').text()).toBe('NOT SET: 1 (100.0%)')
        await wrapper.setProps({ distributionCounts: { ...filtered, total: 0, original_severity: {}, analysis: {} } })
        expect(wrapper.findAll('[data-testid="donut-slice"]')).toHaveLength(0)
        expect(charts[0]!.text()).toContain('No data for this chart.')
    })
})
