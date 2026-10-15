import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import DonutChart from '../DonutChart.vue'

const segments = [
    { label: 'Open', value: 1, color: '#fb923c' },
    { label: 'Assessed', value: 3, color: '#22d3ee' },
]

describe('DonutChart', () => {
    it('renders proportional arcs and exact counts with percentages', () => {
        const wrapper = mount(DonutChart, { props: { title: 'Team coverage', segments } })
        const arcs = wrapper.findAll('[data-testid="donut-slice"]')
        expect(arcs.map(arc => arc.attributes('stroke-dasharray'))).toEqual(['25 75', '75 25'])
        expect(arcs.map(arc => arc.attributes('stroke-dashoffset'))).toEqual(['0', '-25'])
        expect(wrapper.findAll('[data-testid="donut-legend-row"]').map(row => row.text())).toEqual(['Open125.0%', 'Assessed375.0%'])
        const svg = wrapper.get('svg')
        expect(wrapper.get(`[id="${svg.attributes('aria-labelledby')}"]`).text()).toBe('Team coverage: 4 vulnerabilities')
    })

    it('renders a complete ring for a single category', () => {
        const wrapper = mount(DonutChart, { props: { title: 'Complete', segments: [segments[1]!] } })
        expect(wrapper.get('[data-testid="donut-slice"]').attributes('stroke-dasharray')).toBe('100 0')
        expect(wrapper.text()).toContain('100.0%')
    })

    it('shows a safe empty state for zero or invalid counts', () => {
        const wrapper = mount(DonutChart, { props: { title: 'Empty', segments: [
            { ...segments[0]!, value: 0 }, { ...segments[1]!, value: Number.NaN },
        ] } })
        expect(wrapper.findAll('[data-testid="donut-slice"]')).toHaveLength(0)
        expect(wrapper.text()).toContain('No data for this chart.')
        expect(wrapper.html()).not.toContain('NaN')
    })

    it('refreshes proportions when filtered counts change and hides stale data while updating', async () => {
        const wrapper = mount(DonutChart, { props: { title: 'Filtered', segments } })
        await wrapper.setProps({ updating: true })
        expect(wrapper.attributes('aria-busy')).toBe('true')
        expect(wrapper.find('svg').exists()).toBe(false)
        await wrapper.setProps({ updating: false, segments: [{ ...segments[0]!, value: 2 }] })
        expect(wrapper.get('svg > title').text()).toBe('Filtered: 2 vulnerabilities')
        expect(wrapper.get('[data-testid="donut-slice"]').attributes('stroke-dasharray')).toBe('100 0')
    })
})
