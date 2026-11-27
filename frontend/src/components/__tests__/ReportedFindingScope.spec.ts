import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import ReportedFindingScope from '../ReportedFindingScope.vue'

describe('reported component versions', () => {
    it('keeps release, component version and saved state associated, including conflicting states', () => {
        const finding = { project_version: '2.0', component_name: 'lib', component_version: '1.7', analysis_state: 'NOT_AFFECTED' }
        const wrapper = mount(ReportedFindingScope, { props: { instances: [
            finding, { ...finding },
            { ...finding, project_version: '1.0', component_version: '1.2', analysis_state: 'EXPLOITABLE' },
            { ...finding, analysis_state: 'FALSE_POSITIVE' },
            { component_name: 'other' },
        ] } })
        const rows = wrapper.findAll('tbody tr').map(row => row.findAll('td').map(cell => cell.text()))
        expect(rows).toEqual([
            ['1.0', 'lib', '1.2', 'Exploitable'],
            ['2.0', 'lib', '1.7', 'False positive'],
            ['2.0', 'lib', '1.7', 'Not affected'],
            ['Unknown product version', 'other', 'Unknown component version', 'Not assessed'],
        ])
    })

    it('updates with the team-filtered input and distinguishes no findings from unaffected', async () => {
        const wrapper = mount(ReportedFindingScope, { props: { instances: [
            { component_name: 'only-this-team' },
        ] } })
        await wrapper.setProps({ instances: [] })
        expect(wrapper.find('table').exists()).toBe(false)
        expect(wrapper.text()).toContain('No reported findings in this scope.')
        expect(wrapper.text()).toContain('Missing findings do not prove a product version is unaffected.')
        expect(wrapper.text()).not.toContain('only-this-team')
    })
})
