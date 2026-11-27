import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import ReportedFindingScope from '../ReportedFindingScope.vue'

describe('reported component versions', () => {
    it.each([undefined, 'Security'])('comma-groups equivalent coverage without inventing release/version associations for %s', team => {
        const finding = (product: string, version: string, state = 'NOT_AFFECTED') => ({
            project_version: product, component_name: 'lib', component_version: version,
            analysis_state: state, analysis_details: `--- [Team: Security] [State: ${state}] ---\nReviewed.`,
        })
        const instances = ['1.0', '2.0'].flatMap(product => ['3.0', '4.0'].map(version => finding(product, version)))
        const wrapper = mount(ReportedFindingScope, { props: { team, instances } })
        const rows = () => wrapper.findAll('tbody tr').map(row => row.findAll('td').map(cell => cell.text()))
        expect(rows()).toEqual([['1.0, 2.0', 'lib', '3.0, 4.0', 'Not affected']])
        wrapper.unmount()
        const differing = mount(ReportedFindingScope, { props: { team, instances: [
            ...instances, finding('5.0', '4.0'), finding('2.0', '3.0', 'EXPLOITABLE'),
        ] } })
        const cells = differing.findAll('tbody tr').map(row => row.findAll('td').map(cell => cell.text()))
        expect(cells).toContainEqual(['1.0, 2.0', 'lib', '3.0', 'Not affected'])
        expect(cells).toContainEqual(['1.0, 2.0, 5.0', 'lib', '4.0', 'Not affected'])
        expect(cells).toContainEqual(['2.0', 'lib', '3.0', 'Exploitable'])
        expect(cells).toHaveLength(3)
    })

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

    it('shows only the selected team’s own current decisions, resolving aliases and retaining conflicting states', () => {
        const wrapper = mount(ReportedFindingScope, { props: {
            team: 'Runtime', teamAliases: ['Legacy Runtime'],
            instances: [{
                component_name: 'library', component_version: '2.0', project_version: '7.1',
                analysis_state: 'EXPLOITABLE',
                analysis_details: [
                    '--- [Team: General] [State: EXPLOITABLE] ---\nGlobal state.',
                    '--- [Team: Legacy Runtime] [State: NOT_AFFECTED] ---\nAlias decision.',
                    '--- [Team: Runtime] [State: FALSE_POSITIVE] ---\nConflicting team decision.',
                    '--- [Team: Runtime] [State: RESOLVED] [Historical: yes] ---\nOld decision.',
                ].join('\n\n'),
            }],
        } })
        expect(wrapper.get('h4').text()).toBe('Reported components for Runtime')
        expect(wrapper.findAll('thead th').at(-1)?.text()).toBe('Runtime assessment')
        expect(wrapper.findAll('tbody tr').map(row => row.findAll('td').at(-1)?.text()))
            .toEqual(['False positive', 'Not affected'])
        expect(wrapper.find('tbody')!.text()).not.toContain('Exploitable')
        expect(wrapper.find('tbody')!.text()).not.toContain('Resolved')
    })

    it('does not present a Global decision as an explicit team decision', () => {
        const wrapper = mount(ReportedFindingScope, { props: {
            team: 'Security', instances: [{
                component_name: 'library', analysis_state: 'EXPLOITABLE',
                analysis_details: '--- [Team: General] [State: EXPLOITABLE] ---\nGlobal decision.',
            }],
        } })
        expect(wrapper.get('tbody').text()).toContain('Not assessed by this team')
        expect(wrapper.get('tbody').text()).not.toContain('Exploitable')
    })
})
