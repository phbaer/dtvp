import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import FindingMatrix from '../FindingMatrix.vue'

const NA = '--- [Team: TeamB] [State: NOT_AFFECTED] [Assessed By: bob] ---\nNot shipped.'
const finding = (version: string, component: string, details: string, state = 'NOT_AFFECTED') => ({
    project_uuid: `p-${version}`,
    project_version: version,
    component_uuid: component,
    component_name: component,
    vulnerability_uuid: 'v1',
    finding_uuid: `p-${version}:${component}:v1`,
    analysis_state: state,
    analysis_details: details,
})

describe('FindingMatrix version scopes', () => {
    it('marks each overridden version column with its label, and two labels as such', () => {
        const wrapper = mount(FindingMatrix, {
            props: {
                instances: [
                    finding('1.0', 'lib', NA),
                    finding('2.0', 'lib', `[Version Override: legacy]\n\n${NA}`),
                    finding('3.0', 'lib', `[Version Override: legacy]\n\n${NA}`),
                    finding('3.0', 'other', `[Version Override: fork]\n\n${NA}`),
                ],
            },
        })

        const headers = wrapper.findAll('[data-testid="context-project-version"]')
        const badge = (index: number) => headers[index]!.find('[data-testid="matrix-version-scope"]')
        expect(headers.map(header => header.text().split(/\s/)[0])).toEqual(['1.0', '2.0', '3.0'])
        expect(badge(0).exists()).toBe(false)
        expect(badge(1).text()).toBe('override: legacy')
        expect(badge(2).text()).toBe('two overrides')
    })
})
