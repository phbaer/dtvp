import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import VulnRowCompact from '../VulnRowCompact.vue'
import { buildVulnListItem } from '../../lib/vulnListIndex'
import type { GroupedVuln } from '../../types'

const group: GroupedVuln = {
    id: 'CVE-2026-RELOAD',
    title: 'Reloadable vulnerability',
    cvss_score: 7.5,
    affected_versions: [
        {
            project_name: 'Project',
            project_version: '1.0.0',
            project_uuid: 'project-uuid',
            components: [
                {
                    project_name: 'Project',
                    project_version: '1.0.0',
                    project_uuid: 'project-uuid',
                    component_name: 'library-a',
                    component_version: '1.0.0',
                    component_uuid: 'component-uuid',
                    vulnerability_uuid: 'vulnerability-uuid',
                    finding_uuid: 'finding-uuid',
                    analysis_state: 'NOT_SET',
                    is_suppressed: false,
                },
            ],
        },
    ],
}

describe('VulnRowCompact', () => {
    it('emits reload without selecting the vulnerability card', async () => {
        const wrapper = mount(VulnRowCompact, {
            props: { item: buildVulnListItem(group, {}) },
        })

        await wrapper.get('[data-testid="reload-vulnerability"]').trigger('click')

        expect(wrapper.emitted('reload')).toEqual([[group]])
        expect(wrapper.emitted('select')).toBeUndefined()
    })

    it('disables and labels the reload button while loading or after an error', async () => {
        const wrapper = mount(VulnRowCompact, {
            props: {
                item: buildVulnListItem(group, {}),
                reloading: true,
            },
        })
        const button = wrapper.get('[data-testid="reload-vulnerability"]')

        expect(button.attributes('disabled')).toBeDefined()
        expect(button.attributes('aria-label')).toBe('Reloading CVE-2026-RELOAD')

        await wrapper.setProps({ reloading: false, reloadError: 'Reload failed' })
        expect(button.attributes('title')).toBe('Reload failed')
        expect(wrapper.text()).toContain('Reload failed')
    })

    it('shows tmrescore/vscorer availability in the compact vulnerability header', () => {
        const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        const item = buildVulnListItem(
            { ...group, cvss_vector: vector },
            {},
            {
                'CVE-2026-RELOAD': {
                    vuln_id: 'CVE-2026-RELOAD',
                    original_score: 7.5,
                    rescored_score: 4.2,
                    original_vector: vector,
                    rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N',
                    affected_refs: [],
                    session_id: 'session-1',
                    scope: 'latest_only',
                    latest_version: '1.0.0',
                    analyzed_versions: ['1.0.0'],
                },
            },
        )
        const wrapper = mount(VulnRowCompact, { props: { item } })

        expect(wrapper.get('[data-testid="tmrescore-analysis-badge"]').text()).toContain('TMRescore available')
    })
})
