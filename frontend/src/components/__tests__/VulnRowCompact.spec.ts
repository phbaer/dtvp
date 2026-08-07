import { beforeEach, describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import VulnRowCompact from '../VulnRowCompact.vue'
import { buildVulnListItem } from '../../lib/vulnListIndex'
import { analysisQueueStore } from '../../lib/analysisQueueStore'
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
    beforeEach(() => {
        analysisQueueStore.items.value = []
    })

    it('emits reload without selecting the vulnerability card', async () => {
        const wrapper = mount(VulnRowCompact, {
            props: { item: buildVulnListItem(group, {}) },
        })

        await wrapper.get('[data-testid="reload-vulnerability"]').trigger('click')

        expect(wrapper.emitted('reload')).toEqual([[group]])
        expect(wrapper.emitted('select')).toBeUndefined()
        expect(wrapper.get('[data-testid="compact-vulnerability-header"]').classes())
            .toEqual(expect.arrayContaining(['relative', 'min-h-[5rem]', 'pr-40']))
        expect(wrapper.get('[data-testid="reload-vulnerability"]').classes())
            .toEqual(expect.arrayContaining(['absolute', 'bottom-2', 'right-3']))
        expect(wrapper.get('[data-testid="workflow-state-badge"]').text()).toBe('Needs mapping')
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

    it('shows available tmrescore and code-assessment status icons', () => {
        const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        const item = buildVulnListItem(
            { ...group, tags: ['Security'], cvss_vector: vector, code_assessment_status: 'auto' },
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

        const tmrescoreStatus = wrapper.get('[data-testid="tmrescore-analysis-badge"]')
        expect(tmrescoreStatus.attributes('data-availability')).toBe('available')
        expect(tmrescoreStatus.attributes('aria-label')).toBe('TMRescore analysis available')
        expect(tmrescoreStatus.classes()).toEqual(expect.arrayContaining(['h-5', 'w-5']))
        expect(tmrescoreStatus.get('.sr-only').text()).toBe('TMRescore available')

        const codeAssessmentStatus = wrapper.get('[data-testid="automatic-assessment-badge"]')
        expect(codeAssessmentStatus.attributes('data-availability')).toBe('available')
        expect(codeAssessmentStatus.attributes('data-assessment-status')).toBe('auto')
        expect(codeAssessmentStatus.attributes('aria-label')).toBe('Code assessment available: auto')
        expect(codeAssessmentStatus.classes()).toEqual(expect.arrayContaining(['h-5', 'w-5']))
        expect(codeAssessmentStatus.get('.sr-only').text()).toBe('Code assessment available')
        expect(wrapper.get('[data-testid="workflow-state-badge"]').text()).toBe('Result ready')

        const tmrescoreIcon = tmrescoreStatus.get('svg')
        const codeAssessmentIcon = codeAssessmentStatus.get('svg')
        expect(tmrescoreIcon.classes()).toEqual(expect.arrayContaining(['h-3', 'w-3']))
        expect(codeAssessmentIcon.classes()).toEqual(expect.arrayContaining(['h-3', 'w-3']))
        expect(tmrescoreIcon.attributes('width')).toBe('12')
        expect(tmrescoreIcon.attributes('height')).toBe('12')
        expect(codeAssessmentIcon.attributes('width')).toBe('12')
        expect(codeAssessmentIcon.attributes('height')).toBe('12')
    })

    it('prioritizes active analysis for the vulnerability or one of its aliases', () => {
        analysisQueueStore.items.value = [{
            queue_id: 'queue-running',
            vuln_id: 'ghsa-alias',
            component_name: 'library-a',
            submitted_by: 'analyst',
            submitted_at: '2026-08-04T10:00:00Z',
            status: 'running',
            position: 0,
        }]
        const item = buildVulnListItem({
            ...group,
            aliases: ['GHSA-ALIAS'],
            tags: ['Security'],
        }, {})

        const wrapper = mount(VulnRowCompact, { props: { item } })

        expect(wrapper.get('[data-testid="workflow-state-badge"]').text()).toBe('Analysis running')
    })

    it('shows unavailable tmrescore and code-assessment status icons', () => {
        const wrapper = mount(VulnRowCompact, {
            props: { item: buildVulnListItem(group, {}) },
        })

        const tmrescoreStatus = wrapper.get('[data-testid="tmrescore-analysis-badge"]')
        expect(tmrescoreStatus.attributes('data-availability')).toBe('unavailable')
        expect(tmrescoreStatus.attributes('title')).toBe('No TMRescore/vscorer analysis is available')
        expect(tmrescoreStatus.get('.sr-only').text()).toBe('TMRescore unavailable')

        const codeAssessmentStatus = wrapper.get('[data-testid="automatic-assessment-badge"]')
        expect(codeAssessmentStatus.attributes('data-availability')).toBe('unavailable')
        expect(codeAssessmentStatus.attributes('data-assessment-status')).toBe('none')
        expect(codeAssessmentStatus.attributes('title')).toBe('No code-analysis assessment is available')
        expect(codeAssessmentStatus.get('.sr-only').text()).toBe('Code assessment unavailable')
    })
})
