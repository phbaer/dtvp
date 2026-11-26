import { beforeEach, describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { nextTick } from 'vue'
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
        expect(wrapper.get('[data-testid="reload-vulnerability"]').attributes('aria-label')).toBe(`Reload ${group.id}`)
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

    it('shows the code-analysis robot and keeps TMRescore outside the list header', () => {
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

        expect(wrapper.find('[data-testid="tmrescore-analysis-badge"]').exists()).toBe(false)
        const robot = wrapper.get('[data-testid="automatic-assessment-badge"]')
        expect(robot.attributes('data-assessment-status')).toBe('auto')
        expect(robot.attributes('aria-label')).toBe('Automatic code-analysis assessment is available')
        expect(wrapper.get('[data-testid="workflow-state-badge"]').text()).toBe('Result ready')
    })

    it('keeps the completed marker visible during analysis of a vulnerability alias', async () => {
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

        await wrapper.setProps({ item: buildVulnListItem({
            ...item.group, list_metadata: { lifecycle: 'ASSESSED', is_assessed: true },
        }, {}) })
        expect(wrapper.get('[data-testid="workflow-state-badge"]').text()).toBe('Assessed')
        expect(wrapper.get('[data-testid="assessed-corner"]').attributes('aria-hidden')).toBe('true')
        expect(wrapper.get('[data-testid="analysis-progress"]').text()).toContain('library-a')

        await wrapper.setProps({ item: buildVulnListItem({
            ...item.group, list_metadata: { lifecycle: 'NEEDS_APPROVAL', is_pending: true },
        }, {}) })
        expect(wrapper.find('[data-testid="assessed-corner"]').exists()).toBe(false)
        expect(wrapper.get('[data-testid="workflow-state-badge"]').text()).toBe('Ready for approval')
    })

    it('updates component progress and clears it when analysis finishes', async () => {
        const wrapper = mount(VulnRowCompact, { props: { item: buildVulnListItem(group, {}) } })
        const queued = {
            queue_id: 'q1', vuln_id: group.id, component_name: 'library-a',
            submitted_by: 'analyst', submitted_at: '2026-10-29T10:00:00Z',
            status: 'queued' as const, position: 2,
        }
        analysisQueueStore.items.value = [queued]
        await nextTick()
        expect(wrapper.get('[data-testid="workflow-state-badge"]').text()).toBe('Analysis queued')
        expect(wrapper.get('[data-testid="analysis-progress"]').text()).toContain('library-a: Queued · position 2')
        expect(wrapper.find('[role="progressbar"]').exists()).toBe(false)

        analysisQueueStore.items.value = [{
            ...queued, status: 'running',
            progress: { completed_steps: 4, total_steps: 10, percent: 40, current_title: 'Code Scan' },
        }, { ...queued, queue_id: 'q2', component_name: 'library-b' },
        { ...queued, queue_id: 'unrelated', vuln_id: 'CVE-OTHER', component_name: 'unrelated' }]
        await nextTick()
        expect(wrapper.get('[data-testid="analysis-progress"]').text()).toContain('library-a: Code Scan')
        expect(wrapper.get('[data-testid="analysis-progress"]').text()).toContain('40%')
        expect(wrapper.get('[data-testid="analysis-progress"]').text()).toContain('library-b: Queued')
        expect(wrapper.get('[data-testid="analysis-progress"]').text()).not.toContain('unrelated')
        expect(wrapper.get('[role="progressbar"]').attributes('aria-valuenow')).toBe('40')

        analysisQueueStore.items.value = [{ ...queued, status: 'completed' }]
        await nextTick()
        expect(wrapper.find('[data-testid="analysis-progress"]').exists()).toBe(false)
    })

    it('keeps the header clear when there is no code-analysis result', () => {
        const wrapper = mount(VulnRowCompact, { props: { item: buildVulnListItem(group, {}) } })
        expect(wrapper.find('[data-testid="tmrescore-analysis-badge"]').exists()).toBe(false)
        expect(wrapper.find('[data-testid="automatic-assessment-badge"]').exists()).toBe(false)
    })

    it('uses the original severity for the tint until a rescore is saved', async () => {
        const original = { ...group, original_severity: 'CRITICAL' }
        const wrapper = mount(VulnRowCompact, { props: { item: buildVulnListItem(original, {}) } })
        expect(wrapper.attributes('style')).toContain('oklch(from var(--color-gray-800) l 0.028 25)')
        expect(wrapper.get('[data-testid="rescored-severity-badge"]').text()).toBe('Not rescored')

        await wrapper.setProps({ item: buildVulnListItem({ ...original, rescored_cvss: 5.4 }, {}) })
        expect(wrapper.attributes('style')).toContain('oklch(from var(--color-gray-800) l 0.024 88)')
        expect(wrapper.get('[data-testid="severity-badge"]').text()).toBe('Critical')
        expect(wrapper.get('[data-testid="rescored-severity-badge"]').text()).toBe('Medium')
    })

    it('attributes MCP submissions to the matching team only', () => {
        const wrapper = mount(VulnRowCompact, {
            props: {
                item: buildVulnListItem({
                    ...group,
                    tags: ['Core', 'Web'],
                    list_metadata: { assessed_teams: ['Core'], mcp_assessment_teams: ['Core'] },
                }, {}),
            },
        })
        const [core, web] = wrapper.findAll('[data-testid="team-tag"]')
        expect(core.get('[data-testid="team-mcp"]').text()).toBe('MCP')
        expect(web.attributes('aria-label')).toBe('Web: Missing assessment')
        expect(web.find('[data-testid="team-mcp"]').exists()).toBe(false)
    })
})
