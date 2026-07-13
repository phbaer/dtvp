import { mount } from '@vue/test-utils'
import { defineComponent, ref } from 'vue'
import { describe, expect, it, vi } from 'vitest'
import type { GroupedVuln } from '../../types'
import {
    applyAssessmentDataToGroup,
    useProjectAssessmentUpdates,
} from '../useProjectAssessmentUpdates'

type ProjectAssessmentUpdates = ReturnType<typeof useProjectAssessmentUpdates>

const makeGroup = (overrides: Partial<GroupedVuln> = {}): GroupedVuln => ({
    id: 'CVE-1',
    title: 'Test',
    tags: ['Team A'],
    affected_versions: [
        {
            project_name: 'Project',
            project_version: '1.0.0',
            project_uuid: 'project-1',
            components: [
                {
                    project_name: 'Project',
                    project_version: '1.0.0',
                    project_uuid: 'project-1',
                    component_name: 'library-a',
                    component_version: '1.2.3',
                    component_uuid: 'component-1',
                    vulnerability_uuid: 'vuln-1',
                    finding_uuid: 'finding-1',
                    analysis_state: 'NOT_SET',
                    analysis_details: '',
                    is_suppressed: false,
                },
            ],
        },
    ],
    ...overrides,
})

const mountHarness = (options: {
    groups?: GroupedVuln[]
    fullCache?: Record<string, GroupedVuln>
    viewMode?: string
    taskWindowActive?: boolean
    refreshTaskWindow?: () => Promise<unknown> | unknown
} = {}) => {
    const groups = ref(options.groups || [makeGroup()])
    const fullGroupCache = ref<Record<string, GroupedVuln>>(options.fullCache || {})
    const cached: GroupedVuln[] = []
    const cacheFullGroup = vi.fn((group: GroupedVuln) => {
        cached.push(group)
        fullGroupCache.value = {
            ...fullGroupCache.value,
            [group.id]: group,
        }
    })
    const statsDirty = ref(false)
    const viewMode = ref(options.viewMode || 'analysis')
    const fetchStats = vi.fn(() => Promise.resolve())
    const isTaskWindowActive = ref(options.taskWindowActive || false)
    const refreshTaskWindow = vi.fn(
        options.refreshTaskWindow || (() => Promise.resolve()),
    )
    const teamMapping = ref<Record<string, string | string[]>>({})
    let updates!: ProjectAssessmentUpdates

    const Harness = defineComponent({
        setup() {
            updates = useProjectAssessmentUpdates({
                groups,
                fullGroupCache,
                cacheFullGroup,
                teamMapping,
                statsDirty,
                viewMode,
                fetchStats,
                isTaskWindowActive,
                refreshTaskWindow,
            })
            return {}
        },
        template: '<div />',
    })

    const wrapper = mount(Harness)
    return {
        wrapper,
        groups,
        fullGroupCache,
        cacheFullGroup,
        cached,
        statsDirty,
        fetchStats,
        refreshTaskWindow,
        updates,
    }
}

describe('useProjectAssessmentUpdates', () => {
    it('applies assessment data to every component instance', () => {
        const group = makeGroup()
        const updated = applyAssessmentDataToGroup(group, {
            analysis_state: 'NOT_AFFECTED',
            analysis_details: 'Reviewed',
            is_suppressed: true,
            justification: 'CODE_NOT_PRESENT',
            rescored_cvss: 3.2,
            rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
            assignees: ['alice'],
        })

        expect(updated.rescored_cvss).toBe(3.2)
        expect(updated.assignees).toEqual(['alice'])
        expect(updated.affected_versions[0].components[0]).toMatchObject({
            analysis_state: 'NOT_AFFECTED',
            analysis_details: 'Reviewed',
            is_suppressed: true,
            justification: 'CODE_NOT_PRESENT',
        })
    })

    it('updates the lightweight list summary from cached full details', async () => {
        const fullGroup = makeGroup()
        const summaryGroup = {
            ...makeGroup(),
            list_metadata: { lifecycle: 'OPEN', is_open: true },
            affected_versions: [],
        }
        const { groups, cacheFullGroup, updates, wrapper } = mountHarness({
            groups: [summaryGroup],
            fullCache: { 'CVE-1': fullGroup },
        })

        updates.handleLocalAssessmentUpdate(summaryGroup, {
            analysis_state: 'NOT_AFFECTED',
            analysis_details: 'Reviewed',
            is_suppressed: false,
        })

        expect(cacheFullGroup).toHaveBeenCalled()
        expect(groups.value[0].affected_versions[0].components[0]).not.toHaveProperty('analysis_details')
        expect(groups.value[0].list_metadata?.technical_state).toBe('NOT_AFFECTED')

        wrapper.unmount()
    })

    it('refreshes an active task window after a local assessment update', () => {
        const { refreshTaskWindow, updates, wrapper } = mountHarness({
            taskWindowActive: true,
        })

        updates.handleLocalAssessmentUpdate(makeGroup(), {
            analysis_state: 'NOT_AFFECTED',
            analysis_details: 'Reviewed',
            is_suppressed: false,
        })

        expect(refreshTaskWindow).toHaveBeenCalledTimes(1)

        wrapper.unmount()
    })

    it('refreshes statistics once for bulk updates in statistics mode', async () => {
        const first = makeGroup({ id: 'CVE-1' })
        const second = makeGroup({ id: 'CVE-2' })
        const { fetchStats, updates, wrapper } = mountHarness({
            groups: [first, second],
            viewMode: 'statistics',
        })
        const onComplete = vi.fn()

        updates.handleBulkUpdates([
            { id: 'CVE-1', data: { analysis_state: 'NOT_AFFECTED', analysis_details: 'One' } },
            { id: 'CVE-2', data: { analysis_state: 'FALSE_POSITIVE', analysis_details: 'Two' } },
        ], onComplete)

        expect(fetchStats).toHaveBeenCalledTimes(1)
        expect(onComplete).toHaveBeenCalledTimes(1)

        wrapper.unmount()
    })

    it('refreshes an active task window once for bulk updates', () => {
        const first = makeGroup({ id: 'CVE-1' })
        const second = makeGroup({ id: 'CVE-2' })
        const { refreshTaskWindow, updates, wrapper } = mountHarness({
            groups: [first, second],
            taskWindowActive: true,
        })

        updates.handleBulkUpdates([
            { id: 'CVE-1', data: { analysis_state: 'NOT_AFFECTED', analysis_details: 'One' } },
            { id: 'CVE-2', data: { analysis_state: 'FALSE_POSITIVE', analysis_details: 'Two' } },
        ])

        expect(refreshTaskWindow).toHaveBeenCalledTimes(1)

        wrapper.unmount()
    })

    it('refreshes an active task window even when bulk updates are empty', () => {
        const { refreshTaskWindow, updates, wrapper } = mountHarness({
            taskWindowActive: true,
        })
        const onComplete = vi.fn()

        updates.handleBulkUpdates([], onComplete)

        expect(refreshTaskWindow).toHaveBeenCalledTimes(1)
        expect(onComplete).toHaveBeenCalledTimes(1)

        wrapper.unmount()
    })
})
