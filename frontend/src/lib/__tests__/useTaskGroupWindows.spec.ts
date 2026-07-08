import { computed, ref } from 'vue'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useTaskGroupWindows } from '../useTaskGroupWindows'
import type { GroupedVuln } from '../../types'

vi.mock('../api', () => ({
    getTaskVulnGroups: vi.fn(),
}))

const group = (id: string): GroupedVuln => ({
    id,
    affected_versions: [],
})

describe('useTaskGroupWindows', () => {
    beforeEach(() => {
        vi.clearAllMocks()
    })

    it('loads a reset window with the current query and stores the returned counts', async () => {
        const api = await import('../api')
        vi.mocked(api.getTaskVulnGroups).mockResolvedValue({
            items: [group('CVE-1')],
            total: 5,
            filtered: 1,
            counts: {
                all: {
                    total: 5,
                    lifecycle: { OPEN: 5 },
                    analysis: { NOT_SET: 5 },
                    dependency_relationship: { direct: 3, transitive: 1, unknown: 1 },
                    cvss_version_mismatch: 0,
                    versions: {},
                    tags: {},
                    assignees: {},
                    components: {},
                },
                filtered: {
                    total: 1,
                    lifecycle: { OPEN: 1 },
                    analysis: { NOT_SET: 1 },
                    dependency_relationship: { direct: 1, transitive: 0, unknown: 0 },
                    cvss_version_mismatch: 0,
                    versions: {},
                    tags: {},
                    assignees: {},
                    components: {},
                },
            },
            offset: 0,
            limit: 2,
            next_cursor: null,
            sort: 'id',
            order: 'asc',
            partial: true,
            partial_versions_completed: 2,
            partial_total_versions: 5,
            partial_publish_in_progress: true,
            versions_completed: 3,
            versions_total: 5,
        })

        const taskId = ref('task-1')
        const groups = ref<GroupedVuln[]>([])
        const resetVisibleItems = vi.fn()
        const processGroups = vi.fn(async (items: GroupedVuln[]) =>
            items.map(item => ({ ...item, title: 'processed' })),
        )

        const taskWindows = useTaskGroupWindows({
            currentTaskId: taskId,
            groups,
            query: computed(() => ({ lifecycle: ['OPEN'], sort: 'id', order: 'asc' })),
            limit: 2,
            processGroups,
            onResetVisibleItems: resetVisibleItems,
        })

        await taskWindows.loadWindow({ reset: true })

        expect(api.getTaskVulnGroups).toHaveBeenCalledWith('task-1', {
            lifecycle: ['OPEN'],
            sort: 'id',
            order: 'asc',
            offset: 0,
            limit: 2,
        })
        expect(processGroups).toHaveBeenCalledWith([group('CVE-1')])
        expect(groups.value).toEqual([{ ...group('CVE-1'), title: 'processed' }])
        expect(taskWindows.total.value).toBe(5)
        expect(taskWindows.filtered.value).toBe(1)
        expect(taskWindows.counts.value?.all.lifecycle.OPEN).toBe(5)
        expect(taskWindows.partial.value).toBe(true)
        expect(taskWindows.partialVersionsCompleted.value).toBe(2)
        expect(taskWindows.partialVersionsTotal.value).toBe(5)
        expect(taskWindows.partialPublishInProgress.value).toBe(true)
        expect(taskWindows.versionsCompleted.value).toBe(3)
        expect(taskWindows.versionsTotal.value).toBe(5)
        expect(taskWindows.windowLoading.value).toBe(false)
        expect(resetVisibleItems).toHaveBeenCalledTimes(1)
    })

    it('updates partial progress from task status and clears it when completed', () => {
        const taskWindows = useTaskGroupWindows({
            currentTaskId: ref('task-1'),
            groups: ref<GroupedVuln[]>([]),
            query: computed(() => ({})),
            limit: 2,
        })

        taskWindows.updateFromTaskStatus({
            status: 'running',
            partial_result_available: true,
            partial_versions_completed: 12,
            partial_total_versions: 29,
            partial_publish_in_progress: true,
            versions_completed: 16,
            versions_total: 29,
        })

        expect(taskWindows.partial.value).toBe(true)
        expect(taskWindows.partialVersionsCompleted.value).toBe(12)
        expect(taskWindows.partialVersionsTotal.value).toBe(29)
        expect(taskWindows.partialPublishInProgress.value).toBe(true)
        expect(taskWindows.versionsCompleted.value).toBe(16)
        expect(taskWindows.versionsTotal.value).toBe(29)

        taskWindows.updateFromTaskStatus({
            status: 'running',
            partial_result_available: true,
            partial_versions_completed: 13,
            partial_total_versions: 29,
            partial_publish_in_progress: false,
            versions_completed: 17,
            versions_total: 29,
        })

        expect(taskWindows.partialVersionsCompleted.value).toBe(13)
        expect(taskWindows.partialVersionsTotal.value).toBe(29)
        expect(taskWindows.partialPublishInProgress.value).toBe(false)
        expect(taskWindows.versionsCompleted.value).toBe(17)
        expect(taskWindows.versionsTotal.value).toBe(29)

        taskWindows.updateFromTaskStatus({
            status: 'completed',
            partial_result_available: false,
            versions_completed: 29,
            versions_total: 29,
        })

        expect(taskWindows.partial.value).toBe(false)
        expect(taskWindows.partialVersionsCompleted.value).toBeNull()
        expect(taskWindows.partialVersionsTotal.value).toBeNull()
        expect(taskWindows.partialPublishInProgress.value).toBe(false)
        expect(taskWindows.versionsCompleted.value).toBe(29)
        expect(taskWindows.versionsTotal.value).toBe(29)
    })

    it('appends the next window using the backend cursor when available', async () => {
        const api = await import('../api')
        vi.mocked(api.getTaskVulnGroups)
            .mockResolvedValueOnce({
                items: [group('CVE-1')],
                total: 3,
                filtered: 3,
                offset: 0,
                limit: 1,
                next_cursor: 'cursor-1',
                has_more: true,
                sort: 'severity',
                order: 'desc',
            })
            .mockResolvedValueOnce({
                items: [group('CVE-2')],
                total: 3,
                filtered: 3,
                offset: 1,
                limit: 1,
                next_cursor: null,
                has_more: false,
                sort: 'severity',
                order: 'desc',
            })

        const groups = ref<GroupedVuln[]>([])
        const taskWindows = useTaskGroupWindows({
            currentTaskId: ref('task-1'),
            groups,
            query: computed(() => ({ sort: 'severity', order: 'desc' })),
            limit: 1,
        })

        await taskWindows.loadWindow({ reset: true })
        await taskWindows.loadWindow({ reset: false })

        expect(api.getTaskVulnGroups).toHaveBeenNthCalledWith(2, 'task-1', {
            sort: 'severity',
            order: 'desc',
            cursor: 'cursor-1',
            limit: 1,
        })
        expect(groups.value.map(item => item.id)).toEqual(['CVE-1', 'CVE-2'])
        expect(taskWindows.hasMoreGroups.value).toBe(true)
    })

    it('ignores stale windows that resolve after a newer request', async () => {
        const api = await import('../api')
        let resolveFirst: (value: any) => void = () => {}
        vi.mocked(api.getTaskVulnGroups)
            .mockReturnValueOnce(new Promise(resolve => {
                resolveFirst = resolve
            }))
            .mockResolvedValueOnce({
                items: [group('CVE-new')],
                total: 1,
                filtered: 1,
                offset: 0,
                limit: 1,
                next_cursor: null,
                sort: 'id',
                order: 'asc',
            })

        const groups = ref<GroupedVuln[]>([])
        const taskWindows = useTaskGroupWindows({
            currentTaskId: ref('task-1'),
            groups,
            query: computed(() => ({ sort: 'id', order: 'asc' })),
            limit: 1,
        })

        const firstRequest = taskWindows.loadWindow({ reset: true })
        await taskWindows.loadWindow({ reset: true })
        resolveFirst({
            items: [group('CVE-old')],
            total: 1,
            filtered: 1,
            offset: 0,
            limit: 1,
            sort: 'id',
            order: 'asc',
        })
        await firstRequest

        expect(groups.value.map(item => item.id)).toEqual(['CVE-new'])
        expect(taskWindows.windowLoading.value).toBe(false)
    })
})
