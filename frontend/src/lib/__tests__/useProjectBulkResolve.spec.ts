import { mount } from '@vue/test-utils'
import { defineComponent, ref } from 'vue'
import { describe, expect, it, vi } from 'vitest'
import type { TaskVulnGroupListQuery } from '../api'
import type { GroupedVuln } from '../../types'
import { drainTaskVulnGroupDetails } from '../api'
import { useProjectBulkResolve } from '../useProjectBulkResolve'

vi.mock('../api', () => ({
    drainTaskVulnGroupDetails: vi.fn(),
}))

type ProjectBulkResolve = ReturnType<typeof useProjectBulkResolve>

const group = (id: string): GroupedVuln => ({
    id,
    affected_versions: [],
})

const mountHarness = (options: {
    taskId?: string | null
    query?: TaskVulnGroupListQuery
    incompleteGroups?: GroupedVuln[]
    ensureFullGroup?: (groupId: string, options?: { showLoading?: boolean }) => Promise<GroupedVuln | null>
} = {}) => {
    const currentTaskId = ref<string | null>(options.taskId ?? null)
    const taskGroupListQuery = ref<TaskVulnGroupListQuery>(options.query || {})
    const incompleteGroups = ref(options.incompleteGroups || [])
    const ensureFullGroup = vi.fn(options.ensureFullGroup || (async (id: string) => group(`${id}-full`)))
    let bulk!: ProjectBulkResolve

    const Harness = defineComponent({
        setup() {
            bulk = useProjectBulkResolve({
                currentTaskId,
                taskGroupListQuery,
                incompleteGroups,
                ensureFullGroup,
            })
            return {}
        },
        template: '<div />',
    })

    const wrapper = mount(Harness)
    return {
        wrapper,
        currentTaskId,
        taskGroupListQuery,
        incompleteGroups,
        ensureFullGroup,
        bulk,
    }
}

describe('useProjectBulkResolve', () => {
    it('loads full incomplete groups from the task detail window', async () => {
        vi.mocked(drainTaskVulnGroupDetails).mockResolvedValue([group('CVE-1')])
        const { bulk, ensureFullGroup, wrapper } = mountHarness({
            taskId: 'task-1',
            query: {
                q: 'urgent',
                lifecycle: ['OPEN', 'INCOMPLETE'],
                tag: 'platform',
                versions: ['2.0.0'],
                sort: 'severity',
                order: 'desc',
            },
        })

        await bulk.openBulkResolveModal()

        expect(drainTaskVulnGroupDetails).toHaveBeenCalledWith('task-1', {
            q: 'urgent',
            lifecycle: ['INCOMPLETE'],
            tag: 'platform',
            versions: ['2.0.0'],
            sort: 'id',
            order: 'asc',
        }, { limit: 1000 })
        expect(ensureFullGroup).not.toHaveBeenCalled()
        expect(bulk.showBulkModal.value).toBe(true)
        expect(bulk.displayedBulkIncompleteGroups.value).toEqual([group('CVE-1')])

        wrapper.unmount()
    })

    it('hydrates local fallback incomplete groups when no task is active', async () => {
        const { bulk, ensureFullGroup, wrapper } = mountHarness({
            incompleteGroups: [group('CVE-1'), group('CVE-2')],
            ensureFullGroup: async id => group(`${id}-full`),
        })

        await bulk.openBulkResolveModal()

        expect(ensureFullGroup).toHaveBeenCalledTimes(2)
        expect(ensureFullGroup).toHaveBeenCalledWith('CVE-1', { showLoading: false })
        expect(bulk.displayedBulkIncompleteGroups.value.map(item => item.id)).toEqual([
            'CVE-1-full',
            'CVE-2-full',
        ])

        wrapper.unmount()
    })

    it('clears fetched groups on close and reset', async () => {
        vi.mocked(drainTaskVulnGroupDetails).mockResolvedValue([group('CVE-1')])
        const { bulk, wrapper } = mountHarness({ taskId: 'task-1' })

        await bulk.openBulkResolveModal()
        bulk.closeBulkModal()

        expect(bulk.showBulkModal.value).toBe(false)
        expect(bulk.bulkIncompleteGroups.value).toBeNull()

        bulk.bulkModalLoading.value = true
        bulk.resetBulkResolveModal()

        expect(bulk.bulkModalLoading.value).toBe(false)
        expect(bulk.bulkIncompleteGroups.value).toBeNull()

        wrapper.unmount()
    })
})
