import { computed, ref, type ComputedRef, type Ref } from 'vue'
import { getTaskVulnGroups } from './api'
import type { TaskResponse, TaskVulnGroupListQuery, TaskVulnGroupListResponse } from './api'
import type { GroupedVuln } from '../types'

type MaybePromise<T> = T | Promise<T>

interface UseTaskGroupWindowsOptions {
    currentTaskId: Ref<string | null>
    groups: Ref<GroupedVuln[]>
    query: ComputedRef<TaskVulnGroupListQuery>
    limit: number
    processGroups?: (groups: GroupedVuln[]) => MaybePromise<GroupedVuln[]>
    onResetVisibleItems?: () => void
}

export function useTaskGroupWindows({
    currentTaskId,
    groups,
    query,
    limit,
    processGroups = groups => groups,
    onResetVisibleItems,
}: UseTaskGroupWindowsOptions) {
    const total = ref<number | null>(null)
    const filtered = ref<number | null>(null)
    const counts = ref<TaskVulnGroupListResponse['counts'] | null>(null)
    const nextCursor = ref<string | null>(null)
    const partial = ref(false)
    const partialVersionsCompleted = ref<number | null>(null)
    const partialVersionsTotal = ref<number | null>(null)
    const windowLoading = ref(false)
    const appendLoading = ref(false)
    const windowError = ref('')
    let requestId = 0

    const hasMoreGroups = computed(() =>
        !!currentTaskId.value &&
        (nextCursor.value != null ||
            (filtered.value != null && groups.value.length < filtered.value))
    )

    const clearWindowMetadata = () => {
        total.value = null
        filtered.value = null
        counts.value = null
        nextCursor.value = null
        partial.value = false
        partialVersionsCompleted.value = null
        partialVersionsTotal.value = null
        windowError.value = ''
    }

    const reset = () => {
        currentTaskId.value = null
        clearWindowMetadata()
        windowLoading.value = false
        appendLoading.value = false
        requestId++
    }

    const setTaskId = (taskId: string | null) => {
        if (currentTaskId.value === taskId) return
        currentTaskId.value = taskId
        clearWindowMetadata()
        requestId++
    }

    const updateFromTaskStatus = (status: Pick<TaskResponse, 'status' | 'partial_result_available' | 'partial_versions_completed' | 'partial_total_versions'>) => {
        if (status.status === 'completed' || status.status === 'failed') {
            partial.value = false
            partialVersionsCompleted.value = null
            partialVersionsTotal.value = null
            return
        }

        if (!status.partial_result_available) return

        partial.value = true
        partialVersionsCompleted.value = status.partial_versions_completed ?? partialVersionsCompleted.value
        partialVersionsTotal.value = status.partial_total_versions ?? partialVersionsTotal.value
    }

    const loadWindow = async (options: { reset?: boolean } = {}) => {
        const taskId = currentTaskId.value
        if (!taskId) return

        const shouldReset = options.reset !== false
        if (shouldReset) {
            windowLoading.value = true
            windowError.value = ''
        } else {
            if (appendLoading.value || !hasMoreGroups.value) return
            appendLoading.value = true
        }

        const activeRequestId = ++requestId
        const pageQuery: TaskVulnGroupListQuery = {
            ...query.value,
            limit,
        }
        if (shouldReset) {
            pageQuery.offset = 0
            nextCursor.value = null
        } else if (nextCursor.value) {
            pageQuery.cursor = nextCursor.value
        } else {
            pageQuery.offset = groups.value.length
        }

        try {
            const window = await getTaskVulnGroups(taskId, {
                ...pageQuery,
            })
            if (activeRequestId !== requestId) return

            const processedGroups = await processGroups(window.items || [])
            if (activeRequestId !== requestId) return

            groups.value = shouldReset ? processedGroups : [...groups.value, ...processedGroups]
            total.value = window.total
            filtered.value = window.filtered
            counts.value = window.counts || null
            nextCursor.value = window.next_cursor || null
            partial.value = !!window.partial
            partialVersionsCompleted.value = window.partial_versions_completed ?? null
            partialVersionsTotal.value = window.partial_total_versions ?? null
            if (shouldReset) onResetVisibleItems?.()
        } catch (err: any) {
            if (activeRequestId !== requestId) return
            windowError.value = 'Failed to load vulnerability window: ' + (err.message || err)
            console.error(err)
        } finally {
            if (activeRequestId === requestId) {
                windowLoading.value = false
                appendLoading.value = false
            }
        }
    }

    return {
        currentTaskId,
        total,
        filtered,
        counts,
        nextCursor,
        partial,
        partialVersionsCompleted,
        partialVersionsTotal,
        windowLoading,
        appendLoading,
        windowError,
        hasMoreGroups,
        reset,
        setTaskId,
        updateFromTaskStatus,
        loadWindow,
    }
}
