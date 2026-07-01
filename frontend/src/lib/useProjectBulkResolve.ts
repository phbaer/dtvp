import { computed, ref, type ComputedRef, type Ref } from 'vue'
import { drainTaskVulnGroupDetails } from './api'
import type { GroupedVuln } from '../types'

interface UseProjectBulkResolveOptions {
    currentTaskId: Ref<string | null>
    incompleteGroups: ComputedRef<GroupedVuln[]> | Ref<GroupedVuln[]>
    ensureFullGroup: (
        groupId: string,
        options?: { showLoading?: boolean },
    ) => Promise<GroupedVuln | null>
}

export function useProjectBulkResolve({
    currentTaskId,
    incompleteGroups,
    ensureFullGroup,
}: UseProjectBulkResolveOptions) {
    const showBulkModal = ref(false)
    const bulkModalLoading = ref(false)
    const bulkIncompleteGroups = ref<GroupedVuln[] | null>(null)

    const displayedBulkIncompleteGroups = computed(() =>
        bulkIncompleteGroups.value || incompleteGroups.value
    )

    const resetBulkResolveModal = () => {
        bulkIncompleteGroups.value = null
        bulkModalLoading.value = false
    }

    const openBulkResolveModal = async () => {
        if (bulkModalLoading.value) return

        bulkModalLoading.value = true
        try {
            bulkIncompleteGroups.value = null
            const taskId = currentTaskId.value
            if (taskId) {
                bulkIncompleteGroups.value = await drainTaskVulnGroupDetails(taskId, {
                    lifecycle: ['INCOMPLETE'],
                    sort: 'id',
                    order: 'asc',
                }, { limit: 1000 })
            } else {
                const fullGroups = await Promise.all(
                    incompleteGroups.value.map(group => ensureFullGroup(group.id, { showLoading: false })),
                )
                bulkIncompleteGroups.value = fullGroups.filter((group): group is GroupedVuln => !!group)
            }
            showBulkModal.value = true
        } finally {
            bulkModalLoading.value = false
        }
    }

    const closeBulkModal = () => {
        showBulkModal.value = false
        bulkIncompleteGroups.value = null
    }

    return {
        showBulkModal,
        bulkModalLoading,
        bulkIncompleteGroups,
        displayedBulkIncompleteGroups,
        openBulkResolveModal,
        closeBulkModal,
        resetBulkResolveModal,
    }
}
