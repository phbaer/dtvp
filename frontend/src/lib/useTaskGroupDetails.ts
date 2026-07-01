import { computed, ref, type ComputedRef, type Ref } from 'vue'
import { getTaskVulnGroup } from './api'
import { isSummaryGroupedVuln } from './vulnListSummary'
import type { GroupedVuln } from '../types'

interface UseTaskGroupDetailsOptions {
    currentTaskId: Ref<string | null>
    selectedGroupId: Ref<string | null>
    selectedListGroup: ComputedRef<GroupedVuln | null>
    findListGroup: (groupId: string) => GroupedVuln | null
}

export function useTaskGroupDetails({
    currentTaskId,
    selectedGroupId,
    selectedListGroup,
    findListGroup,
}: UseTaskGroupDetailsOptions) {
    const fullGroupCache = ref<Record<string, GroupedVuln>>({})
    const selectedGroupLoading = ref(false)
    const fullGroupRequests = new Map<string, Promise<GroupedVuln | null>>()
    let cacheGeneration = 0

    const cacheGroup = (group: GroupedVuln) => {
        if (isSummaryGroupedVuln(group)) return
        fullGroupCache.value = {
            ...fullGroupCache.value,
            [group.id]: group,
        }
    }

    const reset = () => {
        cacheGeneration++
        fullGroupCache.value = {}
        fullGroupRequests.clear()
        selectedGroupLoading.value = false
    }

    const selectedGroup = computed(() => {
        if (!selectedGroupId.value) return null
        const cached = fullGroupCache.value[selectedGroupId.value]
        if (cached) return cached
        const listGroup = selectedListGroup.value
        return isSummaryGroupedVuln(listGroup) ? null : listGroup
    })

    const ensureFullGroup = async (
        groupId: string,
        options: { showLoading?: boolean } = {},
    ): Promise<GroupedVuln | null> => {
        if (fullGroupCache.value[groupId]) return fullGroupCache.value[groupId]

        const listGroup = findListGroup(groupId)
        const taskId = currentTaskId.value

        if (!taskId && !isSummaryGroupedVuln(listGroup)) {
            return listGroup || null
        }

        if (!taskId) return listGroup || null

        if (listGroup && !isSummaryGroupedVuln(listGroup)) {
            return listGroup
        }

        const existingRequest = fullGroupRequests.get(groupId)
        const showLoading = options.showLoading !== false
        if (existingRequest) {
            if (!showLoading) return existingRequest
            selectedGroupLoading.value = true
            try {
                return await existingRequest
            } finally {
                selectedGroupLoading.value = false
            }
        }

        const generation = cacheGeneration
        if (showLoading) selectedGroupLoading.value = true
        const request = getTaskVulnGroup(taskId, groupId)
            .then((fullGroup) => {
                if (generation !== cacheGeneration || currentTaskId.value !== taskId) {
                    return null
                }
                cacheGroup(fullGroup)
                return fullGroup
            })
            .catch((err) => {
                if (generation === cacheGeneration) {
                    console.error('Failed to fetch vulnerability details:', err)
                }
                return generation === cacheGeneration ? listGroup || null : null
            })
            .finally(() => {
                if (fullGroupRequests.get(groupId) === request) {
                    fullGroupRequests.delete(groupId)
                }
                if (showLoading && generation === cacheGeneration) {
                    selectedGroupLoading.value = false
                }
            })

        fullGroupRequests.set(groupId, request)
        return request
    }

    const hydrateGroup = async (groupId: string): Promise<GroupedVuln | null> => {
        return ensureFullGroup(groupId)
    }

    return {
        fullGroupCache,
        selectedGroup,
        selectedGroupLoading,
        reset,
        cacheGroup,
        ensureFullGroup,
        hydrateGroup,
    }
}
