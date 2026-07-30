import type { Ref } from 'vue'
import type { GroupedVuln } from '../types'
import { isSummaryGroupedVuln, summarizeGroupForList } from './vulnListSummary'

export interface ProjectAssessmentUpdate {
    id: string
    data: any
}

interface UseProjectAssessmentUpdatesOptions {
    groups: Ref<GroupedVuln[]>
    fullGroupCache: Ref<Record<string, GroupedVuln>>
    cacheFullGroup: (group: GroupedVuln) => void
    teamMapping: Ref<Record<string, string | string[]>>
    statsDirty: Ref<boolean>
    viewMode: Ref<string>
    fetchStats: () => Promise<unknown>
    isTaskWindowActive?: Ref<boolean>
    refreshTaskWindow?: () => Promise<unknown> | unknown
}

export const applyAssessmentDataToGroup = (group: GroupedVuln, data: any): GroupedVuln => ({
    ...group,
    rescored_cvss: data.rescored_cvss,
    rescored_vector: data.rescored_vector,
    assignees: data.assignees !== undefined ? data.assignees : group.assignees,
    affected_versions: group.affected_versions.map((version: any) => ({
        ...version,
        components: version.components.map((instance: any) => {
            const persistenceResult = data.dtvp_results?.find(
                (result: any) => result.uuid === instance.finding_uuid,
            )
            return {
                ...instance,
                analysis_state: data.analysis_state,
                analysis_details: data.analysis_details,
                is_suppressed: data.is_suppressed,
                justification: data.justification,
                dtvp_revision: persistenceResult?.revision ?? instance.dtvp_revision,
                dtvp_sync_status: persistenceResult?.sync_status
                    || (persistenceResult?.queued ? 'pending' : instance.dtvp_sync_status),
                dtvp_update_id: persistenceResult?.update_id ?? instance.dtvp_update_id,
                dtvp_sync_error: persistenceResult ? null : instance.dtvp_sync_error,
            }
        }),
    })),
})

export function useProjectAssessmentUpdates({
    groups,
    fullGroupCache,
    cacheFullGroup,
    teamMapping,
    statsDirty,
    viewMode,
    fetchStats,
    isTaskWindowActive,
    refreshTaskWindow,
}: UseProjectAssessmentUpdatesOptions) {
    const refreshStatsIfVisible = (context: string) => {
        statsDirty.value = true
        if (viewMode.value !== 'statistics') return

        fetchStats()
            .then(() => { statsDirty.value = false })
            .catch((err) => {
                console.error(`Failed to refresh statistics after ${context}`, err)
            })
    }

    const refreshTaskWindowIfActive = (context: string) => {
        if (!isTaskWindowActive?.value || !refreshTaskWindow) return

        try {
            Promise.resolve(refreshTaskWindow()).catch((err) => {
                console.error(`Failed to refresh task window after ${context}`, err)
            })
        } catch (err) {
            console.error(`Failed to refresh task window after ${context}`, err)
        }
    }

    const updateListSummaryFromGroup = (
        group: GroupedVuln,
        options: { recompute?: boolean } = {},
    ) => {
        const idx = groups.value.findIndex((entry: any) => entry.id === group.id)
        if (idx === -1) return

        groups.value[idx] = isSummaryGroupedVuln(group) && !options.recompute
            ? group
            : summarizeGroupForList(group, teamMapping.value)
        groups.value = [...groups.value]
    }

    const handleLocalAssessmentUpdate = (
        group: GroupedVuln,
        data: any,
        options: { refreshStats?: boolean; refreshTaskWindow?: boolean } = {},
    ) => {
        const sourceGroup = fullGroupCache.value[group.id] || group
        const updatedGroup = applyAssessmentDataToGroup(sourceGroup, data)
        if (!isSummaryGroupedVuln(updatedGroup)) {
            cacheFullGroup(updatedGroup)
        }
        updateListSummaryFromGroup(updatedGroup, { recompute: true })

        if (options.refreshStats !== false) {
            refreshStatsIfVisible('assessment update')
        }
        if (options.refreshTaskWindow !== false) {
            refreshTaskWindowIfActive('assessment update')
        }
    }

    const handleBulkUpdates = (
        updates: ProjectAssessmentUpdate[],
        onComplete?: () => void,
    ) => {
        for (const update of updates) {
            const group = fullGroupCache.value[update.id] || groups.value.find(entry => entry.id === update.id)
            if (group) {
                handleLocalAssessmentUpdate(group, update.data, {
                    refreshStats: false,
                    refreshTaskWindow: false,
                })
            }
        }

        refreshStatsIfVisible('bulk assessment updates')
        refreshTaskWindowIfActive('bulk assessment updates')
        onComplete?.()
    }

    const replaceGroup = (updatedGroup: GroupedVuln) => {
        if (!isSummaryGroupedVuln(updatedGroup)) {
            cacheFullGroup(updatedGroup)
        }
        updateListSummaryFromGroup(updatedGroup)
    }

    const handleTeamMappingUpdated = async (updatedGroup?: GroupedVuln) => {
        if (updatedGroup) {
            replaceGroup(updatedGroup)
        }

        refreshStatsIfVisible('team mapping update')
        refreshTaskWindowIfActive('team mapping update')
    }

    return {
        applyAssessmentDataToGroup,
        updateListSummaryFromGroup,
        handleLocalAssessmentUpdate,
        handleBulkUpdates,
        replaceGroup,
        handleTeamMappingUpdated,
    }
}
