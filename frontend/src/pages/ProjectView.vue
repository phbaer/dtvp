<script setup lang="ts">
import { ref, watch, computed, inject, provide, onMounted, onUnmounted, onActivated, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { getGroupedVulns, getTeamMapping, getRescoreRules, getStatistics, getTaskStatistics, getTMRescoreProposals } from '../lib/api'
import type { TaskVulnGroupListQuery } from '../lib/api'
import { calculateScoreFromVector } from '../lib/cvss'
import { useCacheStatus } from '../lib/useCacheStatus'
import type { GroupedVuln, Statistics, TMRescoreProposal, TMRescoreProposalSnapshot } from '../types'
import { projectHeaderState } from '../lib/projectHeaderStore'
import { useProjectBulkResolve } from '../lib/useProjectBulkResolve'
import { useProjectVulnFilters } from '../lib/useProjectVulnFilters'
import {
    SEARCH_TOKEN_SHORTCUTS,
    useProjectVulnSearchControls,
} from '../lib/useProjectVulnSearchControls'
import { useProjectViewLayout } from '../lib/useProjectViewLayout'
import { useProjectAssessmentUpdates } from '../lib/useProjectAssessmentUpdates'
import { useProjectVulnSelection } from '../lib/useProjectVulnSelection'
import { useTaskGroupDetails } from '../lib/useTaskGroupDetails'
import { useTaskGroupWindows } from '../lib/useTaskGroupWindows'
import { useVisibleGroupWindow } from '../lib/useVisibleGroupWindow'
import type { DependencyRelationship, TMRescoreProposalFilter } from '../lib/vulnListIndex'
import {
    buildMeaningfulTMRescoreProposalIds,
    buildTaskVulnGroupListQuery,
} from '../lib/projectVulnTaskQuery'
import {
    buildActiveFilterChips,
    hasCustomProjectVulnFilterState,
    optionLabel,
    type ActiveFilterChipKey,
} from '../lib/projectVulnFilterChips'
import { createVulnListItemCache } from '../lib/vulnListItemCache'
import {
    deriveVulnListBaseIndex,
    deriveVulnListGroupLookup,
    deriveVulnListFilterModel,
    sortVulnListItems,
} from '../lib/vulnListViewModel'
import { deriveVulnListFacetsFromTaskCounts } from '../lib/vulnListFacets'

import VulnRowCompact from '../components/VulnRowCompact.vue'
import VulnDetailInspector from '../components/VulnDetailInspector.vue'
import BulkResolveIncompleteModal from '../components/BulkResolveIncompleteModal.vue'
import BulkApproveModal from '../components/BulkApproveModal.vue'
import ProjectStatistics from '../components/ProjectStatistics.vue'
import StatsSidebar from '../components/StatsSidebar.vue'
import { BarChart3, Loader2, Plus, Search, SlidersHorizontal, X } from 'lucide-vue-next'

const TASK_LIST_WINDOW_LIMIT = 250

const route = useRoute()
const router = useRouter()
const {
    selectedGroupId,
    selectGroup,
    closeSelectedGroup,
} = useProjectVulnSelection({
    route,
    router,
})
const user = inject<any>('user', { role: 'ANALYST' })
const currentUserRole = computed(() => (user?.value ?? user)?.role || 'ANALYST')
const groups = ref<GroupedVuln[]>([])
const currentVulnTaskId = ref<string | null>(null)
const loading = ref(true)
const error = ref('')
const loadingMessage = ref('Initializing...')
const loadingProgress = ref(0)
const loadingLog = ref<string[]>([])
const logContainer = ref<HTMLElement | null>(null)
const viewMode = projectHeaderState.viewMode
const stats = ref<Statistics | null>(null)
const statsLoading = ref(false)
const statsError = ref('')
const statsDirty = ref(false)
const {
    cacheStatus,
    cacheStatusText,
    cacheStatusState,
    cacheStatusLabel,
    cacheStatusAge,
    refreshCacheStatus: fetchCacheStatus,
} = useCacheStatus()

const teamMapping = ref<Record<string, string | string[]>>({})
provide('teamMapping', teamMapping)

const rescoreRules = ref<any>(null)
provide('rescoreRules', rescoreRules)

const tmrescoreProposalSnapshot = ref<TMRescoreProposalSnapshot | null>(null)
const emptyTMRescoreProposals: Record<string, TMRescoreProposal> = {}
const tmrescoreProposals = computed(() => tmrescoreProposalSnapshot.value?.proposals || emptyTMRescoreProposals)
const listItemCache = createVulnListItemCache()
provide('tmrescoreProposals', tmrescoreProposals)

const showBulkApproveModal = ref(false)

const TMRESCORE_FILTER_OPTIONS = [
    { value: 'WITH_PROPOSAL', label: 'with' },
    { value: 'WITHOUT_PROPOSAL', label: 'without' },
]

const fetchTeamMapping = async () => {
    try {
        teamMapping.value = await getTeamMapping()
    } catch (err) {
        console.error('Failed to fetch team mapping:', err)
    }
}

const fetchRescoreRules = async () => {
    try {
        rescoreRules.value = await getRescoreRules()
    } catch (err) {
        console.error('Failed to fetch rescore rules:', err)
    }
}

const consumeThreatModelRefreshSignal = () => {
    const name = route.params.name as string
    const sessionStorage = globalThis.window?.sessionStorage
    if (!name || name === '_all_' || !sessionStorage) {
        return false
    }

    const key = `dtvp:tmrescore-refresh:${name}`
    const hasSignal = !!sessionStorage.getItem(key)
    if (hasSignal) {
        sessionStorage.removeItem(key)
    }
    return hasSignal
}

const refreshThreatModelProposalsIfNeeded = async () => {
    if (!consumeThreatModelRefreshSignal()) {
        return
    }
    await fetchTMRescoreProposals()
}

const fetchTMRescoreProposals = async () => {
    const name = route.params.name as string
    if (!name || name === '_all_') {
        tmrescoreProposalSnapshot.value = null
        return
    }

    try {
        tmrescoreProposalSnapshot.value = await getTMRescoreProposals(name)
    } catch (err: any) {
        if (err?.response?.status === 404) {
            tmrescoreProposalSnapshot.value = null
            return
        }
        console.error('Failed to fetch threat-model proposals:', err)
        tmrescoreProposalSnapshot.value = null
    }
}

onMounted(() => {
    fetchTeamMapping()
    fetchRescoreRules()
})

onActivated(() => {
    void refreshThreatModelProposalsIfNeeded()
})

// Auto-scroll the loading log to the bottom when new entries appear
watch(() => loadingLog.value.length, () => {
    nextTick(() => {
        if (logContainer.value) {
            logContainer.value.scrollTop = logContainer.value.scrollHeight
        }
    })
})

const processFetchedGroups = async (data: GroupedVuln[]): Promise<GroupedVuln[]> => {
    if (!data || data.length === 0) return data

    loadingMessage.value = 'Finalizing vulnerability data...'
    const total = data.length
    const batchSize = Math.max(1, Math.ceil(total / 12))
    const result: GroupedVuln[] = []

    for (let start = 0; start < total; start += batchSize) {
        const batch = data.slice(start, start + batchSize).map(g => {
            if (g.cvss_vector && g.cvss_score == null && g.cvss == null) {
                const computed = calculateScoreFromVector(g.cvss_vector)
                if (computed !== null) {
                    g.cvss_score = computed
                    if (g.cvss == null) g.cvss = computed
                }
            }
            if (g.rescored_vector && g.rescored_cvss == null) {
                const computed = calculateScoreFromVector(g.rescored_vector)
                if (computed !== null) g.rescored_cvss = computed
            }
            return g
        })

        result.push(...batch)
        loadingProgress.value = 90 + Math.round(((start + batch.length) / total) * 10)
        await nextTick()
    }

    return result
}

const fetchVulns = async () => {
    let name = route.params.name as string
    if (!name) return
    
    const isAllProjects = name === '_all_'
    const apiName = isAllProjects ? '' : name

    loading.value = true
    error.value = ''
    loadingMessage.value = isAllProjects ? 'Starting global search...' : 'Starting search...'
    loadingProgress.value = 0
    loadingLog.value = []
    resetTaskGroupWindowState()
    resetTaskGroupDetails()
    resetBulkResolveModal()
    let releasedPartialList = false
    let reloadedCompletedList = false
    let lastPartialWindowVersionCount: number | null = null
    const reloadCompletedTaskWindow = async (taskId: string | null) => {
        if (!taskId || currentVulnTaskId.value !== taskId) return
        await loadTaskGroupWindow({ reset: true })
        reloadedCompletedList = true
    }

    try {
        const rawData = await getGroupedVulns(apiName, undefined, (msg, progress, log) => {
            loadingMessage.value = msg
            loadingProgress.value = progress
            if (log && log.length > 0) {
                loadingLog.value = log
            } else if (msg && (loadingLog.value.length === 0 || loadingLog.value[loadingLog.value.length - 1] !== msg)) {
                loadingLog.value.push(msg)
            }
        }, {
            responseMode: 'summary',
            deferResult: true,
            skipResultDownload: true,
            useEventStream: true,
            taskWindowLimit: TASK_LIST_WINDOW_LIMIT,
            onTaskId: (taskId) => {
                setCurrentVulnTaskId(taskId)
            },
            onPartialResultAvailable: async (taskId, status) => {
                if (!currentVulnTaskId.value || currentVulnTaskId.value !== taskId) return
                updateTaskGroupWindowStatus(status)
                const completed = status.partial_versions_completed ?? null
                if (releasedPartialList && completed !== null && completed === lastPartialWindowVersionCount) {
                    return
                }
                await loadTaskGroupWindow({ reset: true })
                lastPartialWindowVersionCount = taskListPartialVersionsCompleted.value ?? completed
                releasedPartialList = true
                loading.value = false
            },
            onTaskCompleted: async (taskId, status) => {
                updateTaskGroupWindowStatus(status)
                await reloadCompletedTaskWindow(taskId)
            },
        })

        if (currentVulnTaskId.value) {
            if (!reloadedCompletedList) {
                await reloadCompletedTaskWindow(currentVulnTaskId.value)
            }
        } else {
            groups.value = await processFetchedGroups(rawData)
        }
        if (selectedGroupId.value) {
            void hydrateVisibleGroup(selectedGroupId.value)
        }
        await fetchCacheStatus()
    } catch (err: any) {
        error.value = 'Failed to load vulnerabilities: ' + (err.message || err)
        console.error(err)
    } finally {
        loading.value = false
    }
}

const fetchStats = async () => {
    let name = route.params.name as string
    if (!name || name === '_all_') return

    statsLoading.value = true
    statsError.value = ''
    try {
        stats.value = currentVulnTaskId.value
            ? await getTaskStatistics(currentVulnTaskId.value)
            : await getStatistics(name, route.query.cve as string)
    } catch (err: any) {
        statsError.value = 'Failed to load statistics: ' + (err.message || err)
    } finally {
        statsLoading.value = false
    }
}

watch(() => viewMode.value, (newMode) => {
    if (newMode === 'statistics' && (!stats.value || statsDirty.value)) {
        fetchStats().finally(() => { statsDirty.value = false })
    }
})

onUnmounted(() => {
    listItemCache.clear()
})

// Expansion tracking removed — now handled by VulnRowCompact click → modal flow

const SORT_OPTIONS = [
    { value: 'severity', label: 'Original Criticality' },
    { value: 'rescored-severity', label: 'Rescored Criticality' },
    { value: 'score', label: 'Score' },
    { value: 'rescored', label: 'Rescored Score' },
    { value: 'analysis', label: 'Analysis' },
    { value: 'tags', label: 'Tags' },
    { value: 'id', label: 'CVE ID' },
] as const
const DEPENDENCY_OPTIONS = [
    { value: 'DIRECT', label: 'Direct' },
    { value: 'TRANSITIVE', label: 'Transitive' },
    { value: 'UNKNOWN', label: 'Unknown' },
] as const

const {
    smartSearchInput,
    flushSmartSearchFilter,
    parsedSmartSearch,
    liveParsedSmartSearch,
    tagFilter,
    idFilter,
    componentFilter,
    assigneeFilter,
    dependencyFilter,
    tmrescoreProposalFilter,
    cvssVersionMismatchOnly,
    attributionAgeDays,
    attributionAgeMode,
    lifecycleFilters,
    analysisFilters,
    filtersReady,
    sortBy,
    sortOrder,
    versionFilterInput,
    versionFilterList,
    selectedDependencyFilters,
    selectedTMRescoreProposalFilters,
    copiedUrl,
    copyFilterUrl,
    resetFilters,
    filterState,
    handleFilterUpdate,
    defaultLifecycleFilters,
    defaultAnalysisFilters,
} = useProjectVulnFilters({
    route,
    router,
    currentUserRole,
})

const meaningfulTMRescoreProposalIds = computed(() =>
    buildMeaningfulTMRescoreProposalIds(tmrescoreProposals.value)
)

const listItems = computed(() => {
    return listItemCache.build(
        groups.value,
        teamMapping.value,
        tmrescoreProposals.value,
    )
})

const listBaseIndex = computed(() => deriveVulnListBaseIndex(listItems.value))

const listFacets = computed(() => listBaseIndex.value.facets)

const listStaticStats = computed(() => listBaseIndex.value.staticStats)

const listGroupLookup = computed(() => listBaseIndex.value.groupLookup)

const showFilterDrawer = ref(false)

const LIFECYCLE_OPTIONS = [
    { value: 'OPEN', label: 'Open', color: 'bg-red-500', description: 'No global assessment AND at least one team assessment is missing' },
    { value: 'ASSESSED', label: 'Assessed', color: 'bg-green-600', description: 'Approved assessments with a global assessment' },
    { value: 'ASSESSED_LEGACY', label: 'Assessed (Legacy)', color: 'bg-sky-600', description: 'Legacy assessments without structured DTvP format' },
    { value: 'INCOMPLETE', label: 'Incomplete', color: 'bg-amber-500', description: 'Some assessment for some version is missing, the others are identical' },
    { value: 'INCONSISTENT', label: 'Inconsistent', color: 'bg-indigo-500', description: 'Different assessments for at least two versions; empty assessments don\'t count' },
    { value: 'NEEDS_APPROVAL', label: 'Needs Approval', color: 'bg-purple-500', description: 'When there\'s a need for an approval (flag)' }
]

const ANALYSIS_OPTIONS = [
    { value: 'NOT_SET', label: 'Not Set', color: 'bg-gray-500' },
    { value: 'EXPLOITABLE', label: 'Exploitable', color: 'bg-red-600' },
    { value: 'IN_TRIAGE', label: 'In Triage', color: 'bg-amber-500' },
    { value: 'RESOLVED', label: 'Resolved', color: 'bg-purple-500' },
    { value: 'FALSE_POSITIVE', label: 'False Positive', color: 'bg-teal-500' },
    { value: 'NOT_AFFECTED', label: 'Not Affected', color: 'bg-green-500' }
]

const allLifecycleFilterValues = computed(() => LIFECYCLE_OPTIONS.map(option => option.value))
const allAnalysisFilterValues = computed(() => ANALYSIS_OPTIONS.map(option => option.value))
const allDependencyFilterValues = computed(() => DEPENDENCY_OPTIONS.map(option => option.value as DependencyRelationship))
const allTMRescoreFilterValues = computed(() => TMRESCORE_FILTER_OPTIONS.map(option => option.value as TMRescoreProposalFilter))

const taskGroupListQuery = computed<TaskVulnGroupListQuery>(() => buildTaskVulnGroupListQuery({
    parsedSearch: parsedSmartSearch.value,
    filtersReady: filtersReady.value,
    lifecycleFilters: lifecycleFilters.value,
    defaultLifecycleFilters: defaultLifecycleFilters.value,
    analysisFilters: analysisFilters.value,
    defaultAnalysisFilters,
    tagFilter: tagFilter.value,
    idFilter: idFilter.value,
    componentFilter: componentFilter.value,
    assigneeFilter: assigneeFilter.value,
    dependencyFilters: selectedDependencyFilters.value,
    versionFilters: versionFilterList.value,
    cvssVersionMismatchOnly: cvssVersionMismatchOnly.value,
    attributionAgeDays: attributionAgeDays.value,
    attributionAgeMode: attributionAgeMode.value,
    tmrescoreFilters: selectedTMRescoreProposalFilters.value,
    allTMRescoreFilterValues: allTMRescoreFilterValues.value,
    meaningfulTMRescoreProposalIds: meaningfulTMRescoreProposalIds.value,
    sortBy: sortBy.value,
    sortOrder: sortOrder.value,
}))

const taskGroupListQueryKey = computed(() => JSON.stringify(taskGroupListQuery.value))

const {
    total: taskListTotal,
    filtered: taskListFiltered,
    counts: taskListCounts,
    partial: taskListPartial,
    partialVersionsCompleted: taskListPartialVersionsCompleted,
    partialVersionsTotal: taskListPartialVersionsTotal,
    windowLoading: taskListWindowLoading,
    appendLoading: taskListAppendLoading,
    windowError: taskListWindowError,
    hasMoreGroups: hasMoreTaskListGroups,
    reset: resetTaskGroupWindowState,
    setTaskId: setCurrentVulnTaskId,
    updateFromTaskStatus: updateTaskGroupWindowStatus,
    loadWindow: loadTaskGroupWindow,
} = useTaskGroupWindows({
    currentTaskId: currentVulnTaskId,
    groups,
    query: taskGroupListQuery,
    limit: TASK_LIST_WINDOW_LIMIT,
    processGroups: processFetchedGroups,
    onResetVisibleItems: () => resetVisibleItems(),
})

const taskWideFacets = computed(() => {
    if (!currentVulnTaskId.value || !taskListCounts.value) {
        return listFacets.value
    }

    const counts = taskListCounts.value.all
    const facets = deriveVulnListFacetsFromTaskCounts(counts)
    return {
        ...facets,
        ids: counts.ids ? facets.ids : listFacets.value.ids,
    }
})

const availableVersions = computed(() => {
    return [...taskWideFacets.value.availableVersions]
        .sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))
})

const {
    showSearchTokenMenu,
    setSearchInput,
    activeCompletionIndex,
    smartSearchChips,
    currentSearchCompletions,
    showSearchCompletions,
    updateSearchCursorPosition,
    handleSearchFocus,
    handleSearchBlur,
    handleSearchKeydown,
    selectSearchCompletion,
    appendSearchToken,
    removeSmartSearchChip,
    clearSmartSearch,
} = useProjectVulnSearchControls({
    smartSearchInput,
    liveParsedSmartSearch,
    flushSmartSearchFilter,
    facets: taskWideFacets,
    lifecycleOptions: LIFECYCLE_OPTIONS,
    analysisOptions: ANALYSIS_OPTIONS,
    dependencyOptions: DEPENDENCY_OPTIONS,
})

const isTaskWindowListActive = computed(() => !!currentVulnTaskId.value)

const listView = computed(() => deriveVulnListFilterModel(listItems.value, {
    smartSearch: parsedSmartSearch.value,
    tagFilter: tagFilter.value,
    idFilter: idFilter.value,
    componentFilter: componentFilter.value,
    assigneeFilter: assigneeFilter.value,
    dependencyFilter: selectedDependencyFilters.value,
    tmrescoreProposalFilter: selectedTMRescoreProposalFilters.value,
    versionFilterList: versionFilterList.value,
    cvssVersionMismatchOnly: cvssVersionMismatchOnly.value,
    attributionAgeDays: attributionAgeDays.value,
    attributionAgeMode: attributionAgeMode.value,
    lifecycleFilters: lifecycleFilters.value,
    analysisFilters: analysisFilters.value,
}, listStaticStats.value))

const sortedItems = computed(() =>
    isTaskWindowListActive.value
        ? listItems.value
        : sortVulnListItems(listView.value.matchingItems, sortBy.value, sortOrder.value)
)

const sortedGroupLookup = computed(() => deriveVulnListGroupLookup(sortedItems.value))

const filteredGroups = computed(() => sortedGroupLookup.value.groups)

const filteredGroupCount = computed(() =>
    currentVulnTaskId.value && taskListFiltered.value != null
        ? taskListFiltered.value
        : sortedItems.value.length
)

const loadedGroupCount = computed(() => sortedItems.value.length)

const totalGroupCount = computed(() =>
    currentVulnTaskId.value && taskListTotal.value != null
        ? taskListTotal.value
        : listItems.value.length
)

const taskListPartialProgress = computed(() => {
    const completed = taskListPartialVersionsCompleted.value
    const total = taskListPartialVersionsTotal.value
    if (completed == null || total == null || total <= 0) return null
    return Math.min(100, Math.round((completed / total) * 100))
})

const showTaskListStatus = computed(() =>
    isTaskWindowListActive.value
    && !loading.value
    && (taskListPartial.value || taskListWindowLoading.value)
)

const taskListStatusMessage = computed(() => {
    if (taskListWindowLoading.value) {
        return 'Refreshing filtered results...'
    }
    if (taskListPartial.value) {
        const completed = taskListPartialVersionsCompleted.value
        const total = taskListPartialVersionsTotal.value
        if (completed != null && total != null) {
            return `Grouping still running. Counts are based on ${completed}/${total} versions.`
        }
        return 'Grouping still running. Counts will update automatically.'
    }
    return ''
})

const filterCounts = computed(() => {
    const counts = taskListCounts.value
    if (currentVulnTaskId.value && counts) {
        return {
            ...counts.all.lifecycle,
            ...counts.filtered.analysis,
        }
    }
    return listView.value.filterCounts
})

const cvssVersionMismatchCount = computed(() =>
    currentVulnTaskId.value && taskListCounts.value
        ? taskListCounts.value.all.cvss_version_mismatch
        : listStaticStats.value.cvssVersionMismatchCount
)

const teamTagCounts = computed(() =>
    currentVulnTaskId.value && taskListCounts.value?.all.team_tags
        ? taskListCounts.value.all.team_tags
        : listStaticStats.value.teamTagCounts
)

const teamTagList = computed(() => {
    return Object.entries(teamTagCounts.value)
        .map(([team, counts]) => ({ team, ...counts }))
        .sort((a, b) => a.team.localeCompare(b.team))
})

const dependencyFilterCounts = computed(() =>
    currentVulnTaskId.value && taskListCounts.value
        ? taskListCounts.value.filtered.dependency_relationship
        : listView.value.dependencyFilterCounts
)

const dependencyRelationshipCounts = computed(() =>
    currentVulnTaskId.value && taskListCounts.value
        ? taskListCounts.value.filtered.dependency_relationship
        : listView.value.dependencyRelationshipCounts
)

const tmrescoreProposalCounts = computed(() =>
    currentVulnTaskId.value && taskListCounts.value?.filtered.tmrescore
        ? taskListCounts.value.filtered.tmrescore
        : listView.value.tmrescoreProposalCounts
)

const attributionAgeCount = computed(() =>
    currentVulnTaskId.value && taskListCounts.value?.filtered.attribution_age != null
        ? taskListCounts.value.filtered.attribution_age
        : listView.value.attributionAgeCount
)

const analysisCounts = computed(() =>
    currentVulnTaskId.value && taskListCounts.value
        ? taskListCounts.value.filtered.analysis
        : listView.value.analysisCounts
)

const needsApprovalGroups = computed(() => listStaticStats.value.needsApprovalGroups)

const incompleteGroups = computed(() => listStaticStats.value.incompleteGroups)

const selectedListGroup = computed(() => {
    if (!selectedGroupId.value) return null
    return sortedGroupLookup.value.groupById.get(selectedGroupId.value) || null
})

const findListGroup = (groupId: string) =>
    listGroupLookup.value.groupById.get(groupId) || null

const {
    fullGroupCache,
    selectedGroup,
    selectedGroupLoading,
    reset: resetTaskGroupDetails,
    cacheGroup: cacheFullGroup,
    ensureFullGroup,
    hydrateGroup: hydrateVisibleGroup,
} = useTaskGroupDetails({
    currentTaskId: currentVulnTaskId,
    selectedGroupId,
    selectedListGroup,
    findListGroup,
})

const {
    handleLocalAssessmentUpdate,
    handleBulkUpdates,
    handleTeamMappingUpdated,
} = useProjectAssessmentUpdates({
    groups,
    fullGroupCache,
    cacheFullGroup,
    teamMapping,
    statsDirty,
    viewMode,
    fetchStats,
    isTaskWindowActive: isTaskWindowListActive,
    refreshTaskWindow: () => loadTaskGroupWindow({ reset: true }),
})

const {
    showBulkModal,
    bulkModalLoading,
    displayedBulkIncompleteGroups,
    openBulkResolveModal,
    closeBulkModal,
    resetBulkResolveModal,
} = useProjectBulkResolve({
    currentTaskId: currentVulnTaskId,
    incompleteGroups,
    ensureFullGroup,
})

projectHeaderState.bulkSyncHandler.value = () => {
    void openBulkResolveModal()
}

const handleBulkResolveUpdates = (updates: Array<{ id: string; data: any }>) => {
    handleBulkUpdates(updates, closeBulkModal)
}

const handleBulkApproveModalUpdates = (updates: Array<{ id: string; data: any }>) => {
    handleBulkUpdates(updates, () => { showBulkApproveModal.value = false })
}

const {
    isDesktopInspector,
    isDesktopDetailOpen,
    isFilterRailVisible,
} = useProjectViewLayout({
    viewMode,
    selectedGroup,
    selectedGroupLoading,
})

const isAnalysisViewActive = computed(() => viewMode.value === 'analysis' && !loading.value && !error.value)
const isAnalysisWorkspaceActive = isAnalysisViewActive
const {
    visibleItems: visibleListItems,
    visibleEndIndex,
    virtualPaddingTop,
    virtualPaddingBottom,
    scrollContainer: listScrollContainer,
    resetVisibleItems,
} = useVisibleGroupWindow({
    items: sortedItems,
    isActive: isAnalysisViewActive,
    batchSize: 40,
    estimatedItemHeight: 88,
    overscan: 8,
})

const setListScrollContainer = (element: any) => {
    listScrollContainer.value = element as HTMLElement | null
}

watch(selectedGroupId, (groupId) => {
    if (groupId) {
        void hydrateVisibleGroup(groupId)
    }
})

watch(isFilterRailVisible, (visible) => {
    if (visible) showFilterDrawer.value = false
})

watch(() => viewMode.value, () => {
    showFilterDrawer.value = false
})

watch(sortedItems, (items, previousItems) => {
    const isAppendingTaskWindow = !!currentVulnTaskId.value
        && taskListAppendLoading.value
        && items.length >= (previousItems?.length || 0)
    if (!isAppendingTaskWindow) {
        resetVisibleItems()
    }
    if (selectedGroupId.value && !selectedListGroup.value && !currentVulnTaskId.value) {
        closeSelectedGroup()
    } else if (selectedGroupId.value && !selectedGroup.value) {
        void hydrateVisibleGroup(selectedGroupId.value)
    }
})

watch(taskGroupListQueryKey, () => {
    if (!currentVulnTaskId.value || loading.value) return
    void loadTaskGroupWindow({ reset: true })
})

watch([visibleEndIndex, loadedGroupCount, hasMoreTaskListGroups], () => {
    if (!isAnalysisViewActive.value || !hasMoreTaskListGroups.value) return
    if (taskListWindowLoading.value || taskListAppendLoading.value) return
    if (visibleEndIndex.value >= loadedGroupCount.value - 20) {
        void loadTaskGroupWindow({ reset: false })
    }
})

defineExpose({ filteredGroups })

const activeFilterChips = computed(() => buildActiveFilterChips({
    lifecycleFilters: lifecycleFilters.value,
    lifecycleOptions: LIFECYCLE_OPTIONS,
    analysisFilters: analysisFilters.value,
    analysisOptions: ANALYSIS_OPTIONS,
    dependencyFilters: selectedDependencyFilters.value,
    dependencyOptions: DEPENDENCY_OPTIONS,
    idFilter: idFilter.value,
    tagFilter: tagFilter.value,
    componentFilter: componentFilter.value,
    assigneeFilter: assigneeFilter.value,
    versionFilters: versionFilterList.value,
    tmrescoreFilters: selectedTMRescoreProposalFilters.value,
    tmrescoreOptions: TMRESCORE_FILTER_OPTIONS,
    cvssVersionMismatchOnly: cvssVersionMismatchOnly.value,
    attributionAgeDays: attributionAgeDays.value,
    attributionAgeMode: attributionAgeMode.value,
}))

const removeActiveFilterChip = (key: ActiveFilterChipKey) => {
    switch (key) {
        case 'lifecycle':
            lifecycleFilters.value = allLifecycleFilterValues.value
            break
        case 'analysis':
            analysisFilters.value = allAnalysisFilterValues.value
            break
        case 'dependency':
            dependencyFilter.value = allDependencyFilterValues.value
            break
        case 'id':
            idFilter.value = ''
            break
        case 'tag':
            tagFilter.value = ''
            break
        case 'component':
            componentFilter.value = ''
            break
        case 'assignee':
            assigneeFilter.value = ''
            break
        case 'versions':
            versionFilterInput.value = ''
            break
        case 'tmrescore':
            tmrescoreProposalFilter.value = allTMRescoreFilterValues.value
            break
        case 'cvss':
            cvssVersionMismatchOnly.value = false
            break
        case 'attributionAge':
            attributionAgeDays.value = null
            attributionAgeMode.value = 'older'
            break
    }
}

const hasCustomFilterState = computed(() => hasCustomProjectVulnFilterState({
    smartSearchInput: smartSearchInput.value,
    idFilter: idFilter.value,
    tagFilter: tagFilter.value,
    componentFilter: componentFilter.value,
    assigneeFilter: assigneeFilter.value,
    versionFilters: versionFilterList.value,
    cvssVersionMismatchOnly: cvssVersionMismatchOnly.value,
    attributionAgeDays: attributionAgeDays.value,
    sortBy: sortBy.value,
    sortOrder: sortOrder.value,
    lifecycleFilters: lifecycleFilters.value,
    defaultLifecycleFilters: defaultLifecycleFilters.value,
    analysisFilters: analysisFilters.value,
    defaultAnalysisFilters,
    dependencyFilters: selectedDependencyFilters.value,
    defaultDependencyFilters: allDependencyFilterValues.value,
    tmrescoreFilters: selectedTMRescoreProposalFilters.value,
    defaultTMRescoreFilters: allTMRescoreFilterValues.value,
}))

const filterSidebarProps = computed(() => ({
    filters: filterState.value,
    filterCounts: filterCounts.value,
    availableVersions: availableVersions.value,
    lifecycleOptions: LIFECYCLE_OPTIONS,
    analysisOptions: ANALYSIS_OPTIONS,
    copiedUrl: copiedUrl.value,
    filteredCount: filteredGroupCount.value,
    dependencyCounts: dependencyRelationshipCounts.value,
    dependencyFilterCounts: dependencyFilterCounts.value,
    tmrescoreCounts: tmrescoreProposalCounts.value,
    analysisCounts: analysisCounts.value,
    teamTagList: teamTagList.value,
    cacheStatusState: cacheStatusState.value,
    cacheStatusLabel: cacheStatusLabel.value,
    cacheStatusAge: cacheStatusAge.value,
    cacheStatusTooltip: cacheStatusText.value,
    cacheStatusDetail: cacheStatus.value,
    sortOptions: SORT_OPTIONS,
    dependencyOptions: DEPENDENCY_OPTIONS,
    tmrescoreOptions: TMRESCORE_FILTER_OPTIONS,
    cvssVersionMismatchCount: cvssVersionMismatchCount.value,
    attributionRangeCount: attributionAgeCount.value,
}))

const syncProjectHeaderState = () => {
    const name = route.params.name as string
    projectHeaderState.currentProjectName.value = name === '_all_' ? null : name
    projectHeaderState.isAllProjects.value = name === '_all_'
    projectHeaderState.isReviewer.value = currentUserRole.value === 'REVIEWER'
    projectHeaderState.incompleteCount.value = needsApprovalGroups.value.length
}

watch(() => route.params.name, () => {
    syncProjectHeaderState()
    fetchVulns()
    fetchTMRescoreProposals()
    if (viewMode.value === 'statistics') {
        fetchStats()
    } else {
        stats.value = null // Reset stats to force refresh if they toggle back
    }
}, { immediate: true })

watch(() => needsApprovalGroups.value.length, (length) => {
    projectHeaderState.incompleteCount.value = length
}, { immediate: true })

watch(currentUserRole, (role) => {
    projectHeaderState.isReviewer.value = (role || 'ANALYST') === 'REVIEWER'
}, { immediate: true })
</script>

<template>
  <div
      :class="[
          'overflow-x-visible min-h-0',
          isAnalysisWorkspaceActive
              ? 'flex h-full flex-col overflow-visible'
              : ''
      ]"
  >
    <div
        v-if="viewMode === 'analysis' && !loading && !error"
        class="relative z-30 mb-3 shrink-0 rounded-2xl border border-white/10 bg-gray-900/85 p-2 shadow-xl shadow-black/20 backdrop-blur-2xl"
        @keydown.esc="showSearchTokenMenu = false"
    >
        <div class="flex flex-col gap-2">
            <div class="flex items-center gap-2">
                <button
                    v-if="!isFilterRailVisible"
                    type="button"
                    title="Open filters"
                    class="inline-flex h-10 shrink-0 items-center gap-2 rounded-xl border border-white/10 bg-slate-950/35 px-3 text-xs font-semibold uppercase tracking-wider text-slate-200 transition-colors hover:bg-slate-900/55 hover:text-white"
                    @click="showFilterDrawer = true"
                >
                    <SlidersHorizontal :size="15" />
                    <span class="hidden sm:inline">Filters</span>
                </button>
                <div class="relative min-w-0 flex-1">
                    <Search :size="16" class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                    <input
                        :ref="setSearchInput"
                        v-model="smartSearchInput"
                        type="search"
                        class="h-10 w-full rounded-xl border border-white/10 bg-slate-950/45 pl-9 pr-9 text-sm font-medium text-gray-100 outline-none transition-colors placeholder:text-gray-600 focus:border-blue-500/50 focus:bg-slate-950/65"
                        placeholder="Search CVE, component, team, assignee, version..."
                        @focus="handleSearchFocus"
                        @blur="handleSearchBlur"
                        @input="updateSearchCursorPosition"
                        @click="updateSearchCursorPosition"
                        @keyup="updateSearchCursorPosition"
                        @keydown="handleSearchKeydown"
                    />
                    <button
                        v-if="smartSearchInput"
                        type="button"
                        class="absolute right-2 top-1/2 inline-flex h-6 w-6 -translate-y-1/2 items-center justify-center rounded-lg text-gray-400 transition-colors hover:bg-white/10 hover:text-white"
                        title="Clear search"
                        @click="clearSmartSearch"
                    >
                        <X :size="13" />
                        <span class="sr-only">Clear search</span>
                    </button>
                    <div
                        v-if="showSearchCompletions"
                        class="absolute left-0 right-0 top-[calc(100%+0.5rem)] z-50 max-h-64 overflow-y-auto rounded-xl border border-white/10 bg-gray-950/95 p-1 shadow-2xl backdrop-blur-xl"
                    >
                        <button
                            v-for="(completion, index) in currentSearchCompletions"
                            :key="`${completion.detail}-${completion.value}`"
                            type="button"
                            :class="[
                                'flex w-full items-center justify-between gap-3 rounded-lg px-3 py-2 text-left transition-colors',
                                activeCompletionIndex === index
                                    ? 'bg-blue-500/15 text-white'
                                    : 'text-gray-300 hover:bg-white/10 hover:text-white'
                            ]"
                            @mouseenter="activeCompletionIndex = index"
                            @mousedown.prevent="selectSearchCompletion(completion)"
                        >
                            <span class="min-w-0 truncate text-sm font-semibold">{{ completion.label }}</span>
                            <span class="shrink-0 rounded bg-white/5 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-gray-500">
                                {{ completion.detail }}
                            </span>
                        </button>
                    </div>
                </div>
                <div class="relative shrink-0">
                    <button
                        type="button"
                        title="Insert search filter"
                        class="inline-flex h-10 items-center gap-2 rounded-xl border border-white/10 bg-slate-950/35 px-3 text-xs font-semibold uppercase tracking-wider text-slate-200 transition-colors hover:bg-slate-900/55 hover:text-white"
                        @click="showSearchTokenMenu = !showSearchTokenMenu"
                    >
                        <Plus :size="14" />
                        <span class="hidden sm:inline">Filter</span>
                    </button>
                    <div
                        v-if="showSearchTokenMenu"
                        class="absolute right-0 top-[calc(100%+0.5rem)] z-50 w-52 overflow-hidden rounded-xl border border-white/10 bg-gray-950/95 p-1 shadow-2xl backdrop-blur-xl"
                    >
                        <button
                            v-for="shortcut in SEARCH_TOKEN_SHORTCUTS"
                            :key="shortcut.value"
                            type="button"
                            class="flex w-full items-center justify-between rounded-lg px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-gray-300 transition-colors hover:bg-white/10 hover:text-white"
                            @click="appendSearchToken(shortcut.value)"
                        >
                            <span>{{ shortcut.label }}</span>
                            <span class="text-[10px] text-gray-500">{{ shortcut.value }}</span>
                        </button>
                    </div>
                </div>
                <div class="hidden shrink-0 text-right text-[11px] leading-tight text-gray-400 md:block">
                    <div><span class="font-semibold text-white">{{ filteredGroupCount }}</span> matched</div>
                    <div>{{ loadedGroupCount }} loaded · {{ totalGroupCount }} total<span v-if="taskListPartial"> · provisional</span></div>
                </div>
                <button
                    v-if="hasCustomFilterState"
                    type="button"
                    class="hidden h-10 shrink-0 rounded-xl border border-white/10 bg-slate-950/35 px-3 text-xs font-semibold uppercase tracking-wider text-gray-400 transition-colors hover:bg-white/10 hover:text-white sm:inline-flex sm:items-center"
                    @click="resetFilters"
                >
                    Reset
                </button>
            </div>
            <div class="flex max-h-24 flex-wrap gap-1.5 overflow-y-auto pr-1">
                <span class="rounded-full border border-blue-400/20 bg-blue-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-blue-200">
                    {{ optionLabel(sortBy, SORT_OPTIONS) }} · {{ sortOrder.toUpperCase() }}
                </span>
                <span
                    v-for="(chip, index) in smartSearchChips"
                    :key="`${chip.raw}-${index}`"
                    class="inline-flex max-w-full items-center gap-1 rounded-full border border-cyan-400/20 bg-cyan-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-cyan-100"
                >
                    <span class="truncate">{{ chip.label }}</span>
                    <button
                        type="button"
                        class="shrink-0 rounded-full text-cyan-200/70 transition-colors hover:bg-cyan-300/15 hover:text-white"
                        title="Remove search token"
                        @click="removeSmartSearchChip(index)"
                    >
                        <X :size="10" />
                        <span class="sr-only">Remove {{ chip.label }}</span>
                    </button>
                </span>
                <span
                    v-for="chip in activeFilterChips"
                    :key="chip.key"
                    class="inline-flex max-w-full items-center gap-1 rounded-full border border-white/10 bg-white/5 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-gray-300"
                >
                    <span class="truncate">{{ chip.label }}</span>
                    <button
                        type="button"
                        class="shrink-0 rounded-full text-gray-400 transition-colors hover:bg-white/10 hover:text-white"
                        title="Remove filter"
                        @click="removeActiveFilterChip(chip.key)"
                    >
                        <X :size="10" />
                        <span class="sr-only">Remove {{ chip.label }}</span>
                    </button>
                </span>
                <button
                    v-if="hasCustomFilterState"
                    type="button"
                    class="rounded-full border border-white/10 bg-slate-950/30 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-gray-400 transition-colors hover:bg-white/10 hover:text-white sm:hidden"
                    @click="resetFilters"
                >
                    Reset
                </button>
            </div>
        </div>
    </div>

    <div
        :class="[
            'grid min-w-full w-full gap-y-4',
            isAnalysisWorkspaceActive
                ? 'min-h-0 flex-1 overflow-hidden pt-0 pb-0'
                : 'pt-2.5 lg:pt-0 pb-8',
            viewMode === 'analysis'
                ? (isDesktopDetailOpen
                    ? (isFilterRailVisible
                        ? 'lg:grid-cols-[20rem_30rem_minmax(48rem,1fr)] lg:items-start lg:gap-x-4'
                        : 'lg:grid-cols-[30rem_minmax(48rem,1fr)] lg:items-start lg:gap-x-3')
                    : (isFilterRailVisible
                        ? 'lg:grid-cols-[20rem_minmax(0,1fr)] lg:items-start lg:gap-x-4'
                        : 'lg:grid-cols-[minmax(0,1fr)] lg:items-start'))
                : 'lg:grid-cols-[minmax(0,1fr)]'
        ]"
    >
        <div
            v-if="viewMode === 'analysis' && isFilterRailVisible"
            class="block h-full min-h-0 w-[20rem] overflow-y-auto"
        >
            <StatsSidebar
                v-bind="filterSidebarProps"
                @update:filters="handleFilterUpdate"
                @copy-filter-url="copyFilterUrl"
            />
        </div>

        <div
            :class="[
                'min-w-0 max-w-full w-full pl-0 lg:pl-0',
                isAnalysisWorkspaceActive ? 'h-full min-h-0 overflow-hidden' : '',
                isDesktopDetailOpen ? 'lg:w-[30rem] lg:min-w-[30rem] lg:max-w-[30rem] lg:pr-0' : ''
            ]"
        >
            <div class="hidden"></div>
            <div v-if="loading" class="text-center py-10">
                <div class="mb-2 text-xl font-semibold">{{ loadingMessage }}</div>
                <div class="w-full max-w-md mx-auto bg-gray-700 rounded-full h-4 relative overflow-hidden">
                    <div v-if="loadingProgress <= 1" class="bg-blue-500/60 h-4 w-1/3 rounded-full animate-pulse"></div>
                    <div v-else class="bg-blue-500 h-4 transition-all duration-300" :style="{ width: loadingProgress + '%' }"></div>
                </div>
                <div class="mt-2 text-sm text-gray-400">{{ loadingProgress > 1 ? loadingProgress + '%' : '' }}</div>
                <div v-if="loadingLog.length > 0" ref="logContainer" class="mt-4 w-full max-w-md mx-auto bg-gray-900 border border-gray-700 rounded-lg p-3 max-h-40 overflow-y-auto text-left">
                    <div v-for="(entry, i) in loadingLog" :key="i" class="text-xs font-mono text-gray-400 py-0.5">
                        <span class="text-gray-600 select-none">{{ String(i + 1).padStart(2, '0') }}</span> {{ entry }}
                    </div>
                </div>
            </div>
            <div v-else-if="error" class="text-red-500 text-center py-10">{{ error }}</div>
            <div
                v-else
                :class="[
                    'shadow-xl bg-white/2 border border-white/5 rounded-2xl backdrop-blur-sm overflow-hidden',
                    isAnalysisWorkspaceActive ? 'h-full min-h-0' : ''
                ]"
            >
                <div :class="viewMode === 'analysis' ? 'flex h-full min-h-0 flex-col p-2' : 'p-3 space-y-3'">
                    <div
                        v-if="showTaskListStatus"
                        class="mb-2 rounded-xl border border-blue-400/20 bg-blue-500/10 px-3 py-2 text-xs text-blue-100"
                    >
                        <div class="flex items-center justify-between gap-3">
                            <div class="inline-flex min-w-0 items-center gap-2">
                                <Loader2
                                    v-if="taskListWindowLoading"
                                    :size="14"
                                    class="shrink-0 animate-spin"
                                />
                                <span class="truncate">{{ taskListStatusMessage }}</span>
                            </div>
                            <span
                                v-if="taskListPartialProgress !== null"
                                class="shrink-0 font-semibold tabular-nums text-blue-50"
                            >
                                {{ taskListPartialProgress }}%
                            </span>
                        </div>
                        <div
                            v-if="taskListPartialProgress !== null"
                            class="mt-2 h-1.5 overflow-hidden rounded-full bg-blue-950/70"
                        >
                            <div
                                class="h-full rounded-full bg-blue-300 transition-all duration-300"
                                :style="{ width: `${taskListPartialProgress}%` }"
                            ></div>
                        </div>
                    </div>
                    <div
                        v-if="viewMode === 'analysis'"
                        :ref="setListScrollContainer"
                        class="min-h-0 flex-1 overflow-y-auto pr-1"
                    >
                        <template v-if="filteredGroupCount > 0">
                            <div
                                aria-hidden="true"
                                class="shrink-0"
                                :style="{ height: `${virtualPaddingTop}px` }"
                            ></div>
                            <div class="space-y-2">
                                <VulnRowCompact
                                    v-for="item in visibleListItems"
                                    :key="item.id"
                                    :item="item"
                                    :selected="selectedGroupId === item.id"
                                    :data-group-id="item.id"
                                    @select="selectGroup"
                                    @update="handleTeamMappingUpdated"
                                    @update:assessment="(data) => handleLocalAssessmentUpdate(item.group, data)"
                                />
                            </div>
                            <div
                                aria-hidden="true"
                                class="shrink-0"
                                :style="{ height: `${virtualPaddingBottom}px` }"
                            ></div>
                            <div v-if="taskListWindowError" class="py-3 text-center text-xs font-semibold text-red-300">
                                {{ taskListWindowError }}
                            </div>
                            <div
                                v-if="hasMoreTaskListGroups || taskListAppendLoading"
                                class="flex justify-center py-4"
                            >
                                <button
                                    type="button"
                                    class="inline-flex h-10 items-center gap-2 rounded-xl border border-white/10 bg-slate-950/40 px-4 text-xs font-semibold uppercase tracking-wider text-slate-200 transition-colors hover:bg-slate-900/70 hover:text-white disabled:cursor-wait disabled:opacity-60"
                                    :disabled="taskListAppendLoading"
                                    @click="loadTaskGroupWindow({ reset: false })"
                                >
                                    <Loader2 v-if="taskListAppendLoading" :size="14" class="animate-spin" />
                                    <span>{{ taskListAppendLoading ? 'Loading more' : `Load more (${loadedGroupCount}/${filteredGroupCount})` }}</span>
                                </button>
                            </div>
                        </template>
                        <div v-if="filteredGroupCount === 0" class="text-gray-500 text-center py-16 font-medium min-h-[20rem] w-full min-w-full">No vulnerabilities found matching criteria.</div>
                    </div>
                    <div v-else class="space-y-4">
                        <div v-if="statsLoading" class="text-center py-16">
                            <div class="animate-pulse flex flex-col items-center">
                                <BarChart3 :size="48" class="text-blue-500 mb-4" />
                                <div class="text-xl font-black text-gray-300 uppercase tracking-tight">Calculating metrics...</div>
                            </div>
                        </div>
                        <div v-else-if="statsError" class="text-red-500 text-center py-16">{{ statsError }}</div>
                        <ProjectStatistics v-else-if="stats" :stats="stats" :projectName="($route.params.name as string)" />
                    </div>
                </div>
            </div>
        </div>

        <div
            v-if="isDesktopDetailOpen"
            class="hidden h-full min-h-0 min-w-[48rem] overflow-hidden lg:block"
        >
            <div
                v-if="selectedGroupLoading && !selectedGroup"
                class="flex h-full items-center justify-center rounded-2xl border border-white/5 bg-gray-900/40 text-xs font-semibold uppercase tracking-wide text-gray-500"
            >
                Loading vulnerability details...
            </div>
            <VulnDetailInspector
                v-else-if="selectedGroup"
                :group="selectedGroup"
                class="h-full"
                @close="closeSelectedGroup"
                @update="handleTeamMappingUpdated"
                @update:assessment="(data) => selectedGroup && handleLocalAssessmentUpdate(selectedGroup, data)"
            />
        </div>
    </div>

    <Teleport to="body">
        <div
            v-if="(selectedGroup || selectedGroupLoading) && viewMode === 'analysis' && !isDesktopInspector"
            class="fixed inset-0 z-[60] bg-gray-950/95 p-2"
        >
            <div
                v-if="selectedGroupLoading && !selectedGroup"
                class="flex h-full items-center justify-center text-xs font-semibold uppercase tracking-wide text-gray-500"
            >
                Loading vulnerability details...
            </div>
            <VulnDetailInspector
                v-else-if="selectedGroup"
                :group="selectedGroup"
                @close="closeSelectedGroup"
                @update="handleTeamMappingUpdated"
                @update:assessment="(data) => selectedGroup && handleLocalAssessmentUpdate(selectedGroup, data)"
            />
        </div>
    </Teleport>

    <Teleport to="body">
        <div
            v-if="showFilterDrawer"
            class="fixed inset-0 z-[70]"
        >
            <button
                type="button"
                class="absolute inset-0 bg-gray-950/80 backdrop-blur-sm"
                title="Close filters"
                @click="showFilterDrawer = false"
            >
                <span class="sr-only">Close filters</span>
            </button>
            <aside class="absolute inset-y-0 left-0 w-[min(26rem,calc(100vw-1rem))] overflow-y-auto border-r border-white/10 bg-gray-950 p-2 shadow-2xl">
                <div class="mb-2 flex items-center justify-between gap-3 px-1">
                    <div class="text-xs font-semibold uppercase tracking-widest text-gray-400">Filters</div>
                    <button
                        type="button"
                        class="inline-flex h-8 w-8 items-center justify-center rounded border border-white/10 bg-white/5 text-gray-300 transition-colors hover:bg-white/10 hover:text-white"
                        title="Close filters"
                        @click="showFilterDrawer = false"
                    >
                        <X :size="14" />
                        <span class="sr-only">Close filters</span>
                    </button>
                </div>
                <StatsSidebar
                    v-bind="filterSidebarProps"
                    @update:filters="handleFilterUpdate"
                    @copy-filter-url="copyFilterUrl"
                />
            </aside>
        </div>
    </Teleport>

    <BulkResolveIncompleteModal
        :show="showBulkModal"
        :incomplete-groups="displayedBulkIncompleteGroups"
        @close="closeBulkModal"
        @updated="handleBulkResolveUpdates"
    />

    <Teleport to="body">
        <div
            v-if="bulkModalLoading"
            class="fixed inset-0 z-[9999] flex items-center justify-center bg-gray-950/70 backdrop-blur-sm"
        >
            <div class="flex items-center gap-3 rounded border border-white/10 bg-gray-950 px-4 py-3 text-sm font-semibold text-gray-100 shadow-2xl">
                <Loader2 class="animate-spin text-amber-300" :size="18" />
                Preparing bulk sync...
            </div>
        </div>
    </Teleport>

    <BulkApproveModal
        :show="showBulkApproveModal"
        :needs-approval-groups="needsApprovalGroups"
        @close="showBulkApproveModal = false"
        @updated="handleBulkApproveModalUpdates"
    />
  </div>
</template>
