<script setup lang="ts">
import { ref, watch, computed, inject, provide, onMounted, onUnmounted, onActivated, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
    getGroupedVulns,
    getAssessmentDetails,
    getProjectArchiveTaskDownloadUrl,
    getRescoreRules,
    getStatistics,
    getTaskStatistics,
    getTeamMapping,
    getTMRescoreProposals,
    startProjectArchiveExport,
    waitForProjectArchiveTask,
} from '../lib/api'
import type { BulkWorkflowApplyResponse, TaskResponse, TaskVulnGroupListCounts, TaskVulnGroupListQuery } from '../lib/api'
import { calculateScoreFromVector } from '../lib/cvss'
import { useCacheStatus } from '../lib/useCacheStatus'
import type { GroupedVuln, ProjectArchiveTask, Statistics, TMRescoreProposal, TMRescoreProposalSnapshot } from '../types'
import { projectHeaderState } from '../lib/projectHeaderStore'
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
import {
    hasAutomaticAssessmentForGroup,
    automaticAssessmentStatusForGroup,
    type AutomaticAssessmentFilter,
    type DependencyRelationship,
    type TMRescoreProposalFilter,
} from '../lib/vulnListIndex'
import {
    buildMeaningfulTMRescoreProposalIds,
    buildTaskVulnGroupListQuery,
    createEmptyTaskVulnGroupListCounts,
} from '../lib/projectVulnTaskQuery'
import {
    buildActiveFilterChips,
    hasCustomProjectVulnFilterState,
    optionLabel,
    type ActiveFilterChipKey,
} from '../lib/projectVulnFilterChips'
import { createVulnListItemCache } from '../lib/vulnListItemCache'
import { deriveVulnListFacetsFromTaskCounts } from '../lib/vulnListFacets'
import { INCONSISTENCY_REASON_OPTIONS } from '../lib/inconsistency'

import VulnRowCompact from '../components/VulnRowCompact.vue'
import VulnDetailInspector from '../components/VulnDetailInspector.vue'
import BulkWorkflowModal from '../components/BulkWorkflowModal.vue'
import ProjectStatistics from '../components/ProjectStatistics.vue'
import StatsSidebar from '../components/StatsSidebar.vue'
import { Archive, BarChart3, Download, Loader2, Plus, Search, SlidersHorizontal, X } from 'lucide-vue-next'
import {
    DEFAULT_VULNERABILITY_BACKEND,
    VULNERABILITY_BACKEND_KEY,
    backendSupports,
} from '../lib/vulnerabilityBackend'

const TASK_LIST_WINDOW_LIMIT = 250

const route = useRoute()
const router = useRouter()

const routeProjectName = () => {
    const value = route.params.name
    if (Array.isArray(value)) return value[0] || ''
    return typeof value === 'string' ? value : ''
}

const isProjectReviewRouteActive = () => {
    const name = routeProjectName()
    if (!name) return false

    const path = route.path || ''
    if (!path) return true
    return /^\/project\/[^/]+\/?$/.test(path) || /^\/projects\/[^/]+\/[^/]+\/?$/.test(path)
}

const {
    selectedGroupId,
    selectGroup,
    closeSelectedGroup,
    syncSelectedGroupFromRoute,
} = useProjectVulnSelection({
    route,
    router,
    isRouteActive: isProjectReviewRouteActive,
})
const detailInspectorRef = ref<{ confirmApplyDraftBeforeLeave?: () => Promise<boolean> } | null>(null)

const confirmSelectedDraftBeforeLeave = async () =>
    detailInspectorRef.value?.confirmApplyDraftBeforeLeave?.() ?? true

const selectGroupWithDraftGuard = async (group: GroupedVuln) => {
    if (selectedGroupId.value && selectedGroupId.value !== group.id) {
        const canLeave = await confirmSelectedDraftBeforeLeave()
        if (!canLeave) return
    }
    selectGroup(group)
}

const closeSelectedGroupWithDraftGuard = async () => {
    if (!await confirmSelectedDraftBeforeLeave()) return
    closeSelectedGroup()
}
const user = inject<any>('user', { role: 'ANALYST' })
const currentUserRole = computed(() => (user?.value ?? user)?.role || 'ANALYST')
const vulnerabilityBackend = inject(
    VULNERABILITY_BACKEND_KEY,
    computed(() => DEFAULT_VULNERABILITY_BACKEND),
)
const canExportArchives = computed(() => backendSupports(
    vulnerabilityBackend.value,
    'finding_read',
    'sbom_read',
    'assessment_read',
))
const groups = ref<GroupedVuln[]>([])
const currentVulnTaskId = ref<string | null>(null)
const loadedProjectName = ref<string | null>(null)
const loadingProjectName = ref<string | null>(null)
const loading = ref(true)
const error = ref('')
const loadingMessage = ref('Initializing...')
const loadingProgress = ref(0)
const loadingLog = ref<string[]>([])
const archiveExporting = ref(false)
const archiveExportMessage = ref('')
const archiveExportError = ref('')
const archiveExportTask = ref<ProjectArchiveTask | null>(null)
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

const showBulkWorkflowModal = ref(false)

const appendLoadingLog = (message: string) => {
    if (!message) return
    if (loadingLog.value[loadingLog.value.length - 1] === message) return
    loadingLog.value.push(message)
}

const setLoadingStep = (message: string, progress?: number) => {
    loadingMessage.value = message
    if (typeof progress === 'number') {
        loadingProgress.value = Math.max(
            loadingProgress.value || 0,
            Math.max(0, Math.min(100, Math.round(progress))),
        )
    }
    appendLoadingLog(message)
}

const archiveExportProgress = computed(() => {
    const progress = archiveExportTask.value?.progress ?? 0
    return Math.max(0, Math.min(100, progress))
})

const archiveExportDownloadUrl = computed(() => {
    if (archiveExportTask.value?.status !== 'completed') return ''
    return getProjectArchiveTaskDownloadUrl(archiveExportTask.value.id)
})

const TMRESCORE_FILTER_OPTIONS = [
    { value: 'WITH_PROPOSAL', label: 'with' },
    { value: 'WITHOUT_PROPOSAL', label: 'without' },
]
const AUTOMATIC_ASSESSMENT_FILTER_OPTIONS: Array<{ value: AutomaticAssessmentFilter; label: string }> = [
    { value: 'WITH_AUTOMATIC_ASSESSMENT', label: 'available' },
    { value: 'WITHOUT_AUTOMATIC_ASSESSMENT', label: 'missing' },
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
    const name = routeProjectName()
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
    const name = routeProjectName()
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

const processFetchedGroups = async (data: GroupedVuln[]): Promise<GroupedVuln[]> => {
    if (!data || data.length === 0) return data

    setLoadingStep('Finalizing vulnerability data...', 90)
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
        const completed = Math.min(total, start + batch.length)
        setLoadingStep(
            `Finalized ${completed}/${total} vulnerabilities...`,
            90 + Math.round((completed / total) * 10),
        )
        await nextTick()
    }

    return result
}

let fetchVulnsRequestId = 0

const fetchVulns = async () => {
    const name = routeProjectName()
    if (!name || !isProjectReviewRouteActive()) return
    
    const isAllProjects = name === '_all_'
    const apiName = isAllProjects ? '' : name
    const requestId = ++fetchVulnsRequestId
    const isCurrentRequest = () => requestId === fetchVulnsRequestId

    loadingProjectName.value = name
    loadedProjectName.value = null
    loading.value = true
    error.value = ''
    loadingMessage.value = isAllProjects ? 'Starting global search...' : 'Starting search...'
    loadingProgress.value = 0
    loadingLog.value = []
    resetTaskGroupWindowState()
    resetTaskGroupDetails()
    showBulkWorkflowModal.value = false
    let releasedPartialList = false
    let reloadedCompletedList = false
    let lastPartialWindowVersionCount: number | null = null
    let partialWindowRefreshInFlight = false
    let queuedPartialWindow: { taskId: string; status: TaskResponse } | null = null
    const loadInitialTaskWindow = async (message: string, progress: number) => {
        setLoadingStep(message, progress)
        await loadTaskGroupWindow({ reset: true })
    }
    const reloadCompletedTaskWindow = async (taskId: string | null) => {
        if (!taskId || currentVulnTaskId.value !== taskId) return
        reloadedCompletedList = true
        await loadInitialTaskWindow('Loading final vulnerability list window...', 96)
    }
    const runQueuedPartialWindowRefresh = () => {
        if (partialWindowRefreshInFlight) return
        partialWindowRefreshInFlight = true
        void (async () => {
            try {
                while (queuedPartialWindow && !reloadedCompletedList) {
                    const request = queuedPartialWindow
                    queuedPartialWindow = null
                    if (!currentVulnTaskId.value || currentVulnTaskId.value !== request.taskId) {
                        continue
                    }
                    await loadInitialTaskWindow(
                        'Loading partial vulnerability list window...',
                        Math.max(1, request.status.progress ?? loadingProgress.value),
                    )
                    if (!currentVulnTaskId.value || currentVulnTaskId.value !== request.taskId || reloadedCompletedList) {
                        continue
                    }
                    lastPartialWindowVersionCount = taskListPartialVersionsCompleted.value
                        ?? request.status.partial_versions_completed
                        ?? null
                    releasedPartialList = true
                    loading.value = false
                }
            } finally {
                partialWindowRefreshInFlight = false
            }
        })()
    }
    const schedulePartialWindowRefresh = (taskId: string, status: TaskResponse) => {
        if (!currentVulnTaskId.value || currentVulnTaskId.value !== taskId) return
        const completed = status.partial_versions_completed ?? null
        if (releasedPartialList && completed !== null && completed === lastPartialWindowVersionCount) {
            return
        }
        queuedPartialWindow = { taskId, status }
        runQueuedPartialWindowRefresh()
    }

    try {
        const rawData = await getGroupedVulns(apiName, undefined, (msg, progress, log) => {
            if (!isCurrentRequest()) return
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
                if (!isCurrentRequest()) return
                setCurrentVulnTaskId(taskId)
            },
            onPartialResultAvailable: (taskId, status) => {
                if (!isCurrentRequest()) return
                if (!currentVulnTaskId.value || currentVulnTaskId.value !== taskId) return
                updateTaskGroupWindowStatus(status)
                schedulePartialWindowRefresh(taskId, status)
            },
            onTaskCompleted: async (taskId, status) => {
                if (!isCurrentRequest()) return
                updateTaskGroupWindowStatus(status)
                queuedPartialWindow = null
                await reloadCompletedTaskWindow(taskId)
            },
        })

        if (!isCurrentRequest()) return
        if (currentVulnTaskId.value) {
            if (!reloadedCompletedList) {
                await reloadCompletedTaskWindow(currentVulnTaskId.value)
            }
        } else {
            // Kept only for compatibility with older API mocks and servers.
            // Production filtering, counting, and sorting always use task windows.
            groups.value = await processFetchedGroups(rawData)
        }
        if (!isCurrentRequest()) return
        loadedProjectName.value = name
        if (selectedGroupId.value) {
            void hydrateVisibleGroup(selectedGroupId.value)
        }
        await fetchCacheStatus()
    } catch (err: any) {
        if (!isCurrentRequest()) return
        error.value = 'Failed to load vulnerabilities: ' + (err.message || err)
        console.error(err)
    } finally {
        if (isCurrentRequest()) {
            loading.value = false
            loadingProjectName.value = null
        }
    }
}

const fetchStats = async () => {
    const name = routeProjectName()
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
    projectHeaderState.bulkWorkflowHandler.value = null
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
    inconsistencyReasonFilters,
    analysisFilters,
    filtersReady,
    sortBy,
    sortOrder,
    versionFilterInput,
    versionFilterList,
    selectedDependencyFilters,
    selectedTMRescoreProposalFilters,
    selectedAutomaticAssessmentFilters,
    copiedUrl,
    copyFilterUrl,
    resetFilters,
    filterState,
    handleFilterUpdate,
    defaultLifecycleFilters,
    defaultAnalysisFilters,
    automaticAssessmentFilter,
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

const listGroupLookup = computed(() => ({
    groups: listItems.value.map(item => item.group),
    groupById: new Map(listItems.value.map(item => [item.id, item.group])),
}))

const showFilterDrawer = ref(false)

const LIFECYCLE_OPTIONS = [
    { value: 'OPEN', label: 'Open', color: 'bg-red-500', description: 'No global assessment AND at least one team assessment is missing' },
    { value: 'ASSESSED', label: 'Assessed', color: 'bg-green-600', description: 'Approved assessments with a global assessment' },
    { value: 'ASSESSED_LEGACY', label: 'Assessed (Legacy)', color: 'bg-sky-600', description: 'Legacy assessments without structured DTvP format' },
    { value: 'INCOMPLETE', label: 'Incomplete', color: 'bg-amber-500', description: 'Some assessment for some version is missing, the others are identical' },
    { value: 'INCONSISTENT', label: 'Inconsistent', color: 'bg-indigo-500', description: 'Assessment states, team blocks, details, or rescoring metadata disagree' },
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
const allAutomaticAssessmentFilterValues = computed(() => AUTOMATIC_ASSESSMENT_FILTER_OPTIONS.map(option => option.value))

const taskGroupListQuery = computed<TaskVulnGroupListQuery>(() => buildTaskVulnGroupListQuery({
    parsedSearch: parsedSmartSearch.value,
    filtersReady: filtersReady.value,
    lifecycleFilters: lifecycleFilters.value,
    inconsistencyReasonFilters: inconsistencyReasonFilters.value,
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
    automaticAssessmentFilters: selectedAutomaticAssessmentFilters.value,
    allAutomaticAssessmentFilterValues: allAutomaticAssessmentFilterValues.value,
    automaticAssessmentIds: [],
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
    partialPublishInProgress: taskListPartialPublishInProgress,
    versionsCompleted: taskListVersionsCompleted,
    versionsTotal: taskListVersionsTotal,
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
    const counts = taskListCounts.value?.all ?? createEmptyTaskVulnGroupListCounts()
    return deriveVulnListFacetsFromTaskCounts(counts)
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

// Task windows arrive filtered and sorted by the backend. The frontend only
// indexes the visible window for rendering and detail selection.
const sortedItems = listItems

const sortedGroupLookup = listGroupLookup

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
    const completed = taskListVersionsCompleted.value ?? taskListPartialVersionsCompleted.value
    const total = taskListVersionsTotal.value ?? taskListPartialVersionsTotal.value
    if (completed == null || total == null || total <= 0) return null
    return Math.min(100, Math.round((completed / total) * 100))
})

const loadingProgressPercent = computed(() =>
    Math.max(0, Math.min(100, Math.round(loadingProgress.value || 0)))
)

const loadingProgressTitle = computed(() =>
    loadingLog.value.length > 0
        ? loadingLog.value.slice(-5).join('\n')
        : loadingMessage.value
)

const preparingListDetailMessage = computed(() => {
    if (taskListWindowLoading.value) {
        return loadingMessage.value || 'Loading vulnerability list window...'
    }
    return loadingMessage.value || 'Preparing vulnerability list...'
})

const preparingListLog = computed(() =>
    loadingLog.value
        .filter(entry => entry && entry !== preparingListDetailMessage.value)
        .slice(-3)
)

const preparingListProgressLabel = computed(() => {
    if (taskListPartialProgress.value !== null) {
        return `${taskListPartialProgress.value}%`
    }
    if (loadingProgressPercent.value > 1 && loadingProgressPercent.value < 100) {
        return `${loadingProgressPercent.value}%`
    }
    return ''
})

const preparingListProgressWidth = computed(() => {
    if (taskListPartialProgress.value !== null) {
        return taskListPartialProgress.value
    }
    if (loadingProgressPercent.value > 1 && loadingProgressPercent.value < 100) {
        return loadingProgressPercent.value
    }
    return null
})

const showPreparingListStatus = computed(() =>
    viewMode.value === 'analysis'
    && filteredGroupCount.value === 0
    && loading.value
    && !error.value
)

const showLoadingStatus = computed(() =>
    viewMode.value === 'analysis'
    && loading.value
    && !error.value
    && !showPreparingListStatus.value
)

const showTaskListStatus = computed(() =>
    isTaskWindowListActive.value
    && !loading.value
    && (taskListPartial.value || taskListWindowLoading.value)
)

const taskListStatusMessage = computed(() => {
    if (taskListWindowLoading.value) {
        const fetched = taskListVersionsCompleted.value
        const fetchedTotal = taskListVersionsTotal.value ?? taskListPartialVersionsTotal.value
        const completed = taskListPartialVersionsCompleted.value
        const total = taskListPartialVersionsTotal.value
        if (
            taskListPartial.value
            && completed != null
            && total != null
            && completed >= total
        ) {
            return 'All project-version snapshots are loaded; preparing the final grouped result.'
        }
        if (taskListPartial.value && fetched != null && fetchedTotal != null) {
            return `Preparing the visible partial result window. `
                + `Backend has loaded ${fetched} of ${fetchedTotal} project versions.`
        }
        if (taskListPartial.value && completed != null && total != null) {
            return `Preparing the visible partial result window for ${completed} of ${total} project versions.`
        }
        return 'Preparing the visible vulnerability window...'
    }
    if (taskListPartial.value) {
        const completed = taskListPartialVersionsCompleted.value
        const total = taskListPartialVersionsTotal.value
        if (completed != null && total != null) {
            if (completed >= total) {
                return 'All project-version snapshots are loaded; preparing the final grouped result.'
            }
            const fetched = taskListVersionsCompleted.value
            const fetchedTotal = taskListVersionsTotal.value ?? total
            if (fetched != null && fetchedTotal === total && fetched >= total) {
                return `Visible results cover ${completed} of ${total} project versions. `
                    + 'All version snapshots are loaded; preparing the final grouped result.'
            }
            if (fetched != null && fetchedTotal === total && fetched > completed) {
                return `Visible results cover ${completed} of ${total} project versions. `
                    + `Backend has loaded ${fetched} of ${total}; preparing the next visible window.`
            }
            if (taskListPartialPublishInProgress.value) {
                return `Preparing a visible result window for ${completed} of ${total} project versions.`
            }
            const remaining = Math.max(0, total - completed)
            return `Visible results cover ${completed} of ${total} project versions. `
                + `${remaining} project-version snapshots are still loading.`
        }
        return 'Vulnerability grouping is still loading project-version snapshots.'
    }
    return ''
})

const visibleResultCounts = computed<TaskVulnGroupListCounts>(() =>
    taskListCounts.value?.filtered ?? createEmptyTaskVulnGroupListCounts()
)

const resultCountsUpdating = computed(() =>
    !!currentVulnTaskId.value && taskListWindowLoading.value
)

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
    hydrateGroup: hydrateVisibleGroup,
    refreshGroup: refreshTaskGroupDetail,
} = useTaskGroupDetails({
    currentTaskId: currentVulnTaskId,
    selectedGroupId,
    selectedListGroup,
    findListGroup,
})

const refreshActiveTaskWindowAndDetails = async () => {
    await loadTaskGroupWindow({ reset: true })
    if (selectedGroupId.value) {
        await refreshTaskGroupDetail(selectedGroupId.value, { showLoading: false })
    }
}

const selectedGroupHasAutomaticAssessment = computed(() =>
    selectedGroup.value
        ? hasAutomaticAssessmentForGroup(selectedGroup.value)
        : false
)
const selectedGroupAutomaticAssessmentStatus = computed(() =>
    selectedGroup.value
        ? automaticAssessmentStatusForGroup(selectedGroup.value)
        : null
)

const {
    handleLocalAssessmentUpdate,
    handleBulkUpdates,
    handleTeamMappingUpdated,
    replaceGroup,
} = useProjectAssessmentUpdates({
    groups,
    fullGroupCache,
    cacheFullGroup,
    teamMapping,
    statsDirty,
    viewMode,
    fetchStats,
    isTaskWindowActive: isTaskWindowListActive,
    refreshTaskWindow: refreshActiveTaskWindowAndDetails,
})

const reloadingGroupIds = ref<Set<string>>(new Set())
const groupReloadErrors = ref<Record<string, string>>({})

const setGroupReloading = (groupId: string, reloading: boolean) => {
    const next = new Set(reloadingGroupIds.value)
    if (reloading) next.add(groupId)
    else next.delete(groupId)
    reloadingGroupIds.value = next
}

const assessmentIdentity = (value: any) => [
    value?.project_uuid,
    value?.component_uuid,
    value?.vulnerability_uuid,
].map(part => String(part || '')).join('\u0000')

const applyReloadedAssessmentDetails = (group: GroupedVuln, results: any[]): GroupedVuln => {
    const byFindingId = new Map<string, any>()
    const byIdentity = new Map<string, any>()
    for (const result of results) {
        if (!result?.analysis || result.error) continue
        if (result.finding_uuid) byFindingId.set(String(result.finding_uuid), result.analysis)
        const identity = assessmentIdentity(result)
        if (identity !== '\u0000\u0000') byIdentity.set(identity, result.analysis)
    }

    return {
        ...group,
        affected_versions: (group.affected_versions || []).map(version => ({
            ...version,
            components: (version.components || []).map(component => {
                const analysis = (component.finding_uuid
                    ? byFindingId.get(String(component.finding_uuid))
                    : undefined) || byIdentity.get(assessmentIdentity(component))
                if (!analysis) return component
                return {
                    ...component,
                    analysis_state: analysis.analysisState ?? analysis.analysis_state ?? component.analysis_state,
                    analysis_details: analysis.analysisDetails ?? analysis.analysis_details ?? component.analysis_details,
                    is_suppressed: analysis.isSuppressed ?? analysis.is_suppressed ?? component.is_suppressed,
                    justification: analysis.analysisJustification ?? analysis.justification ?? component.justification,
                }
            }),
        })),
    }
}

const handleReloadGroup = async (group: GroupedVuln) => {
    if (reloadingGroupIds.value.has(group.id)) return
    setGroupReloading(group.id, true)
    const nextErrors = { ...groupReloadErrors.value }
    delete nextErrors[group.id]
    groupReloadErrors.value = nextErrors

    try {
        let sourceGroup = fullGroupCache.value[group.id] || group
        let instances = (sourceGroup.affected_versions || [])
            .flatMap(version => version.components || [])
            .filter(component => component.project_uuid && component.component_uuid && component.vulnerability_uuid)
        if (instances.length === 0 && currentVulnTaskId.value) {
            sourceGroup = await refreshTaskGroupDetail(group.id, { showLoading: false }) || sourceGroup
            instances = (sourceGroup.affected_versions || [])
                .flatMap(version => version.components || [])
                .filter(component => component.project_uuid && component.component_uuid && component.vulnerability_uuid)
        }
        if (instances.length === 0) {
            throw new Error('No vulnerability instances are available to reload')
        }

        const results = await getAssessmentDetails(instances)
        if (!Array.isArray(results)) {
            throw new Error('The reload response was invalid')
        }

        replaceGroup(applyReloadedAssessmentDetails(sourceGroup, results))
        statsDirty.value = true
        if (currentVulnTaskId.value) {
            await loadTaskGroupWindow({ reset: true })
            if (selectedGroupId.value === group.id) {
                await refreshTaskGroupDetail(group.id, { showLoading: false })
            }
        }

        const failures = results.filter(result => result?.error)
        if (failures.length > 0) {
            groupReloadErrors.value = {
                ...groupReloadErrors.value,
                [group.id]: `Reloaded with ${failures.length} failed component${failures.length === 1 ? '' : 's'}`,
            }
        }
    } catch (err: any) {
        console.error(`Failed to reload vulnerability ${group.id}:`, err)
        groupReloadErrors.value = {
            ...groupReloadErrors.value,
            [group.id]: err?.message || 'Failed to reload vulnerability',
        }
    } finally {
        setGroupReloading(group.id, false)
    }
}

projectHeaderState.bulkWorkflowHandler.value = () => {
    if (!currentVulnTaskId.value) return
    flushSmartSearchFilter()
    void nextTick(() => { showBulkWorkflowModal.value = true })
}

const handleBulkWorkflowApplied = (_result: BulkWorkflowApplyResponse) => {
    handleBulkUpdates([])
}

const exportCurrentProjectArchive = async () => {
    const name = routeProjectName()
    if (!name || name === '_all_') return
    archiveExporting.value = true
    archiveExportError.value = ''
    archiveExportTask.value = null
    archiveExportMessage.value = `Queueing archive export for ${name}...`
    try {
        const { task_id } = await startProjectArchiveExport({ project_name: name, refresh: true })
        archiveExportTask.value = {
            id: task_id,
            kind: 'export',
            status: 'pending',
            message: `Queued archive export for ${name}`,
            progress: 0,
        }
        const task = await waitForProjectArchiveTask(task_id, (status) => {
            archiveExportTask.value = status
            archiveExportMessage.value = status.message
        })
        archiveExportTask.value = task
        archiveExportMessage.value = `Archive ready for ${name}`
        window.location.href = getProjectArchiveTaskDownloadUrl(task.id)
    } catch (err: any) {
        archiveExportError.value = err.message || 'Project archive export failed'
    } finally {
        archiveExporting.value = false
    }
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

const isAnalysisViewActive = computed(() => viewMode.value === 'analysis' && !error.value)
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

const hasMeasuredListViewport = () => {
    const element = listScrollContainer.value
    if (!element) return false
    return (element.clientHeight || element.getBoundingClientRect().height || 0) > 0
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
    if (!hasMeasuredListViewport()) return
    if (taskListWindowLoading.value || taskListAppendLoading.value) return
    if (visibleEndIndex.value >= loadedGroupCount.value - 20) {
        void loadTaskGroupWindow({ reset: false })
    }
})

defineExpose({ filteredGroups })

const activeFilterChips = computed(() => buildActiveFilterChips({
    lifecycleFilters: lifecycleFilters.value,
    lifecycleOptions: LIFECYCLE_OPTIONS,
    inconsistencyReasonFilters: inconsistencyReasonFilters.value,
    inconsistencyReasonOptions: INCONSISTENCY_REASON_OPTIONS,
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
    automaticAssessmentFilters: selectedAutomaticAssessmentFilters.value,
    automaticAssessmentOptions: AUTOMATIC_ASSESSMENT_FILTER_OPTIONS,
    cvssVersionMismatchOnly: cvssVersionMismatchOnly.value,
    attributionAgeDays: attributionAgeDays.value,
    attributionAgeMode: attributionAgeMode.value,
}))

const removeActiveFilterChip = (key: ActiveFilterChipKey) => {
    switch (key) {
        case 'lifecycle':
            lifecycleFilters.value = allLifecycleFilterValues.value
            break
        case 'inconsistencyReason':
            inconsistencyReasonFilters.value = []
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
        case 'automaticAssessment':
            automaticAssessmentFilter.value = allAutomaticAssessmentFilterValues.value
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
    inconsistencyReasonFilters: inconsistencyReasonFilters.value,
    defaultLifecycleFilters: defaultLifecycleFilters.value,
    analysisFilters: analysisFilters.value,
    defaultAnalysisFilters,
    dependencyFilters: selectedDependencyFilters.value,
    defaultDependencyFilters: allDependencyFilterValues.value,
    tmrescoreFilters: selectedTMRescoreProposalFilters.value,
    defaultTMRescoreFilters: allTMRescoreFilterValues.value,
    automaticAssessmentFilters: selectedAutomaticAssessmentFilters.value,
    defaultAutomaticAssessmentFilters: allAutomaticAssessmentFilterValues.value,
}))

const filterSidebarProps = computed(() => ({
    filters: filterState.value,
    availableVersions: availableVersions.value,
    lifecycleOptions: LIFECYCLE_OPTIONS,
    inconsistencyReasonOptions: INCONSISTENCY_REASON_OPTIONS,
    analysisOptions: ANALYSIS_OPTIONS,
    copiedUrl: copiedUrl.value,
    resultCounts: visibleResultCounts.value,
    countsUpdating: resultCountsUpdating.value,
    teamOptions: taskWideFacets.value.teams,
    cacheStatusState: cacheStatusState.value,
    cacheStatusLabel: cacheStatusLabel.value,
    cacheStatusAge: cacheStatusAge.value,
    cacheStatusTooltip: cacheStatusText.value,
    cacheStatusDetail: cacheStatus.value,
    sortOptions: SORT_OPTIONS,
    dependencyOptions: DEPENDENCY_OPTIONS,
    tmrescoreOptions: TMRESCORE_FILTER_OPTIONS,
    automaticAssessmentOptions: AUTOMATIC_ASSESSMENT_FILTER_OPTIONS,
}))

const syncProjectHeaderState = () => {
    const name = routeProjectName()
    const isAllProjects = name === '_all_'
    projectHeaderState.currentProjectName.value = isAllProjects ? null : name
    projectHeaderState.isAllProjects.value = isAllProjects
    if (!isAllProjects && name) {
        projectHeaderState.lastProjectName.value = name
        projectHeaderState.lastProjectPath.value = route.fullPath || `/project/${name}`
    }
    projectHeaderState.isReviewer.value = currentUserRole.value === 'REVIEWER'
}

const hydrateSelectedRouteGroup = () => {
    if (selectedGroupId.value) {
        void hydrateVisibleGroup(selectedGroupId.value)
    }
}

const syncStatsForProjectRoute = () => {
    if (viewMode.value === 'statistics') {
        fetchStats()
    } else {
        stats.value = null // Reset stats to force refresh if they toggle back
    }
}

const loadProjectRouteState = () => {
    if (!isProjectReviewRouteActive()) return

    const name = routeProjectName()
    syncSelectedGroupFromRoute()
    if (route.query.vuln) {
        viewMode.value = 'analysis'
    }
    syncProjectHeaderState()

    if (loadedProjectName.value === name && !error.value) {
        hydrateSelectedRouteGroup()
        syncStatsForProjectRoute()
        return
    }

    if (loadingProjectName.value === name) {
        hydrateSelectedRouteGroup()
        return
    }

    void fetchVulns()
    void fetchTMRescoreProposals()
    syncStatsForProjectRoute()
}

watch([() => route.path, () => route.params.name], () => {
    loadProjectRouteState()
}, { immediate: true })

watch(() => route.query.vuln, (vulnId) => {
    if (!isProjectReviewRouteActive()) return
    syncSelectedGroupFromRoute()
    if (vulnId) {
        viewMode.value = 'analysis'
    }
    syncProjectHeaderState()
    hydrateSelectedRouteGroup()
})

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
        v-if="viewMode === 'analysis' && !error"
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
                <button
                    v-if="currentUserRole === 'REVIEWER' && canExportArchives"
                    type="button"
                    title="Export project archive"
                    :disabled="archiveExporting"
                    class="inline-flex h-10 shrink-0 items-center gap-2 rounded-xl border border-white/10 bg-slate-950/35 px-3 text-xs font-semibold uppercase tracking-wider text-slate-200 transition-colors hover:bg-slate-900/55 hover:text-white disabled:cursor-wait disabled:opacity-60"
                    @click="exportCurrentProjectArchive"
                >
                    <Loader2 v-if="archiveExporting" :size="14" class="animate-spin" />
                    <Archive v-else :size="14" />
                    <span class="hidden sm:inline">{{ archiveExporting ? 'Exporting' : 'Archive' }}</span>
                </button>
                <div
                    class="hidden shrink-0 text-right text-[11px] leading-tight text-gray-400 md:block"
                    role="status"
                    aria-live="polite"
                >
                    <div v-if="resultCountsUpdating" class="font-semibold text-blue-200">Updating results…</div>
                    <div v-else>
                        <span class="font-semibold text-white">{{ filteredGroupCount }}</span>
                        <span v-if="filteredGroupCount !== totalGroupCount"> of {{ totalGroupCount }}</span>
                        {{ filteredGroupCount === 1 && totalGroupCount === 1 ? 'vulnerability' : 'vulnerabilities' }}
                        <span v-if="taskListPartial"> · provisional</span>
                    </div>
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
            <div
                v-if="showLoadingStatus"
                class="rounded-xl border border-blue-400/20 bg-blue-500/10 p-3 text-sm text-blue-100"
                role="status"
                data-testid="loading-status"
                :title="loadingProgressTitle"
            >
                <div class="flex flex-wrap items-center justify-between gap-3">
                    <span class="inline-flex min-w-0 flex-1 items-center gap-2">
                        <Loader2 :size="14" class="shrink-0 animate-spin text-blue-200" />
                        <span class="min-w-0 truncate">{{ loadingMessage }}</span>
                    </span>
                    <span
                        v-if="loadingProgressPercent > 1"
                        class="shrink-0 text-xs font-bold tabular-nums text-blue-50"
                    >
                        {{ loadingProgressPercent }}%
                    </span>
                </div>
                <div class="mt-3 h-2 overflow-hidden rounded bg-black/30">
                    <div
                        v-if="loadingProgressPercent <= 1"
                        class="h-full w-1/3 animate-pulse rounded-full bg-blue-300/70"
                    ></div>
                    <div
                        v-else
                        class="h-full rounded-full bg-blue-300 transition-all duration-300"
                        :style="{ width: `${loadingProgressPercent}%` }"
                    ></div>
                </div>
            </div>
            <div
                v-if="archiveExportMessage || archiveExportError"
                class="rounded-xl border p-3 text-sm"
                :class="archiveExportError ? 'border-red-400/20 bg-red-500/10 text-red-200' : 'border-blue-400/20 bg-blue-500/10 text-blue-100'"
                role="status"
            >
                <div class="flex flex-wrap items-center justify-between gap-3">
                    <span class="min-w-0 flex-1 truncate">{{ archiveExportError || archiveExportMessage }}</span>
                    <span v-if="archiveExportTask && !archiveExportError" class="text-xs font-bold text-blue-200">{{ archiveExportProgress }}%</span>
                    <a
                        v-if="archiveExportDownloadUrl"
                        :href="archiveExportDownloadUrl"
                        class="inline-flex items-center gap-1 rounded-lg border border-green-400/30 bg-green-500/15 px-2.5 py-1.5 text-xs font-bold text-green-100 transition-colors hover:bg-green-500/25"
                    >
                        <Download :size="13" />
                        Download
                    </a>
                </div>
                <div v-if="archiveExportTask && !archiveExportError && archiveExportTask.status !== 'completed'" class="mt-3 h-2 overflow-hidden rounded bg-black/30">
                    <div class="h-full bg-blue-400 transition-all" :style="{ width: `${archiveExportProgress}%` }"></div>
                </div>
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
            <div v-if="loading && viewMode !== 'analysis'" class="text-center py-10">
                <div class="mb-2 text-xl font-semibold">{{ loadingMessage }}</div>
                <div class="w-full max-w-md mx-auto bg-gray-700 rounded-full h-4 relative overflow-hidden">
                    <div v-if="loadingProgress <= 1" class="bg-blue-500/60 h-4 w-1/3 rounded-full animate-pulse"></div>
                    <div v-else class="bg-blue-500 h-4 transition-all duration-300" :style="{ width: loadingProgress + '%' }"></div>
                </div>
                <div class="mt-2 text-sm text-gray-400">{{ loadingProgress > 1 ? loadingProgress + '%' : '' }}</div>
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
                                    :reloading="reloadingGroupIds.has(item.id)"
                                    :reload-error="groupReloadErrors[item.id]"
                                    :data-group-id="item.id"
                                    @select="selectGroupWithDraftGuard"
                                    @reload="handleReloadGroup"
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
                        <div
                            v-if="showPreparingListStatus"
                            class="flex min-h-[20rem] w-full min-w-full flex-col items-center justify-center gap-3 py-16 text-center text-gray-400"
                            role="status"
                            data-testid="preparing-list-status"
                        >
                            <Loader2 :size="28" class="animate-spin text-blue-300" />
                            <div class="text-sm font-semibold uppercase tracking-wider text-gray-300">
                                Preparing vulnerability list...
                            </div>
                            <div class="max-w-xl text-sm text-blue-100">
                                {{ preparingListDetailMessage }}
                            </div>
                            <div class="w-full max-w-xl">
                                <div class="mb-1 flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-gray-500">
                                    <span>Progress</span>
                                    <span v-if="preparingListProgressLabel" class="text-blue-100">
                                        {{ preparingListProgressLabel }}
                                    </span>
                                </div>
                                <div class="h-2 overflow-hidden rounded bg-black/30">
                                    <div
                                        v-if="preparingListProgressWidth === null"
                                        class="h-full w-1/3 animate-pulse rounded-full bg-blue-300/70"
                                    ></div>
                                    <div
                                        v-else
                                        class="h-full rounded-full bg-blue-300 transition-all duration-300"
                                        :style="{ width: `${preparingListProgressWidth}%` }"
                                    ></div>
                                </div>
                            </div>
                            <div
                                v-if="preparingListLog.length > 0"
                                class="max-w-xl space-y-1 text-xs text-gray-500"
                            >
                                <div
                                    v-for="entry in preparingListLog"
                                    :key="entry"
                                    class="truncate"
                                >
                                    {{ entry }}
                                </div>
                            </div>
                        </div>
                        <div v-else-if="filteredGroupCount === 0" class="text-gray-500 text-center py-16 font-medium min-h-[20rem] w-full min-w-full">No vulnerabilities found matching criteria.</div>
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
                ref="detailInspectorRef"
                :group="selectedGroup"
                :hasAutomaticAssessment="selectedGroupHasAutomaticAssessment"
                :automaticAssessmentStatus="selectedGroupAutomaticAssessmentStatus"
                class="h-full"
                @close="closeSelectedGroupWithDraftGuard"
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
                ref="detailInspectorRef"
                :group="selectedGroup"
                :hasAutomaticAssessment="selectedGroupHasAutomaticAssessment"
                :automaticAssessmentStatus="selectedGroupAutomaticAssessmentStatus"
                @close="closeSelectedGroupWithDraftGuard"
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

    <BulkWorkflowModal
        :show="showBulkWorkflowModal"
        :task-id="currentVulnTaskId"
        :query="taskGroupListQuery"
        @close="showBulkWorkflowModal = false"
        @applied="handleBulkWorkflowApplied"
    />
  </div>
</template>
