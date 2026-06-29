<script setup lang="ts">
import { ref, watch, computed, inject, provide, onMounted, onUnmounted, onActivated, nextTick, triggerRef } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { getGroupedVulns, getTeamMapping, getRescoreRules, getStatistics, getTMRescoreProposals } from '../lib/api'
import { calculateScoreFromVector } from '../lib/cvss'
import { useCacheStatus } from '../lib/useCacheStatus'
import type { GroupedVuln, Statistics, TMRescoreProposalSnapshot } from '../types'
import { projectHeaderState } from '../lib/projectHeaderStore'
import { useVisibleGroupWindow } from '../lib/useVisibleGroupWindow'
import {
    buildVulnListItems,
    computeListFilterCounts,
    computeListTeamCounts,
    matchesLifecycleFilter,
    matchesAttributionAgeFilter,
    matchesListFilters,
    matchesStateFilters,
    normalizeAttributionAgeDays,
    normalizeFilterSelection,
    parseVulnSearchQuery,
} from '../lib/vulnListIndex'
import type { DependencyRelationship, TMRescoreProposalFilter, VulnListItem } from '../lib/vulnListIndex'

import VulnRowCompact from '../components/VulnRowCompact.vue'
import VulnDetailInspector from '../components/VulnDetailInspector.vue'
import BulkResolveIncompleteModal from '../components/BulkResolveIncompleteModal.vue'
import BulkApproveModal from '../components/BulkApproveModal.vue'
import ProjectStatistics from '../components/ProjectStatistics.vue'
import StatsSidebar from '../components/StatsSidebar.vue'
import type { FilterState } from '../components/FilterSidebar.vue'
import { BarChart3, Plus, Search, SlidersHorizontal, X } from 'lucide-vue-next'

const route = useRoute()
const router = useRouter()
const user = inject<any>('user', { role: 'ANALYST' })
const currentUserRole = computed(() => (user?.value ?? user)?.role || 'ANALYST')
const groups = ref<GroupedVuln[]>([])
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
provide('tmrescoreProposals', computed(() => tmrescoreProposalSnapshot.value?.proposals || {}))

const showBulkApproveModal = ref(false)
let filterUrlSyncTimer: ReturnType<typeof setTimeout> | null = null

const tmrescoreProposalFilter = ref<TMRescoreProposalFilter[]>(['WITH_PROPOSAL', 'WITHOUT_PROPOSAL'])
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

    try {
        const rawData = await getGroupedVulns(apiName, undefined, (msg, progress, log) => {
            loadingMessage.value = msg
            loadingProgress.value = progress
            if (log && log.length > 0) {
                loadingLog.value = log
            } else if (msg && (loadingLog.value.length === 0 || loadingLog.value[loadingLog.value.length - 1] !== msg)) {
                loadingLog.value.push(msg)
            }
        })

        groups.value = await processFetchedGroups(rawData)
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
        stats.value = await getStatistics(name, route.query.cve as string)
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

const selectedGroupId = ref<string | null>(
    typeof route.query.vuln === 'string' ? route.query.vuln : null
)
const DETAIL_INSPECTOR_MIN_VIEWPORT = 1360
const FILTER_RAIL_MIN_VIEWPORT = 1280
const FILTER_RAIL_WITH_DETAIL_MIN_VIEWPORT = 1680
const viewportWidth = ref(typeof window === 'undefined' ? 1280 : window.innerWidth)
const isDesktopInspector = computed(() => viewportWidth.value >= DETAIL_INSPECTOR_MIN_VIEWPORT)

const updateViewportWidth = () => {
    if (typeof window === 'undefined') return
    viewportWidth.value = window.innerWidth
}

onMounted(() => {
    updateViewportWidth()
    window.addEventListener('resize', updateViewportWidth)
})

onUnmounted(() => {
    if (typeof window === 'undefined') return
    window.removeEventListener('resize', updateViewportWidth)
    if (filterUrlSyncTimer) {
        clearTimeout(filterUrlSyncTimer)
        filterUrlSyncTimer = null
    }
})

const handleLocalAssessmentUpdate = (group: GroupedVuln, data: any) => {
    group.rescored_cvss = data.rescored_cvss
    group.rescored_vector = data.rescored_vector
    if (data.assignees !== undefined) {
        group.assignees = data.assignees
    }

    // Update all affected instances in this group by creating new array and object references for reactivity
    group.affected_versions = group.affected_versions.map((version: any) => {
        return {
            ...version,
            components: version.components.map((instance: any) => {
                return {
                    ...instance,
                    analysis_state: data.analysis_state,
                    analysis_details: data.analysis_details,
                    is_suppressed: data.is_suppressed,
                    justification: data.justification
                }
            })
        }
    })
    
    // Force top-level reactivity by replacing only the changed group
    const idx = groups.value.findIndex((g: any) => g.id === group.id)
    if (idx !== -1) {
        groups.value[idx] = { ...group }
    }
    triggerRef(groups)

    statsDirty.value = true

    if (viewMode.value === 'statistics') {
        fetchStats()
            .then(() => { statsDirty.value = false })
            .catch((err) => {
                console.error('Failed to refresh statistics after assessment update', err)
            })
    }
}

const handleBulkUpdates = (updates: Array<{ id: string; data: any }>, onComplete?: () => void) => {
    for (const update of updates) {
        const group = groups.value.find(g => g.id === update.id)
        if (group) {
            handleLocalAssessmentUpdate(group, update.data)
        }
    }

    statsDirty.value = true

    if (viewMode.value === 'statistics') {
        fetchStats()
            .then(() => { statsDirty.value = false })
            .catch((err) => {
                console.error('Failed to refresh statistics after bulk assessment updates', err)
            })
    }

    if (onComplete) onComplete()
}

const replaceGroup = (updatedGroup: GroupedVuln) => {
    const idx = groups.value.findIndex(g => g.id === updatedGroup.id)
    if (idx === -1) return

    groups.value[idx] = updatedGroup
    groups.value = [...groups.value]
}

const handleTeamMappingUpdated = async (updatedGroup?: GroupedVuln) => {
    if (updatedGroup) {
        replaceGroup(updatedGroup)
    }

    statsDirty.value = true
    if (viewMode.value === 'statistics') {
        fetchStats()
            .then(() => { statsDirty.value = false })
            .catch((err) => {
                console.error('Failed to refresh statistics after team mapping update', err)
            })
    }
}

const showBulkModal = ref(false)
projectHeaderState.bulkSyncHandler.value = () => {
    showBulkModal.value = true
}

const handleBulkApproveModalUpdates = (updates: Array<{ id: string; data: any }>) => {
    handleBulkUpdates(updates, () => { showBulkApproveModal.value = false })
}

// Expansion tracking removed — now handled by VulnRowCompact click → modal flow

const smartSearchInput = ref('')
const parsedSmartSearch = computed(() => parseVulnSearchQuery(smartSearchInput.value))
const tagFilter = ref('')
const idFilter = ref('')
const componentFilter = ref('')
const assigneeFilter = ref('')
const dependencyFilter = ref<DependencyRelationship[]>(['DIRECT', 'TRANSITIVE', 'UNKNOWN'])
const cvssVersionMismatchOnly = ref(false)
const attributionAgeDays = ref<number | null>(null)
const attributionAgeMode = ref<'older' | 'younger'>('older')

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
const versionFilterInput = ref('')
const versionFilterList = computed(() => {
    return versionFilterInput.value
        .split(',')
        .map(v => v.trim())
        .filter(v => v.length > 0)
})

const selectedDependencyFilters = computed(() => normalizeFilterSelection(dependencyFilter.value))
const selectedTMRescoreProposalFilters = computed(() => normalizeFilterSelection(tmrescoreProposalFilter.value))

const listItems = computed(() => {
    return buildVulnListItems(
        groups.value,
        teamMapping.value,
        tmrescoreProposalSnapshot.value?.proposals || {},
    )
})

const availableVersions = computed(() => {
    const allVersions = new Set<string>()
    listItems.value.forEach(item => {
        item.versions.forEach(version => allVersions.add(version))
    })
    return Array.from(allVersions).sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }))
})


const filterUrl = computed(() => {
    const query: Record<string, string | string[]> = {
        ...(route.query as Record<string, string | string[]>)
    }

    if (selectedDependencyFilters.value.length > 0) {
        query.dependency = selectedDependencyFilters.value
    } else {
        delete query.dependency
    }

    if (versionFilterInput.value) {
        query.versions = versionFilterInput.value
    } else {
        delete query.versions
    }

    if (selectedTMRescoreProposalFilters.value.length > 0) {
        query.tmrescore = selectedTMRescoreProposalFilters.value
    } else {
        delete query.tmrescore
    }

    if (attributionAgeDays.value == null) {
        delete query.attributed_before_days
        delete query.attribution_mode
    } else {
        query.attributed_before_days = String(attributionAgeDays.value)
        query.attribution_mode = attributionAgeMode.value
    }
    delete query.attributed_from
    delete query.attributed_to
    delete query.attributed_not
    delete query.attribution_age_days
    delete query.age_days

    if (smartSearchInput.value.trim()) {
        query.q = smartSearchInput.value.trim()
    } else {
        delete query.q
    }

    const params = new URLSearchParams()
    Object.entries(query).forEach(([k, v]) => {
        if (Array.isArray(v)) {
            v.forEach(item => params.append(k, item))
        } else if (v != null && v !== '') {
            params.set(k, String(v))
        }
    })

    const path = (route.path || '/') as string
    return `${window.location.origin}${path}${params.toString() ? `?${params.toString()}` : ''}`
})

const copiedUrl = ref(false)
const showFilterDrawer = ref(false)
const showSearchTokenMenu = ref(false)
const searchInput = ref<HTMLInputElement | null>(null)
const searchFocused = ref(false)
const searchCursorPosition = ref(0)
const activeCompletionIndex = ref(0)

const copyFilterUrl = async () => {
    const link = filterUrl.value
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(link)
        } else {
            const textarea = document.createElement('textarea')
            document.body.appendChild(textarea)
            textarea.value = link
            textarea.select()
            document.execCommand('copy')
            document.body.removeChild(textarea)
        }
        copiedUrl.value = true
        setTimeout(() => copiedUrl.value = false, 2000)
    } catch (e) {
        console.error('Failed to copy URL', e)
    }
}

const lifecycleFilters = ref<string[]>([])
const analysisFilters = ref<string[]>([])
const sortBy = ref('rescored-severity')
const sortOrder = ref<'asc' | 'desc'>('desc')

const firstQueryValue = (value: unknown) => Array.isArray(value) ? value[0] : value
const FILTER_QUERY_KEYS = new Set([
    'q',
    'lifecycle',
    'analysis',
    'tag',
    'id',
    'cve',
    'component',
    'assignee',
    'sort',
    'order',
    'tmrescore',
    'cvss_mismatch',
    'attributed_before_days',
    'attribution_mode',
    'attribution_age_days',
    'age_days',
])

onMounted(() => {
    const q = route.query
    const hasFilterParams = Object.entries(q).some(([k, v]) => {
        if (!FILTER_QUERY_KEYS.has(k)) return false;
        if (Array.isArray(v)) return v.length > 0;
        return v !== undefined && v !== null && v !== '';
    })

    if (hasFilterParams) {
        if (q.q) smartSearchInput.value = Array.isArray(q.q) ? q.q.join(' ') : (q.q as string)
        if (q.lifecycle) lifecycleFilters.value = (Array.isArray(q.lifecycle) ? q.lifecycle : [q.lifecycle]) as string[]
        else lifecycleFilters.value = (currentUserRole.value === 'REVIEWER')
            ? ['OPEN', 'ASSESSED', 'INCOMPLETE', 'INCONSISTENT', 'NEEDS_APPROVAL']
            : ['OPEN']
        
        if (q.analysis) analysisFilters.value = (Array.isArray(q.analysis) ? q.analysis : [q.analysis]) as string[]
        else analysisFilters.value = ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED']
        
        if (q.tag) tagFilter.value = q.tag as string
        if (q.id) idFilter.value = q.id as string
        else if (q.cve) idFilter.value = q.cve as string

        if (q.component) componentFilter.value = q.component as string
        if (q.assignee) assigneeFilter.value = q.assignee as string
        if (q.dependency) dependencyFilter.value = Array.isArray(q.dependency) ? (q.dependency as string[]).map(v => v.toUpperCase() as DependencyRelationship) : [(q.dependency as string).toUpperCase() as DependencyRelationship]
        if (q.versions) versionFilterInput.value = Array.isArray(q.versions) ? q.versions.join(',') : (q.versions as string)
        if (q.tmrescore) tmrescoreProposalFilter.value = Array.isArray(q.tmrescore) ? (q.tmrescore as string[]).map(v => v.toUpperCase() as TMRescoreProposalFilter) : [String(q.tmrescore).toUpperCase() as TMRescoreProposalFilter]
        if (q.cvss_mismatch === 'true') cvssVersionMismatchOnly.value = true
        const legacyDays = normalizeAttributionAgeDays(
            firstQueryValue(q.attributed_before_days ?? q.attribution_age_days ?? q.age_days),
        )
        if (legacyDays != null) {
            attributionAgeDays.value = legacyDays
            attributionAgeMode.value = firstQueryValue(q.attribution_mode) === 'younger' ? 'younger' : 'older'
        }
        if (q.sort) sortBy.value = q.sort as string
        if (q.order) sortOrder.value = q.order as 'asc' | 'desc'
    } else {
        resetFilters()
    }
})

// If the user switches between reviewer and analyst, reapply defaults for lifecycle/analysis
watch(currentUserRole, (newRole, oldRole) => {
    if (!newRole || newRole === oldRole) return

    const allAnalysis = ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED']
    analysisFilters.value = [...allAnalysis]

    if (newRole === 'REVIEWER') {
        lifecycleFilters.value = ['OPEN', 'ASSESSED', 'ASSESSED_LEGACY', 'INCOMPLETE', 'INCONSISTENT', 'NEEDS_APPROVAL']
    } else {
        lifecycleFilters.value = ['OPEN']
    }

    // Keep explicit tag/id/component/sort/order if present, but apply role-specific default lifecycle+analysis.
})

const resetFilters = () => {
    const allAnalysis = ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED']
    analysisFilters.value = [...allAnalysis]
    
    if (currentUserRole.value === 'REVIEWER') {
        lifecycleFilters.value = ['OPEN', 'ASSESSED', 'ASSESSED_LEGACY', 'INCOMPLETE', 'INCONSISTENT', 'NEEDS_APPROVAL']
    } else {
        lifecycleFilters.value = ['OPEN']
    }
    idFilter.value = ''
    tagFilter.value = ''
    smartSearchInput.value = ''
    componentFilter.value = ''
    assigneeFilter.value = ''
    dependencyFilter.value = ['DIRECT', 'TRANSITIVE', 'UNKNOWN']
    tmrescoreProposalFilter.value = ['WITH_PROPOSAL', 'WITHOUT_PROPOSAL']
    versionFilterInput.value = ''
    cvssVersionMismatchOnly.value = false
    attributionAgeDays.value = null
    attributionAgeMode.value = 'older'
    sortBy.value = 'rescored-severity'
    sortOrder.value = 'desc'
}

// Filter state now remains local in the frontend and does not cause backend re-fetch.
// This reduces unnecessary chattiness and keeps filtering fast and responsive.
// URL sync was removed to avoid automatic API refresh for every filter tweak.

const syncFilterQueryToUrl = () => {
    const query = { ...route.query }

    if (smartSearchInput.value.trim()) query.q = smartSearchInput.value.trim()
    else delete query.q

    if (lifecycleFilters.value.length > 0) query.lifecycle = lifecycleFilters.value
    else delete query.lifecycle

    if (analysisFilters.value.length > 0) query.analysis = analysisFilters.value
    else delete query.analysis

    if (tagFilter.value) query.tag = tagFilter.value
    else delete query.tag

    if (idFilter.value) query.id = idFilter.value
    else delete query.id

    if (componentFilter.value) query.component = componentFilter.value
    else delete query.component

    if (assigneeFilter.value) query.assignee = assigneeFilter.value
    else delete query.assignee

    if (selectedDependencyFilters.value.length > 0) query.dependency = selectedDependencyFilters.value
    else delete query.dependency

    if (versionFilterInput.value) query.versions = versionFilterInput.value
    else delete query.versions

    if (selectedTMRescoreProposalFilters.value.length > 0) query.tmrescore = selectedTMRescoreProposalFilters.value
    else delete query.tmrescore

    if (cvssVersionMismatchOnly.value) query.cvss_mismatch = 'true'
    else delete query.cvss_mismatch

    if (attributionAgeDays.value == null) {
        delete query.attributed_before_days
        delete query.attribution_mode
    } else {
        query.attributed_before_days = String(attributionAgeDays.value)
        query.attribution_mode = attributionAgeMode.value
    }
    delete query.attributed_from
    delete query.attributed_to
    delete query.attributed_not
    delete query.attribution_age_days
    delete query.age_days

    query.sort = sortBy.value
    query.order = sortOrder.value

    router.replace({ query }).catch(() => {})
}

watch([smartSearchInput, lifecycleFilters, analysisFilters, tagFilter, idFilter, componentFilter, assigneeFilter, dependencyFilter, tmrescoreProposalFilter, versionFilterInput, cvssVersionMismatchOnly, attributionAgeDays, attributionAgeMode, sortBy, sortOrder], () => {
    if (filterUrlSyncTimer) clearTimeout(filterUrlSyncTimer)
    filterUrlSyncTimer = setTimeout(() => {
        filterUrlSyncTimer = null
        syncFilterQueryToUrl()
    }, 200)
}, { deep: true })

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

const scoreSeverityOrder = (score: number | undefined | null): number => {
    const s = score ?? 0
    if (s >= 9.0) return 0  // CRITICAL
    if (s >= 7.0) return 1  // HIGH
    if (s >= 4.0) return 2  // MEDIUM
    if (s >= 0.1) return 3  // LOW
    return 4                // INFO
}

const ANALYSIS_STATE_ORDER: Record<string, number> = {
    'EXPLOITABLE': 0,
    'IN_TRIAGE': 1,
    'NOT_SET': 2,
    'RESOLVED': 3,
    'FALSE_POSITIVE': 4,
    'NOT_AFFECTED': 5
}

const nonStateFilters = computed(() => ({
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
}))

// Items after applying all non-lifecycle/non-analysis filters (used for filter counts)
const preFilteredItems = computed(() => {
    return listItems.value.filter(item => matchesListFilters(item, nonStateFilters.value))
})

const matchingItems = computed(() => {
    return preFilteredItems.value.filter(item => matchesStateFilters(item, {
        lifecycleFilters: lifecycleFilters.value,
        analysisFilters: analysisFilters.value,
    }))
})

const sortedItems = computed(() => {
    const result = [...matchingItems.value]

    result.sort((a, b) => {
        let comparison = 0
        
        switch (sortBy.value) {
            case 'analysis': {
                const stateA = a.technicalState
                const stateB = b.technicalState
                comparison = (ANALYSIS_STATE_ORDER[stateA] ?? 99) - (ANALYSIS_STATE_ORDER[stateB] ?? 99)
                break
            }
            case 'tags': {
                comparison = a.firstTag.localeCompare(b.firstTag)
                break
            }
            case 'severity': {
                // Negate so that desc = most critical first (CRITICAL=0 is highest priority)
                comparison = scoreSeverityOrder(b.baseScore) - scoreSeverityOrder(a.baseScore)
                break
            }
            case 'rescored-severity': {
                // Negate so that desc = most critical first (CRITICAL=0 is highest priority)
                comparison = scoreSeverityOrder(b.rescoredScore) - scoreSeverityOrder(a.rescoredScore)
                break
            }
            case 'score': {
                comparison = a.baseScore - b.baseScore
                break
            }
            case 'rescored': {
                comparison = a.rescoredScore - b.rescoredScore
                break
            }
            case 'id': {
                comparison = a.id.localeCompare(b.id)
                break
            }
        }
        
        if (comparison === 0) {
            return a.id.localeCompare(b.id)
        }
        
        return sortOrder.value === 'asc' ? comparison : -comparison
    })
    
    return result
})

const sortedGroups = computed(() => sortedItems.value.map(item => item.group))

const selectedGroup = computed(() => {
    if (!selectedGroupId.value) return null
    return sortedGroups.value.find(group => group.id === selectedGroupId.value) || null
})

const isDesktopDetailOpen = computed(() =>
    !!selectedGroup.value && viewMode.value === 'analysis' && isDesktopInspector.value
)

const isFilterRailVisible = computed(() => {
    const requiredWidth = isDesktopDetailOpen.value
        ? FILTER_RAIL_WITH_DETAIL_MIN_VIEWPORT
        : FILTER_RAIL_MIN_VIEWPORT
    return viewportWidth.value >= requiredWidth
})

const isAnalysisViewActive = computed(() => viewMode.value === 'analysis' && !loading.value && !error.value)
const isAnalysisWorkspaceActive = isAnalysisViewActive
const {
    visibleItems: visibleGroups,
    hasMoreItems: hasMoreGroups,
    loadMoreTrigger,
    visibleItemCount,
    resetVisibleItems,
} = useVisibleGroupWindow({
    items: sortedGroups,
    isActive: isAnalysisViewActive,
    batchSize: 40,
    rootMargin: '800px',
})

const setLoadMoreTrigger = (element: any) => {
    loadMoreTrigger.value = element as HTMLElement | null
}

const updateVulnQuery = (id: string | null) => {
    const query: Record<string, any> = { ...route.query }
    if (id) query.vuln = id
    else delete query.vuln
    router.replace({ query }).catch(() => {})
}

const selectGroup = (group: GroupedVuln) => {
    selectedGroupId.value = group.id
    updateVulnQuery(group.id)
}

const closeSelectedGroup = () => {
    selectedGroupId.value = null
    updateVulnQuery(null)
}

watch(() => route.query.vuln, (value) => {
    selectedGroupId.value = typeof value === 'string' ? value : null
})

watch(isFilterRailVisible, (visible) => {
    if (visible) showFilterDrawer.value = false
})

watch(() => viewMode.value, () => {
    showFilterDrawer.value = false
})

watch(sortedGroups, () => {
    resetVisibleItems()
    if (selectedGroupId.value && !selectedGroup.value) {
        closeSelectedGroup()
    }
})

const filteredGroups = sortedGroups

defineExpose({ filteredGroups })

const filterCounts = computed(() => {
    return computeListFilterCounts(listItems.value, lifecycleFilters.value)
})

const cvssVersionMismatchCount = computed(() => {
    return listItems.value.filter(item => item.cvssVersionMismatch).length
})

const teamTagCounts = computed(() => {
    return computeListTeamCounts(listItems.value)
})

const teamTagList = computed(() => {
    return Object.entries(teamTagCounts.value)
        .map(([team, counts]) => ({ team, ...counts }))
        .sort((a, b) => a.team.localeCompare(b.team))
})

const itemsAfterLifecycle = computed(() => {
    if (lifecycleFilters.value.length === 0) return listItems.value

    return listItems.value.filter(item => matchesLifecycleFilter(item, lifecycleFilters.value))
})

const itemsAfterLifecycleAndDependency = computed(() => {
    if (selectedDependencyFilters.value.length === 0) return itemsAfterLifecycle.value
    return itemsAfterLifecycle.value.filter(item => selectedDependencyFilters.value.includes(item.dependencyRelationship))
})

const itemsAfterLifecycleDependencyAndTMRescore = computed(() => {
    if (selectedTMRescoreProposalFilters.value.length === 0) return itemsAfterLifecycleAndDependency.value

    return itemsAfterLifecycleAndDependency.value.filter(item => {
        const matchesWith = selectedTMRescoreProposalFilters.value.includes('WITH_PROPOSAL') && item.hasTmrescoreProposal
        const matchesWithout = selectedTMRescoreProposalFilters.value.includes('WITHOUT_PROPOSAL') && !item.hasTmrescoreProposal
        return matchesWith || matchesWithout
    })
})

const itemsBeforeAnalysis = computed(() => {
    if (attributionAgeDays.value == null) return itemsAfterLifecycleDependencyAndTMRescore.value

    return itemsAfterLifecycleDependencyAndTMRescore.value.filter(item =>
        matchesAttributionAgeFilter(item, attributionAgeDays.value, attributionAgeMode.value)
    )
})

const countRelationships = (items: VulnListItem[]) => {
    const counts = { direct: 0, transitive: 0, unknown: 0 }
    items.forEach(item => {
        const relationship = item.dependencyRelationship.toLowerCase() as 'direct' | 'transitive' | 'unknown'
        counts[relationship]++
    })
    return counts
}

const dependencyFilterCounts = computed(() => {
    return countRelationships(itemsAfterLifecycle.value)
})

const dependencyRelationshipCounts = computed(() => {
    return countRelationships(matchingItems.value)
})

const tmrescoreProposalCounts = computed(() => {
    const counts: Record<string, number> = {
        WITH_PROPOSAL: 0,
        WITHOUT_PROPOSAL: 0,
    }
    itemsAfterLifecycleAndDependency.value.forEach(item => {
        if (item.hasTmrescoreProposal) counts.WITH_PROPOSAL++
        else counts.WITHOUT_PROPOSAL++
    })
    return counts
})

const attributionAgeCount = computed(() => {
    return itemsAfterLifecycleDependencyAndTMRescore.value.filter(item =>
        matchesAttributionAgeFilter(item, attributionAgeDays.value, attributionAgeMode.value)
    ).length
})

const analysisCounts = computed(() => {
    const counts: Record<string, number> = {
        EXPLOITABLE: 0,
        IN_TRIAGE: 0,
        NOT_SET: 0,
        RESOLVED: 0,
        FALSE_POSITIVE: 0,
        NOT_AFFECTED: 0,
        NEEDS_APPROVAL: 0,
    }
    itemsBeforeAnalysis.value.forEach(item => {
        counts[item.technicalState] = (counts[item.technicalState] || 0) + 1
    })
    return counts
})

const needsApprovalGroups = computed(() => {
    return listItems.value
        .filter(item => item.lifecycle === 'NEEDS_APPROVAL')
        .map(item => item.group)
})

const incompleteGroups = computed(() => {
    return listItems.value
        .filter(item => item.lifecycle === 'INCOMPLETE')
        .map(item => item.group)
})

const filterState = computed<FilterState>(() => ({
    sortBy: sortBy.value,
    sortOrder: sortOrder.value,
    dependencyFilter: selectedDependencyFilters.value,
    tmrescoreFilter: selectedTMRescoreProposalFilters.value,
    idFilter: idFilter.value,
    tagFilter: tagFilter.value,
    componentFilter: componentFilter.value,
    assigneeFilter: assigneeFilter.value,
    versionFilterInput: versionFilterInput.value,
    lifecycleFilters: lifecycleFilters.value,
    analysisFilters: analysisFilters.value,
    cvssVersionMismatchOnly: cvssVersionMismatchOnly.value,
    attributionAgeDays: attributionAgeDays.value,
    attributionAgeMode: attributionAgeMode.value,
}))

const optionLabel = (
    value: string,
    options: ReadonlyArray<{ value: string; label: string }>,
) => options.find(option => option.value === value)?.label || value.replace(/_/g, ' ')

const summarizedSelection = (
    values: readonly string[],
    options: ReadonlyArray<{ value: string; label: string }>,
    allLabel: string,
) => {
    if (values.length === 0) return 'None'
    if (values.length === options.length) return allLabel
    return values.map(value => optionLabel(value, options)).join(', ')
}

const hasAllOptionsSelected = (
    values: readonly string[],
    options: ReadonlyArray<{ value: string }>,
) => {
    if (values.length !== options.length) return false
    const selected = new Set(values)
    return options.every(option => selected.has(option.value))
}

const defaultLifecycleFilters = computed(() => {
    if (currentUserRole.value === 'REVIEWER') {
        return ['OPEN', 'ASSESSED', 'ASSESSED_LEGACY', 'INCOMPLETE', 'INCONSISTENT', 'NEEDS_APPROVAL']
    }
    return ['OPEN']
})

const defaultAnalysisFilters = ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED']
const allLifecycleFilterValues = computed(() => LIFECYCLE_OPTIONS.map(option => option.value))
const allAnalysisFilterValues = computed(() => ANALYSIS_OPTIONS.map(option => option.value))
const allDependencyFilterValues = computed(() => DEPENDENCY_OPTIONS.map(option => option.value as DependencyRelationship))
const allTMRescoreFilterValues = computed(() => TMRESCORE_FILTER_OPTIONS.map(option => option.value as TMRescoreProposalFilter))

const sameStringSet = (a: readonly string[], b: readonly string[]) => {
    if (a.length !== b.length) return false
    const set = new Set(a)
    return b.every(value => set.has(value))
}

const smartSearchChips = computed(() => parsedSmartSearch.value.chips)

const SEARCH_TOKEN_SHORTCUTS = [
    { label: 'CVE', value: 'cve:' },
    { label: 'Component', value: 'component:' },
    { label: 'Team', value: 'team:' },
    { label: 'Assignee', value: 'assignee:' },
    { label: 'Version', value: 'version:' },
] as const

interface SearchCompletionOption {
    value: string
    label: string
    detail: string
}

interface SearchCompletionToken {
    prefix: string
    typedPrefix: string
    value: string
    start: number
    end: number
}

const cleanCompletionValue = (value: unknown) => String(value || '').trim()

const buildCompletionOptions = (
    values: unknown[],
    detail: string,
    labelForValue: (value: string) => string = value => value,
): SearchCompletionOption[] => {
    return Array.from(new Set(values.map(cleanCompletionValue).filter(Boolean)))
        .sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }))
        .map(value => ({ value, label: labelForValue(value), detail }))
}

const quoteSearchValue = (value: string) => {
    if (!/\s/.test(value)) return value
    return `"${value.replace(/"/g, '\\"')}"`
}

const updateSearchCursorPosition = (event?: Event) => {
    const target = event?.target as HTMLInputElement | null
    searchCursorPosition.value = target?.selectionStart
        ?? searchInput.value?.selectionStart
        ?? smartSearchInput.value.length
}

const handleSearchFocus = (event: FocusEvent) => {
    searchFocused.value = true
    updateSearchCursorPosition(event)
}

const handleSearchBlur = () => {
    setTimeout(() => {
        searchFocused.value = false
    }, 120)
}

const searchCompletionOptionsByPrefix = computed<Record<string, SearchCompletionOption[]>>(() => {
    const ids: string[] = []
    const components: string[] = []
    const assignees: string[] = []

    groups.value.forEach(group => {
        ids.push(group.id, ...(group.aliases || []))
        assignees.push(...(group.assignees || []))
        const affectedVersions = group.affected_versions || []
        affectedVersions.forEach(version => {
            (version.components || []).forEach(component => {
                components.push(component.component_name)
            })
        })
    })

    const idOptions = buildCompletionOptions(ids, 'ID')
    const componentOptions = buildCompletionOptions(components, 'Component')
    const teamOptions = buildCompletionOptions(teamTagList.value.map(entry => entry.team), 'Team')
    const assigneeOptions = buildCompletionOptions(assignees, 'Assignee')
    const versionOptions = buildCompletionOptions(availableVersions.value, 'Version')
    const lifecycleOptions = LIFECYCLE_OPTIONS.map(option => ({
        value: option.value.toLowerCase(),
        label: option.label,
        detail: 'Lifecycle',
    }))
    const analysisOptions = ANALYSIS_OPTIONS.map(option => ({
        value: option.value.toLowerCase(),
        label: option.label,
        detail: 'State',
    }))
    const dependencyOptions = DEPENDENCY_OPTIONS.map(option => ({
        value: option.value.toLowerCase(),
        label: option.label,
        detail: 'Dependency',
    }))
    const tmrescoreOptions = [
        { value: 'with', label: 'With proposal', detail: 'TM' },
        { value: 'without', label: 'Without proposal', detail: 'TM' },
    ]
    const hasOptions = [
        { value: 'tmrescore', label: 'TM proposal', detail: 'Has' },
        { value: 'no_tmrescore', label: 'No TM proposal', detail: 'Has' },
        { value: 'cvss_mismatch', label: 'CVSS mismatch', detail: 'Has' },
    ]
    const cvssOptions = [
        { value: 'mismatch', label: 'Mismatch', detail: 'CVSS' },
    ]

    return {
        id: idOptions,
        cve: idOptions,
        alias: idOptions,
        vuln: idOptions,
        component: componentOptions,
        comp: componentOptions,
        pkg: componentOptions,
        package: componentOptions,
        team: teamOptions,
        tag: teamOptions,
        assignee: assigneeOptions,
        assigned: assigneeOptions,
        owner: assigneeOptions,
        version: versionOptions,
        ver: versionOptions,
        v: versionOptions,
        lifecycle: lifecycleOptions,
        analysis: analysisOptions,
        state: [...lifecycleOptions, ...analysisOptions],
        dep: dependencyOptions,
        dependency: dependencyOptions,
        tm: tmrescoreOptions,
        tmrescore: tmrescoreOptions,
        proposal: tmrescoreOptions,
        has: hasOptions,
        cvss: cvssOptions,
    }
})

const currentSearchCompletionToken = computed<SearchCompletionToken | null>(() => {
    const input = smartSearchInput.value
    const cursor = Math.min(searchCursorPosition.value, input.length)
    const beforeCursor = input.slice(0, cursor)
    const tokenMatch = beforeCursor.match(/(?:^|\s)([^\s]*)$/)
    const tokenUntilCursor = tokenMatch?.[1] || ''
    const tokenStart = cursor - tokenUntilCursor.length
    const separatorIndex = tokenUntilCursor.indexOf(':')

    if (separatorIndex <= 0) return null

    const typedPrefix = tokenUntilCursor.slice(0, separatorIndex)
    const prefix = typedPrefix.toLowerCase()
    if (!searchCompletionOptionsByPrefix.value[prefix]) return null

    const rawValue = tokenUntilCursor.slice(separatorIndex + 1).replace(/^["']/, '')
    const afterCursor = input.slice(cursor)
    const tokenEndOffset = afterCursor.search(/\s/)
    const tokenEnd = tokenEndOffset === -1 ? input.length : cursor + tokenEndOffset

    return {
        prefix,
        typedPrefix,
        value: rawValue.toLowerCase(),
        start: tokenStart,
        end: tokenEnd,
    }
})

const currentSearchCompletions = computed(() => {
    const token = currentSearchCompletionToken.value
    if (!token) return []

    const query = token.value
    const options = searchCompletionOptionsByPrefix.value[token.prefix] || []

    return options
        .filter(option => {
            if (!query) return true
            const value = option.value.toLowerCase()
            const label = option.label.toLowerCase()
            return value.includes(query) || label.includes(query)
        })
        .sort((a, b) => {
            if (!query) return 0
            const aStarts = a.value.toLowerCase().startsWith(query) || a.label.toLowerCase().startsWith(query)
            const bStarts = b.value.toLowerCase().startsWith(query) || b.label.toLowerCase().startsWith(query)
            if (aStarts !== bStarts) return aStarts ? -1 : 1
            return a.label.localeCompare(b.label, undefined, { numeric: true, sensitivity: 'base' })
        })
        .slice(0, 8)
})

const showSearchCompletions = computed(() =>
    searchFocused.value
    && !!currentSearchCompletionToken.value
    && currentSearchCompletions.value.length > 0
)

watch(() => `${currentSearchCompletionToken.value?.prefix || ''}:${currentSearchCompletionToken.value?.value || ''}`, () => {
    activeCompletionIndex.value = 0
})

const selectSearchCompletion = async (completion: SearchCompletionOption) => {
    const token = currentSearchCompletionToken.value
    if (!token) return

    const before = smartSearchInput.value.slice(0, token.start)
    const after = smartSearchInput.value.slice(token.end).replace(/^\s+/, '')
    const replacement = `${token.typedPrefix}:${quoteSearchValue(completion.value)}`
    smartSearchInput.value = `${before}${replacement}${after ? ` ${after}` : ' '}`

    const cursor = `${before}${replacement} `.length
    searchCursorPosition.value = cursor
    activeCompletionIndex.value = 0
    await nextTick()
    searchInput.value?.focus()
    searchInput.value?.setSelectionRange(cursor, cursor)
}

const handleSearchKeydown = (event: KeyboardEvent) => {
    if (!showSearchCompletions.value) {
        return
    }

    if (event.key === 'ArrowDown') {
        event.preventDefault()
        activeCompletionIndex.value = (activeCompletionIndex.value + 1) % currentSearchCompletions.value.length
    } else if (event.key === 'ArrowUp') {
        event.preventDefault()
        activeCompletionIndex.value = (activeCompletionIndex.value - 1 + currentSearchCompletions.value.length) % currentSearchCompletions.value.length
    } else if (event.key === 'Enter' || event.key === 'Tab') {
        const selected = currentSearchCompletions.value[activeCompletionIndex.value]
        if (selected) {
            event.preventDefault()
            void selectSearchCompletion(selected)
        }
    }
}

const appendSearchToken = async (token: string) => {
    const current = smartSearchInput.value.trim()
    const hasToken = !token.endsWith(':') && current.split(/\s+/).filter(Boolean).includes(token)
    smartSearchInput.value = hasToken ? current : `${current}${current && !hasToken ? ' ' : ''}${hasToken ? '' : token}`.trim()
    showSearchTokenMenu.value = false
    await nextTick()
    searchInput.value?.focus()

    if (token.endsWith(':')) {
        const end = smartSearchInput.value.length
        searchCursorPosition.value = end
        searchInput.value?.setSelectionRange(end, end)
    }
}

const formatSearchChipRaw = (raw: string) => {
    const separatorIndex = raw.indexOf(':')
    if (separatorIndex > 0) {
        const prefix = raw.slice(0, separatorIndex)
        const value = raw.slice(separatorIndex + 1)
        return /\s/.test(value) ? `${prefix}:${quoteSearchValue(value)}` : raw
    }
    return raw.includes(' ') ? quoteSearchValue(raw) : raw
}

const removeSmartSearchChip = (indexToRemove: number) => {
    smartSearchInput.value = smartSearchChips.value
        .filter((_, index) => index !== indexToRemove)
        .map(chip => formatSearchChipRaw(chip.raw))
        .join(' ')
}

const clearSmartSearch = () => {
    smartSearchInput.value = ''
    searchCursorPosition.value = 0
}

type ActiveFilterChipKey =
    | 'lifecycle'
    | 'analysis'
    | 'dependency'
    | 'id'
    | 'tag'
    | 'component'
    | 'assignee'
    | 'versions'
    | 'tmrescore'
    | 'cvss'
    | 'attributionAge'

const activeFilterChips = computed(() => {
    const chips: Array<{ key: ActiveFilterChipKey; label: string }> = []

    if (!hasAllOptionsSelected(lifecycleFilters.value, LIFECYCLE_OPTIONS)) {
        chips.push({ key: 'lifecycle', label: `Lifecycle: ${summarizedSelection(lifecycleFilters.value, LIFECYCLE_OPTIONS, 'All lifecycle')}` })
    }
    if (!hasAllOptionsSelected(analysisFilters.value, ANALYSIS_OPTIONS)) {
        chips.push({ key: 'analysis', label: `State: ${summarizedSelection(analysisFilters.value, ANALYSIS_OPTIONS, 'All states')}` })
    }
    if (!hasAllOptionsSelected(selectedDependencyFilters.value, DEPENDENCY_OPTIONS)) {
        chips.push({ key: 'dependency', label: `Dependency: ${summarizedSelection(selectedDependencyFilters.value, DEPENDENCY_OPTIONS, 'All dependencies')}` })
    }

    if (idFilter.value) chips.push({ key: 'id', label: `ID: ${idFilter.value}` })
    if (tagFilter.value) chips.push({ key: 'tag', label: `Team: ${tagFilter.value}` })
    if (componentFilter.value) chips.push({ key: 'component', label: `Component: ${componentFilter.value}` })
    if (assigneeFilter.value) chips.push({ key: 'assignee', label: `Assignee: ${assigneeFilter.value}` })
    if (versionFilterList.value.length) chips.push({ key: 'versions', label: `Versions: ${versionFilterList.value.join(', ')}` })
    if (selectedTMRescoreProposalFilters.value.length !== TMRESCORE_FILTER_OPTIONS.length) {
        chips.push({ key: 'tmrescore', label: `TM: ${summarizedSelection(selectedTMRescoreProposalFilters.value, TMRESCORE_FILTER_OPTIONS, 'All proposals')}` })
    }
    if (cvssVersionMismatchOnly.value) chips.push({ key: 'cvss', label: 'CVSS mismatch' })
    if (attributionAgeDays.value != null) {
        const verb = attributionAgeMode.value === 'younger' ? 'younger' : 'older'
        chips.push({ key: 'attributionAge', label: `Attributed ${verb} than ${attributionAgeDays.value}d` })
    }

    return chips
})

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

const hasCustomFilterState = computed(() =>
    !!smartSearchInput.value.trim()
    || !!idFilter.value
    || !!tagFilter.value
    || !!componentFilter.value
    || !!assigneeFilter.value
    || versionFilterList.value.length > 0
    || cvssVersionMismatchOnly.value
    || attributionAgeDays.value != null
    || sortBy.value !== 'rescored-severity'
    || sortOrder.value !== 'desc'
    || !sameStringSet(lifecycleFilters.value, defaultLifecycleFilters.value)
    || !sameStringSet(analysisFilters.value, defaultAnalysisFilters)
    || !sameStringSet(selectedDependencyFilters.value, allDependencyFilterValues.value)
    || !sameStringSet(selectedTMRescoreProposalFilters.value, allTMRescoreFilterValues.value)
)

const filterSidebarProps = computed(() => ({
    filters: filterState.value,
    filterCounts: filterCounts.value,
    availableVersions: availableVersions.value,
    lifecycleOptions: LIFECYCLE_OPTIONS,
    analysisOptions: ANALYSIS_OPTIONS,
    copiedUrl: copiedUrl.value,
    filteredCount: sortedGroups.value.length,
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

const handleFilterUpdate = (newFilters: FilterState) => {
    sortBy.value = newFilters.sortBy
    sortOrder.value = newFilters.sortOrder
    dependencyFilter.value = newFilters.dependencyFilter
    tmrescoreProposalFilter.value = newFilters.tmrescoreFilter
    idFilter.value = newFilters.idFilter
    tagFilter.value = newFilters.tagFilter
    componentFilter.value = newFilters.componentFilter
    assigneeFilter.value = newFilters.assigneeFilter
    versionFilterInput.value = newFilters.versionFilterInput
    lifecycleFilters.value = newFilters.lifecycleFilters
    analysisFilters.value = newFilters.analysisFilters
    cvssVersionMismatchOnly.value = newFilters.cvssVersionMismatchOnly
    attributionAgeDays.value = normalizeAttributionAgeDays(newFilters.attributionAgeDays)
    attributionAgeMode.value = newFilters.attributionAgeMode === 'younger' ? 'younger' : 'older'
}

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
                        ref="searchInput"
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
                    <div><span class="font-semibold text-white">{{ sortedGroups.length }}</span> shown</div>
                    <div>{{ listItems.length }} total</div>
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
                    <div v-if="viewMode === 'analysis'" class="min-h-0 flex-1 space-y-2 overflow-y-auto pr-1">
                        <VulnRowCompact
                            v-for="group in visibleGroups"
                            :key="group.id"
                            :group="group"
                            :selected="selectedGroupId === group.id"
                            :data-group-id="group.id"
                            @select="selectGroup"
                            @update="handleTeamMappingUpdated"
                            @update:assessment="(data) => handleLocalAssessmentUpdate(group, data)"
                        />
                        <div
                            v-if="hasMoreGroups"
                            :ref="setLoadMoreTrigger"
                            class="flex min-h-14 items-center justify-center rounded-lg border border-dashed border-gray-700 bg-gray-900/60 text-xs font-semibold uppercase tracking-wide text-gray-500"
                        >
                            Showing {{ Math.min(visibleItemCount, sortedGroups.length) }} of {{ sortedGroups.length }}
                        </div>
                        <div v-if="sortedGroups.length === 0" class="text-gray-500 text-center py-16 font-medium min-h-[20rem] w-full min-w-full">No vulnerabilities found matching criteria.</div>
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
            <VulnDetailInspector
                v-if="selectedGroup"
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
            v-if="selectedGroup && viewMode === 'analysis' && !isDesktopInspector"
            class="fixed inset-0 z-[60] bg-gray-950/95 p-2"
        >
            <VulnDetailInspector
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
        :incomplete-groups="incompleteGroups"
        @close="showBulkModal = false"
        @updated="(updates) => handleBulkUpdates(updates, () => { showBulkModal = false })"
    />

    <BulkApproveModal
        :show="showBulkApproveModal"
        :needs-approval-groups="needsApprovalGroups"
        @close="showBulkApproveModal = false"
        @updated="handleBulkApproveModalUpdates"
    />
  </div>
</template>
