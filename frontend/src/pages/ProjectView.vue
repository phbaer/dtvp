<script setup lang="ts">
import { ref, watch, computed, inject, provide, onMounted, onUnmounted, onActivated, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { getGroupedVulns, getTeamMapping, getRescoreRules, getStatistics, getCacheStatus, getTMRescoreProposals } from '../lib/api'
import { getGroupLifecycle, tagToString, hasCvssVersionMismatch, normalizeTags } from '../lib/assessment-helpers'
import { classifyGroup, computeFilterCounts, computeTeamCounts, matchesFilters, getGroupTechnicalState } from '../lib/group-classifier'
import { calculateScoreFromVector } from '../lib/cvss'
import type { GroupedVuln, Statistics, CacheStatus, TMRescoreProposalSnapshot } from '../types'
import { projectHeaderState } from '../lib/projectHeaderStore'

import VulnGroupCard from '../components/VulnGroupCard.vue'
import BulkResolveIncompleteModal from '../components/BulkResolveIncompleteModal.vue'
import BulkApproveModal from '../components/BulkApproveModal.vue'
import ProjectStatistics from '../components/ProjectStatistics.vue'
import StatsSidebar from '../components/StatsSidebar.vue'
import type { FilterState } from '../components/FilterSidebar.vue'
import { BarChart3 } from 'lucide-vue-next'

const route = useRoute()
const router = useRouter()
const user = inject<any>('user', { role: 'ANALYST' })
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
const cacheStatus = ref<CacheStatus | null>(null)
const cacheStatusLoading = ref(false)
const cacheStatusError = ref('')
const now = ref<number>(Date.now())
const cacheStatusTimer = ref<number | null>(null)
const cacheStatusRefreshTimer = ref<number | null>(null)
const cacheStatusRefreshInProgress = ref(false)

const teamMapping = ref<Record<string, string | string[]>>({})
provide('teamMapping', teamMapping)

const rescoreRules = ref<any>(null)
provide('rescoreRules', rescoreRules)

const tmrescoreProposalSnapshot = ref<TMRescoreProposalSnapshot | null>(null)
provide('tmrescoreProposals', computed(() => tmrescoreProposalSnapshot.value?.proposals || {}))

const showBulkApproveModal = ref(false)
const needsApprovalGroups = computed(() => {
    return groups.value.filter(g => getDisplayState(g) === 'NEEDS_APPROVAL')
})

const tmrescoreProposalFilter = ref<Array<'WITH_PROPOSAL' | 'WITHOUT_PROPOSAL'>>(['WITH_PROPOSAL', 'WITHOUT_PROPOSAL'])
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

onUnmounted(() => {
    if (cacheStatusTimer.value !== null) {
        window.clearInterval(cacheStatusTimer.value)
    }
    if (cacheStatusRefreshTimer.value !== null) {
        window.clearInterval(cacheStatusRefreshTimer.value)
    }
})

const fetchRescoreRules = async () => {
    try {
        rescoreRules.value = await getRescoreRules()
    } catch (err) {
        console.error('Failed to fetch rescore rules:', err)
    }
}

const cacheLastRefreshedDate = computed(() => {
    if (!cacheStatus.value?.last_refreshed_at) return null
    const date = new Date(cacheStatus.value.last_refreshed_at)
    return Number.isNaN(date.getTime()) ? null : date
})

const cacheAgeSeconds = computed(() => {
    if (!cacheLastRefreshedDate.value) return null
    return Math.max(0, Math.floor((now.value - cacheLastRefreshedDate.value.getTime()) / 1000))
})

const cacheAgeLabel = computed(() => {
    if (cacheAgeSeconds.value === null) return ''
    if (cacheAgeSeconds.value < 60) {
        return '< 1 min ago'
    }
    const minutes = Math.floor(cacheAgeSeconds.value / 60)
    if (minutes < 60) {
        return `${minutes}m ago`
    }
    const hours = Math.floor(minutes / 60)
    return `${hours}h ago`
})

const cacheStatusText = computed(() => {
    if (cacheStatusLoading.value && !cacheStatus.value) {
        return 'Loading…'
    }
    if (!cacheStatus.value) {
        return cacheStatusError.value || 'Unknown'
    }

    const age = cacheAgeLabel.value ? `updated ${cacheAgeLabel.value}` : 'updated Unknown'
    const statusLabel = cacheStatus.value.fully_cached ? 'Cache in sync' : 'Partially cached'
    return `${statusLabel}\n${age}`
})

const cacheStatusState = computed<'cached' | 'partial' | 'unknown' | 'loading'>(() => {
    if (cacheStatusLoading.value && !cacheStatus.value) return 'loading'
    if (cacheStatusError.value || !cacheStatus.value) return 'unknown'
    return cacheStatus.value.fully_cached ? 'cached' : 'partial'
})

const cacheStatusLabel = computed(() => {
    if (cacheStatusLoading.value && !cacheStatus.value) return 'Loading…'
    if (!cacheStatus.value) return cacheStatusError.value || 'Cache out of sync'
    return cacheStatus.value.fully_cached ? 'Cache in sync' : 'Partially cached'
})

const cacheStatusAge = computed(() => {
    if (!cacheStatus.value) {
        return cacheStatusLoading.value ? '' : (cacheStatusError.value || '')
    }
    return cacheAgeLabel.value ? `updated ${cacheAgeLabel.value}` : 'updated Unknown'
})

const fetchCacheStatus = async () => {
    if (cacheStatusRefreshInProgress.value) return
    cacheStatusRefreshInProgress.value = true

    const showLoading = !cacheStatus.value
    if (showLoading) cacheStatusLoading.value = true
    cacheStatusError.value = ''
    try {
        cacheStatus.value = await getCacheStatus()
    } catch (err: any) {
        cacheStatusError.value = 'Unable to load cache freshness'
        console.error('Failed to fetch cache status:', err)
    } finally {
        if (showLoading) cacheStatusLoading.value = false
        cacheStatusRefreshInProgress.value = false
    }
}

const consumeThreatModelRefreshSignal = () => {
    const name = route.params.name as string
    if (!name || name === '_all_' || typeof window === 'undefined' || !window.sessionStorage) {
        return false
    }

    const key = `dtvp:tmrescore-refresh:${name}`
    const hasSignal = !!window.sessionStorage.getItem(key)
    if (hasSignal) {
        window.sessionStorage.removeItem(key)
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
    fetchCacheStatus()

    cacheStatusTimer.value = window.setInterval(() => {
        now.value = Date.now()
    }, 1000)
    cacheStatusRefreshTimer.value = window.setInterval(() => {
        fetchCacheStatus().catch(() => {})
    }, 5000)
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
            // Always recalculate scores from vectors using the standard CVSS library
            if (g.cvss_vector) {
                const computed = calculateScoreFromVector(g.cvss_vector)
                if (computed !== null) {
                    g.cvss_score = computed
                    if (!g.cvss) g.cvss = computed
                }
            }
            if (g.rescored_vector) {
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

const handleLocalAssessmentUpdate = (group: GroupedVuln, data: any) => {
    const groupId = group.id
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
    
    // Force top-level reactivity by replacing the group object itself with a new reference
    const idx = groups.value.findIndex((g: any) => g.id === group.id)
    if (idx !== -1) {
        groups.value[idx] = { ...group }
    }
    groups.value = [...groups.value]

    // After Vue re-renders with new sort order, scroll the updated card back into view
    nextTick(() => {
        const el = document.querySelector(`[data-group-id="${groupId.replace(/"/g, '\\"')}"]`)
        if (el) {
            el.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
        }
    })

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

const showBulkModal = ref(false)
projectHeaderState.bulkSyncHandler.value = () => {
    showBulkModal.value = true
}
const incompleteGroups = computed(() => {
    return groups.value.filter(g => getDisplayState(g) === 'INCOMPLETE')
})

const handleBulkApproveModalUpdates = (updates: Array<{ id: string; data: any }>) => {
    handleBulkUpdates(updates, () => { showBulkApproveModal.value = false })
}

const expandedGroupIds = ref(new Set<string>())
const handleToggleExpand = (id: string, expanded: boolean) => {
    if (expanded) {
        expandedGroupIds.value.add(id)
    } else {
        expandedGroupIds.value.delete(id)
    }
}

const tagFilter = ref('')
const idFilter = ref('')
const componentFilter = ref('')
const assigneeFilter = ref('')
const dependencyFilter = ref<Array<'DIRECT' | 'TRANSITIVE' | 'UNKNOWN'>>(['DIRECT', 'TRANSITIVE', 'UNKNOWN'])
const cvssVersionMismatchOnly = ref(false)

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

const availableVersions = computed(() => {
    const allVersions = new Set<string>()
    groups.value.forEach(g => {
        (g.affected_versions || []).forEach((v: any) => {
            if (typeof v.project_version === 'string' && v.project_version.trim().length > 0) {
                allVersions.add(v.project_version.trim())
            }
        })
    })
    return Array.from(allVersions).sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }))
})


const filterUrl = computed(() => {
    const query: Record<string, string | string[]> = {
        ...(route.query as Record<string, string | string[]>)
    }

    if (dependencyFilter.value.length > 0) {
        query.dependency = dependencyFilter.value
    } else {
        delete query.dependency
    }

    if (versionFilterInput.value) {
        query.versions = versionFilterInput.value
    } else {
        delete query.versions
    }

    if (tmrescoreProposalFilter.value.length > 0) {
        query.tmrescore = tmrescoreProposalFilter.value
    } else {
        delete query.tmrescore
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

onMounted(() => {
    const q = route.query
    const hasFilterParams = Object.entries(q).some(([k, v]) => {
        if (!['lifecycle', 'analysis', 'tag', 'id', 'cve', 'component', 'assignee', 'sort', 'order', 'tmrescore'].includes(k)) return false;
        if (Array.isArray(v)) return v.length > 0;
        return v !== undefined && v !== null && v !== '';
    })

    if (hasFilterParams) {
        if (q.lifecycle) lifecycleFilters.value = (Array.isArray(q.lifecycle) ? q.lifecycle : [q.lifecycle]) as string[]
        else lifecycleFilters.value = (user?.value?.role === 'REVIEWER')
            ? ['OPEN', 'ASSESSED', 'INCOMPLETE', 'INCONSISTENT', 'NEEDS_APPROVAL']
            : ['OPEN']
        
        if (q.analysis) analysisFilters.value = (Array.isArray(q.analysis) ? q.analysis : [q.analysis]) as string[]
        else analysisFilters.value = ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED']
        
        if (q.tag) tagFilter.value = q.tag as string
        if (q.id) idFilter.value = q.id as string
        else if (q.cve) idFilter.value = q.cve as string

        if (q.component) componentFilter.value = q.component as string
        if (q.assignee) assigneeFilter.value = q.assignee as string
        if (q.dependency) dependencyFilter.value = Array.isArray(q.dependency) ? (q.dependency as string[]).map(v => v.toUpperCase() as 'DIRECT'|'TRANSITIVE'|'UNKNOWN') : [(q.dependency as string).toUpperCase() as 'DIRECT'|'TRANSITIVE'|'UNKNOWN']
        if (q.versions) versionFilterInput.value = Array.isArray(q.versions) ? q.versions.join(',') : (q.versions as string)
        if (q.tmrescore) tmrescoreProposalFilter.value = Array.isArray(q.tmrescore) ? (q.tmrescore as string[]).map(v => v.toUpperCase() as 'WITH_PROPOSAL' | 'WITHOUT_PROPOSAL') : [String(q.tmrescore).toUpperCase() as 'WITH_PROPOSAL' | 'WITHOUT_PROPOSAL']
        if (q.cvss_mismatch === 'true') cvssVersionMismatchOnly.value = true
        if (q.sort) sortBy.value = q.sort as string
        if (q.order) sortOrder.value = q.order as 'asc' | 'desc'
    } else {
        resetFilters()
    }
})

// If the user switches between reviewer and analyst, reapply defaults for lifecycle/analysis
watch(() => user?.value?.role, (newRole, oldRole) => {
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
    
    if (user?.value?.role === 'REVIEWER') {
        lifecycleFilters.value = ['OPEN', 'ASSESSED', 'ASSESSED_LEGACY', 'INCOMPLETE', 'INCONSISTENT', 'NEEDS_APPROVAL']
    } else {
        lifecycleFilters.value = ['OPEN']
    }
    idFilter.value = ''
    tagFilter.value = ''
    componentFilter.value = ''
    assigneeFilter.value = ''
    dependencyFilter.value = ['DIRECT', 'TRANSITIVE', 'UNKNOWN']
    tmrescoreProposalFilter.value = ['WITH_PROPOSAL', 'WITHOUT_PROPOSAL']
    versionFilterInput.value = ''
    cvssVersionMismatchOnly.value = false
    sortBy.value = 'rescored-severity'
    sortOrder.value = 'desc'
}

// Filter state now remains local in the frontend and does not cause backend re-fetch.
// This reduces unnecessary chattiness and keeps filtering fast and responsive.
// URL sync was removed to avoid automatic API refresh for every filter tweak.

watch([lifecycleFilters, analysisFilters, tagFilter, idFilter, componentFilter, assigneeFilter, dependencyFilter, tmrescoreProposalFilter, versionFilterInput, cvssVersionMismatchOnly, sortBy, sortOrder], () => {
    const query = { ...route.query }

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

    if (dependencyFilter.value.length > 0) query.dependency = dependencyFilter.value
    else delete query.dependency

    if (versionFilterInput.value) query.versions = versionFilterInput.value
    else delete query.versions

    if (tmrescoreProposalFilter.value.length > 0) query.tmrescore = tmrescoreProposalFilter.value
    else delete query.tmrescore

    if (cvssVersionMismatchOnly.value) query.cvss_mismatch = 'true'
    else delete query.cvss_mismatch

    query.sort = sortBy.value
    query.order = sortOrder.value

    router.replace({ query }).catch(() => {})
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


const getDisplayState = (group: GroupedVuln): string => {
    return getGroupLifecycle(group, group.tags || [], teamMapping.value)
}

const getGroupDependencyRelationship = (group: GroupedVuln): 'DIRECT' | 'TRANSITIVE' | 'UNKNOWN' => {
    const directFlags = (group.affected_versions || [])
        .flatMap(v => (v.components || []).map(c => c.is_direct_dependency))
        .filter((x): x is boolean => x === true || x === false)

    if (directFlags.includes(true)) return 'DIRECT'
    if (directFlags.includes(false)) return 'TRANSITIVE'
    return 'UNKNOWN'
}

const isMeaningfulTMRescoreProposal = (group: GroupedVuln, proposal: any) => {
    const rescoredVector = proposal?.rescored_vector || null
    const originalVector = proposal?.original_vector || group.cvss_vector || null
    if (!rescoredVector) return false
    return !originalVector || rescoredVector !== originalVector
}

const hasTMRescoreProposal = (group: GroupedVuln) => {
    const proposals = tmrescoreProposalSnapshot.value?.proposals || {}
    const candidateIds = [group.id, ...(group.aliases || [])]
    return candidateIds.some((candidateId) => {
        const normalized = String(candidateId || '').trim().toUpperCase()
        return normalized && isMeaningfulTMRescoreProposal(group, proposals[normalized])
    })
}

// Groups after applying all non-lifecycle/non-analysis filters (used for filter counts)
const preFilteredGroups = computed(() => {
    let result = [...groups.value]
    
    const rawTagFilter = tagFilter.value.trim().toLowerCase()
    if (rawTagFilter) {
        result = result.filter(g => {
            const rawTags = (g.tags || []).map(tagToString).filter(Boolean)
            const normalized = teamMapping.value ? normalizeTags(g.tags || [], teamMapping.value) : []
            const allTags = Array.from(new Set([...rawTags, ...normalized]))
            return allTags.some(tag => tag.toLowerCase().includes(rawTagFilter))
        })
    }

    if (dependencyFilter.value.length === 0) {
        return []
    }

    if (tmrescoreProposalFilter.value.length === 0) {
        return []
    }

    if (dependencyFilter.value.length > 0) {
        result = result.filter(g => dependencyFilter.value.includes(getGroupDependencyRelationship(g)))
    }

    if (tmrescoreProposalFilter.value.length > 0) {
        result = result.filter(g => {
            const hasProposal = hasTMRescoreProposal(g)
            const matchesWith = tmrescoreProposalFilter.value.includes('WITH_PROPOSAL') && hasProposal
            const matchesWithout = tmrescoreProposalFilter.value.includes('WITHOUT_PROPOSAL') && !hasProposal
            return matchesWith || matchesWithout
        })
    }

    if (versionFilterList.value.length > 0) {
        result = result.filter(g => {
            const available = (g.affected_versions || []).map((v: any) => v.project_version).filter((x: any) => !!x)
            return versionFilterList.value.some(v => available.includes(v))
        })
    }

    if (idFilter.value) {
        const term = idFilter.value.toLowerCase()
        result = result.filter(g => 
            g.id.toLowerCase().includes(term)
        )
    }

    if (componentFilter.value) {
        const term = componentFilter.value.toLowerCase()
        result = result.filter((g: any) => 
            g.affected_versions.some((v: any) => 
                v.components.some((c: any) => c.component_name.toLowerCase().includes(term))
            )
        )
    }

    if (assigneeFilter.value) {
        const term = assigneeFilter.value.trim().toLowerCase()
        result = result.filter(g =>
            (g.assignees || []).some((a: string) => a.toLowerCase().includes(term))
        )
    }

    if (cvssVersionMismatchOnly.value) {
        result = result.filter(g => hasCvssVersionMismatch(g))
    }

    return result
})

const filteredGroups = computed(() => {
    let result = preFilteredGroups.value

    result = result.filter(g => {
        return matchesFilters(g, lifecycleFilters.value, analysisFilters.value, teamMapping.value)
    })


    result.sort((a, b) => {
        let comparison = 0
        
        switch (sortBy.value) {
            case 'analysis': {
                const stateA = getGroupTechnicalState(a)
                const stateB = getGroupTechnicalState(b)
                comparison = (ANALYSIS_STATE_ORDER[stateA] ?? 99) - (ANALYSIS_STATE_ORDER[stateB] ?? 99)
                break
            }
            case 'tags': {
                const tagsA = teamMapping.value ? normalizeTags(a.tags || [], teamMapping.value) : (a.tags || []).map(tagToString).filter(Boolean)
                const tagsB = teamMapping.value ? normalizeTags(b.tags || [], teamMapping.value) : (b.tags || []).map(tagToString).filter(Boolean)
                const tagA = tagsA.length > 0 ? tagsA[0] : ''
                const tagB = tagsB.length > 0 ? tagsB[0] : ''
                comparison = tagA.localeCompare(tagB)
                break
            }
            case 'severity': {
                const baseA = a.cvss_score ?? a.cvss
                const baseB = b.cvss_score ?? b.cvss
                // Negate so that desc = most critical first (CRITICAL=0 is highest priority)
                comparison = scoreSeverityOrder(baseB) - scoreSeverityOrder(baseA)
                break
            }
            case 'rescored-severity': {
                const rA = a.rescored_cvss ?? a.cvss_score ?? a.cvss
                const rB = b.rescored_cvss ?? b.cvss_score ?? b.cvss
                // Negate so that desc = most critical first (CRITICAL=0 is highest priority)
                comparison = scoreSeverityOrder(rB) - scoreSeverityOrder(rA)
                break
            }
            case 'rescored-severity': {
                const rA = a.rescored_cvss ?? a.cvss_score ?? a.cvss
                const rB = b.rescored_cvss ?? b.cvss_score ?? b.cvss
                comparison = scoreSeverityOrder(rA) - scoreSeverityOrder(rB)
                break
            }
            case 'score': {
                const scoreA = a.cvss_score ?? a.cvss ?? 0
                const scoreB = b.cvss_score ?? b.cvss ?? 0
                comparison = scoreA - scoreB
                break
            }
            case 'rescored': {
                const scoreA = a.rescored_cvss ?? a.cvss_score ?? a.cvss ?? 0
                const scoreB = b.rescored_cvss ?? b.cvss_score ?? b.cvss ?? 0
                comparison = scoreA - scoreB
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


const filterCounts = computed(() => {
    return computeFilterCounts(groups.value, teamMapping.value, lifecycleFilters.value)
})

const cvssVersionMismatchCount = computed(() => {
    return groups.value.filter(g => hasCvssVersionMismatch(g)).length
})

const teamTagCounts = computed(() => {
    return computeTeamCounts(groups.value, teamMapping.value)
})

const teamTagList = computed(() => {
    return Object.entries(teamTagCounts.value)
        .map(([team, counts]) => ({ team, ...counts }))
        .sort((a, b) => a.team.localeCompare(b.team))
})

const groupsAfterLifecycle = computed(() => {
    if (lifecycleFilters.value.length === 0) return groups.value

    return groups.value.filter(g => {
        const c = classifyGroup(g, teamMapping.value)
        return (
            (lifecycleFilters.value.includes('OPEN') && c.isOpen) ||
            (lifecycleFilters.value.includes('NEEDS_APPROVAL') && c.isPending) ||
            lifecycleFilters.value.includes(c.lifecycle)
        )
    })
})

const groupsAfterLifecycleAndDependency = computed(() => {
    if (dependencyFilter.value.length === 0) return groupsAfterLifecycle.value
    return groupsAfterLifecycle.value.filter(g => dependencyFilter.value.includes(getGroupDependencyRelationship(g)))
})

const groupsBeforeAnalysis = computed(() => {
    if (tmrescoreProposalFilter.value.length === 0) return groupsAfterLifecycleAndDependency.value

    const proposals = tmrescoreProposalSnapshot.value?.proposals || {}
    return groupsAfterLifecycleAndDependency.value.filter(g => {
        const candidateIds = [g.id, ...(g.aliases || [])]
        const hasProposal = candidateIds.some((candidateId) => {
            const normalized = String(candidateId || '').trim().toUpperCase()
            return normalized && isMeaningfulTMRescoreProposal(g, proposals[normalized])
        })
        const matchesWith = tmrescoreProposalFilter.value.includes('WITH_PROPOSAL') && hasProposal
        const matchesWithout = tmrescoreProposalFilter.value.includes('WITHOUT_PROPOSAL') && !hasProposal
        return matchesWith || matchesWithout
    })
})
const dependencyFilterCounts = computed(() => {
    const counts = { direct: 0, transitive: 0, unknown: 0 }
    groupsAfterLifecycle.value.forEach(g => {
        const relationship = getGroupDependencyRelationship(g).toLowerCase() as 'direct' | 'transitive' | 'unknown'
        counts[relationship]++
    })
    return counts
})

const dependencyRelationshipCounts = computed(() => {
    const counts = { direct: 0, transitive: 0, unknown: 0 }
    filteredGroups.value.forEach(g => {
        const relationship = getGroupDependencyRelationship(g).toLowerCase() as 'direct' | 'transitive' | 'unknown'
        counts[relationship]++
    })
    return counts
})

const tmrescoreProposalCounts = computed(() => {
    const counts: Record<string, number> = {
        WITH_PROPOSAL: 0,
        WITHOUT_PROPOSAL: 0,
    }
    groupsAfterLifecycleAndDependency.value.forEach(g => {
        const proposals = tmrescoreProposalSnapshot.value?.proposals || {}
        const candidateIds = [g.id, ...(g.aliases || [])]
        const hasProposal = candidateIds.some((candidateId) => {
            const normalized = String(candidateId || '').trim().toUpperCase()
            return normalized && isMeaningfulTMRescoreProposal(g, proposals[normalized])
        })

        if (hasProposal) counts.WITH_PROPOSAL++
        else counts.WITHOUT_PROPOSAL++
    })
    return counts
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
    groupsBeforeAnalysis.value.forEach(g => {
        const state = getGroupTechnicalState(g)
        counts[state] = (counts[state] || 0) + 1
    })
    return counts
})

const filterState = computed<FilterState>(() => ({
    sortBy: sortBy.value,
    sortOrder: sortOrder.value,
    dependencyFilter: dependencyFilter.value,
    tmrescoreFilter: tmrescoreProposalFilter.value,
    idFilter: idFilter.value,
    tagFilter: tagFilter.value,
    componentFilter: componentFilter.value,
    assigneeFilter: assigneeFilter.value,
    versionFilterInput: versionFilterInput.value,
    lifecycleFilters: lifecycleFilters.value,
    analysisFilters: analysisFilters.value,
    cvssVersionMismatchOnly: cvssVersionMismatchOnly.value,
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
}

const syncProjectHeaderState = () => {
    const name = route.params.name as string
    projectHeaderState.currentProjectName.value = name === '_all_' ? null : name
    projectHeaderState.isAllProjects.value = name === '_all_'
    projectHeaderState.isReviewer.value = (user?.role || 'ANALYST') === 'REVIEWER'
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

watch(() => user?.role, (role) => {
    projectHeaderState.isReviewer.value = (role || 'ANALYST') === 'REVIEWER'
}, { immediate: true })
</script>

<template>
  <div class="overflow-x-visible min-h-0">
    <div class="grid min-w-full w-full gap-y-10 pt-2.5 lg:pt-0 lg:gap-x-4 pb-8">
        <div class="flex-1 min-w-[20rem] max-w-full w-full pl-0 lg:pl-0 lg:-ml-2 lg:pr-[425px]">
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
            <div v-else class="shadow-xl bg-white/2 border border-white/5 rounded-2xl backdrop-blur-sm overflow-hidden">
                <div class="p-3 space-y-3">
                    <div v-if="viewMode === 'analysis'" class="space-y-3">
                        <VulnGroupCard
                            v-for="group in filteredGroups"
                            :key="group.id"
                            :group="group"
                            :data-group-id="group.id"
                            @update:assessment="(data) => handleLocalAssessmentUpdate(group, data)"
                            @toggle-expand="(id, expanded) => handleToggleExpand(id, expanded)"
                        />
                        <div v-if="filteredGroups.length === 0" class="text-gray-500 text-center py-16 font-medium min-h-[20rem] w-full min-w-full">No vulnerabilities found matching criteria.</div>
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

        <div class="hidden lg:block lg:fixed lg:top-24 lg:right-0 lg:w-[440px] lg:pr-4 lg:max-h-[calc(100vh-10rem)] overflow-y-auto">
            <StatsSidebar
                :filters="filterState"
                :filterCounts="filterCounts"
                :availableVersions="availableVersions"
                :lifecycleOptions="LIFECYCLE_OPTIONS"
                :analysisOptions="ANALYSIS_OPTIONS"
                :copiedUrl="copiedUrl"
                :filteredCount="filteredGroups.length"
                :dependencyCounts="dependencyRelationshipCounts"
                :dependencyFilterCounts="dependencyFilterCounts"
                :tmrescoreCounts="tmrescoreProposalCounts"
                :analysisCounts="analysisCounts"
                :teamTagList="teamTagList"
                :cacheStatusState="cacheStatusState"
                :cacheStatusLabel="cacheStatusLabel"
                :cacheStatusAge="cacheStatusAge"
                :cacheStatusTooltip="cacheStatusText"
                :cacheStatusDetail="cacheStatus"
                :sortOptions="SORT_OPTIONS"
                :dependencyOptions="DEPENDENCY_OPTIONS"
                :tmrescoreOptions="TMRESCORE_FILTER_OPTIONS"
                :cvssVersionMismatchCount="cvssVersionMismatchCount"
                @update:filters="handleFilterUpdate"
                @copy-filter-url="copyFilterUrl"
            />
        </div>
    </div>

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

