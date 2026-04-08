<script setup lang="ts">
import { ref, watch, computed, inject, provide, onMounted, onUnmounted, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { getGroupedVulns, getTeamMapping, getRescoreRules, getStatistics } from '../lib/api'
import { getGroupLifecycle, isPendingReview as isPendingReviewHelper, matchesFilters, getGroupTechnicalState, tagToString } from '../lib/assessment-helpers'
import { calculateScoreFromVector } from '../lib/cvss'
import type { GroupedVuln, Statistics } from '../types'

import VulnGroupCard from '../components/VulnGroupCard.vue'
import BulkResolveIncompleteModal from '../components/BulkResolveIncompleteModal.vue'
import BulkApproveModal from '../components/BulkApproveModal.vue'
import ProjectStatistics from '../components/ProjectStatistics.vue'
import CustomSelect from '../components/CustomSelect.vue'
import { BarChart3, Layers, ChevronLeft, ShieldCheck, LayoutList, Copy } from 'lucide-vue-next'

const route = useRoute()
const router = useRouter()
const user = inject<any>('user')
const groups = ref<GroupedVuln[]>([])
const loading = ref(true)
const error = ref('')
const loadingMessage = ref('Initializing...')
const loadingProgress = ref(0)
const loadingLog = ref<string[]>([])
const logContainer = ref<HTMLElement | null>(null)
const viewMode = ref<'analysis' | 'statistics'>('analysis')
const stats = ref<Statistics | null>(null)
const statsLoading = ref(false)
const statsError = ref('')
const statsDirty = ref(false)

const teamMapping = ref<Record<string, string | string[]>>({})
provide('teamMapping', teamMapping)

const rescoreRules = ref<any>(null)
provide('rescoreRules', rescoreRules)

const isFilterCollapsed = ref(false)

const fetchTeamMapping = async () => {
    try {
        teamMapping.value = await getTeamMapping()
    } catch (err) {
        console.error('Failed to fetch team mapping:', err)
    }
}


const selectedLifecycleOptions = computed(() => {
    return LIFECYCLE_OPTIONS.filter(opt => lifecycleFilters.value.includes(opt.value))
})

const selectedAnalysisOptions = computed(() => {
    return ANALYSIS_OPTIONS.filter(opt => analysisFilters.value.includes(opt.value))
})

const onScroll = () => {
    isFilterCollapsed.value = window.scrollY > 160
}

onMounted(() => {
    window.addEventListener('scroll', onScroll, { passive: true })
})

onUnmounted(() => {
    window.removeEventListener('scroll', onScroll)
})

const fetchRescoreRules = async () => {
    try {
        rescoreRules.value = await getRescoreRules()
    } catch (err) {
        console.error('Failed to fetch rescore rules:', err)
    }
}

onMounted(() => {
    fetchTeamMapping()
    fetchRescoreRules()
})

// Auto-scroll the loading log to the bottom when new entries appear
watch(() => loadingLog.value.length, () => {
    nextTick(() => {
        if (logContainer.value) {
            logContainer.value.scrollTop = logContainer.value.scrollHeight
        }
    })
})

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
        const data = await getGroupedVulns(apiName, undefined, (msg, progress, log) => {
            loadingMessage.value = msg
            loadingProgress.value = progress
            if (log && log.length > 0) {
                loadingLog.value = log
            } else if (msg && (loadingLog.value.length === 0 || loadingLog.value[loadingLog.value.length - 1] !== msg)) {
                loadingLog.value.push(msg)
            }
        })
        
        // Ensure rescored_cvss is populated if rescored_vector exists
        groups.value = data.map(g => {
            if (!g.rescored_cvss && g.rescored_vector) {
                g.rescored_cvss = calculateScoreFromVector(g.rescored_vector)
            }
            return g
        })
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
    group.rescored_cvss = data.rescored_cvss
    group.rescored_vector = data.rescored_vector

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
const showBulkApproveModal = ref(false)
const incompleteGroups = computed(() => {
    return groups.value.filter(g => getDisplayState(g) === 'INCOMPLETE')
})

const needsApprovalGroups = computed(() => {
    return groups.value.filter(g => {
        return (g.affected_versions || []).some(v => 
            (v.components || []).some(c => (c.analysis_details || '').includes('[Status: Pending Review]'))
        )
    })
})

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
const dependencyFilter = ref<'ALL' | 'DIRECT' | 'TRANSITIVE' | 'UNKNOWN'>('ALL')

const SORT_OPTIONS = [
    { value: 'severity', label: 'Criticality' },
    { value: 'score', label: 'Score' },
    { value: 'analysis', label: 'Analysis' },
    { value: 'tags', label: 'Tags' },
    { value: 'id', label: 'CVE ID' },
] as const
const DEPENDENCY_OPTIONS = [
    { value: 'ALL', label: 'All' },
    { value: 'DIRECT', label: 'Direct' },
    { value: 'TRANSITIVE', label: 'Transitive' },
    { value: 'UNKNOWN', label: 'Unknown' },
] as const
const versionFilterInput = ref('')
const versionSearch = ref('')
const versionSearchInput = ref<HTMLInputElement | null>(null)
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

const filteredVersionOptions = computed(() => {
    const query = versionSearch.value.trim().toLowerCase()
    return availableVersions.value.filter(ver => {
        if (query && !ver.toLowerCase().includes(query)) return false
        return true
    })
})

const toggleVersion = (version: string) => {
    const list = versionFilterList.value
    const idx = list.findIndex(v => v.toLowerCase() === version.toLowerCase())
    if (idx >= 0) {
        const newList = [...list]
        newList.splice(idx, 1)
        versionFilterInput.value = newList.join(', ')
    } else {
        versionFilterInput.value = list.length ? `${list.join(', ')}, ${version}` : version
    }
    versionSearch.value = ''
}

const removeVersion = (version: string) => {
    const newList = versionFilterList.value.filter(v => v.toLowerCase() !== version.toLowerCase())
    versionFilterInput.value = newList.join(', ')
}


const filterUrl = computed(() => {
    const query: Record<string, string | string[]> = {
        ...(route.query as Record<string, string | string[]>)
    }

    if (dependencyFilter.value && dependencyFilter.value !== 'ALL') {
        query.dependency = dependencyFilter.value
    } else {
        delete query.dependency
    }

    if (versionFilterInput.value) {
        query.versions = versionFilterInput.value
    } else {
        delete query.versions
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
const sortBy = ref('severity')
const sortOrder = ref<'asc' | 'desc'>('asc')

onMounted(() => {
    const q = route.query
    const hasFilterParams = Object.entries(q).some(([k, v]) => {
        if (!['lifecycle', 'analysis', 'tag', 'id', 'cve', 'component', 'sort', 'order'].includes(k)) return false;
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
        if (q.dependency) dependencyFilter.value = (q.dependency as string).toUpperCase() as 'ALL'|'DIRECT'|'TRANSITIVE'|'UNKNOWN'
        if (q.versions) versionFilterInput.value = Array.isArray(q.versions) ? q.versions.join(',') : (q.versions as string)
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
    dependencyFilter.value = 'ALL'
    versionFilterInput.value = ''
    versionSearch.value = ''
    sortBy.value = 'severity'
    sortOrder.value = 'asc'
}

// Filter state now remains local in the frontend and does not cause backend re-fetch.
// This reduces unnecessary chattiness and keeps filtering fast and responsive.
// URL sync was removed to avoid automatic API refresh for every filter tweak.

watch([lifecycleFilters, analysisFilters, tagFilter, idFilter, componentFilter, dependencyFilter, versionFilterInput, sortBy, sortOrder], () => {
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

    if (dependencyFilter.value && dependencyFilter.value !== 'ALL') query.dependency = dependencyFilter.value
    else delete query.dependency

    if (versionFilterInput.value) query.versions = versionFilterInput.value
    else delete query.versions

    query.sort = sortBy.value
    query.order = sortOrder.value

    router.replace({ query }).catch(() => {})
}, { deep: true })

const LIFECYCLE_OPTIONS = [
    { value: 'OPEN', label: 'Open', color: 'bg-amber-500', description: 'No global assessment AND at least one team assessment is missing' },
    { value: 'ASSESSED', label: 'Assessed', color: 'bg-blue-600', description: 'Approved assessments with a global assessment' },
    { value: 'ASSESSED_LEGACY', label: 'Assessed (Legacy)', color: 'bg-sky-600', description: 'Legacy assessments without structured DTvP format' },
    { value: 'INCOMPLETE', label: 'Incomplete', color: 'bg-amber-700', description: 'Some assessment for some version is missing, the others are identical' },
    { value: 'INCONSISTENT', label: 'Inconsistent', color: 'bg-indigo-600', description: 'Different assessments for at least two versions; empty assessments don\'t count' },
    { value: 'NEEDS_APPROVAL', label: 'Needs Approval', color: 'bg-purple-600', description: 'When there\'s a need for an approval (flag)' }
]

const ANALYSIS_OPTIONS = [
    { value: 'NOT_SET', label: 'Not Set', color: 'bg-gray-600' },
    { value: 'EXPLOITABLE', label: 'Exploitable', color: 'bg-red-600' },
    { value: 'IN_TRIAGE', label: 'In Triage', color: 'bg-amber-400' },
    { value: 'RESOLVED', label: 'Resolved', color: 'bg-green-600' },
    { value: 'FALSE_POSITIVE', label: 'False Positive', color: 'bg-teal-600' },
    { value: 'NOT_AFFECTED', label: 'Not Affected', color: 'bg-slate-600' }
]

const toggleLifecycleFilter = (val: string) => {
    if (lifecycleFilters.value.includes(val)) {
        lifecycleFilters.value = lifecycleFilters.value.filter(s => s !== val)
    } else {
        lifecycleFilters.value.push(val)
    }
}

const toggleAnalysisFilter = (val: string) => {
    if (analysisFilters.value.includes(val)) {
        analysisFilters.value = analysisFilters.value.filter(s => s !== val)
    } else {
        analysisFilters.value.push(val)
    }
}

const SEVERITY_ORDER: Record<string, number> = {
    'CRITICAL': 0,
    'HIGH': 1,
    'MEDIUM': 2,
    'LOW': 3,
    'INFO': 4,
    'UNKNOWN': 5
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

// Groups after applying all non-lifecycle/non-analysis filters (used for filter counts)
const preFilteredGroups = computed(() => {
    let result = [...groups.value]
    
    const rawTagFilter = tagFilter.value.trim().toLowerCase()
    if (rawTagFilter) {
        result = result.filter(g => {
            return g.tags?.some(t => {
                const tagText = tagToString(t)
                return tagText.toLowerCase().includes(rawTagFilter)
            })
        })
    }

    if (dependencyFilter.value !== 'ALL') {
        result = result.filter(g => getGroupDependencyRelationship(g) === dependencyFilter.value)
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
                const tagA = (a.tags && a.tags.length > 0) ? tagToString(a.tags[0]) : ''
                const tagB = (b.tags && b.tags.length > 0) ? tagToString(b.tags[0]) : ''
                comparison = tagA.localeCompare(tagB)
                break
            }
            case 'severity': {
                const sevA = a.severity || 'UNKNOWN'
                const sevB = b.severity || 'UNKNOWN'
                comparison = (SEVERITY_ORDER[sevA] ?? 5) - (SEVERITY_ORDER[sevB] ?? 5)
                break
            }
            case 'score': {
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
    const counts: Record<string, number> = {
        OPEN: 0,
        ASSESSED: 0,
        ASSESSED_LEGACY: 0,
        INCOMPLETE: 0,
        INCONSISTENT: 0,
        NOT_SET: 0,
        EXPLOITABLE: 0,
        IN_TRIAGE: 0,
        RESOLVED: 0,
        FALSE_POSITIVE: 0,
        NOT_AFFECTED: 0,
        NEEDS_APPROVAL: 0
    }

    preFilteredGroups.value.forEach(g => {
        const state = getDisplayState(g)
        const isPendingGroup = isPendingReviewHelper(g)

        // 1. Lifecycle counts (Global)
        if (state === 'OPEN') counts.OPEN++
        if (state === 'ASSESSED') counts.ASSESSED++
        if (state === 'ASSESSED_LEGACY') counts.ASSESSED_LEGACY++
        if (state === 'INCOMPLETE') counts.INCOMPLETE++
        if (state === 'INCONSISTENT') counts.INCONSISTENT++

        // 2. Analysis counts (Hierarchical: respect Lifecycle filters)
        // We use a simplified version of matchesFilters logic here for counts
        const lifecycleActiveMatch = lifecycleFilters.value.length === 0 || lifecycleFilters.value.includes(state) || (lifecycleFilters.value.includes('NEEDS_APPROVAL') && isPendingGroup)
        
        if (lifecycleActiveMatch) {
            const techState = getGroupTechnicalState(g)
            counts[techState]++
        }

        // 3. Needs Approval count (Global)
        if (isPendingGroup) counts.NEEDS_APPROVAL++
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

watch(() => route.params.name, () => {
    fetchVulns()
    if (viewMode.value === 'statistics') {
        fetchStats()
    } else {
        stats.value = null // Reset stats to force refresh if they toggle back
    }
}, { immediate: true })
</script>

<template>
  <div class="mx-auto">
    <transition name="overlay-fade">
      <div v-if="isFilterCollapsed" class="fixed top-0 left-0 right-0 z-50 bg-gray-900/70 border-b border-white/10 backdrop-blur-md px-0 py-2 pointer-events-none text-left">
        <div class="w-full max-w-7xl px-4">
          <div class="flex flex-wrap items-start justify-start gap-2 text-xs text-gray-300 mb-1">
            <span class="font-bold text-gray-400">Lifecycle:</span>
            <template v-if="selectedLifecycleOptions.length">
              <span v-for="opt in selectedLifecycleOptions" :key="`top-lc-${opt.value}`" :class="[opt.color, 'text-white text-[10px] font-semibold px-2 py-0.5 rounded-full']">{{ opt.label }}</span>
            </template>
            <span v-else class="text-gray-500">All</span>
          </div>
          <div class="flex flex-wrap items-center gap-2 text-xs text-gray-300">
            <span class="font-bold text-gray-400">Analysis:</span>
            <template v-if="selectedAnalysisOptions.length">
              <span v-for="opt in selectedAnalysisOptions" :key="`top-as-${opt.value}`" :class="[opt.color, 'text-white text-[10px] font-semibold px-2 py-0.5 rounded-full']">{{ opt.label }}</span>
            </template>
            <span v-else class="text-gray-500">All</span>
          </div>
         </div>
      </div>
    </transition>
    <div class="mb-10 flex flex-col gap-6 transition-all duration-300">
        <!-- Breadcrumbs & Header -->
        <div class="flex flex-col gap-3">
            <router-link to="/" class="text-blue-400 hover:text-blue-300 text-sm flex items-center gap-1.5 font-medium transition-colors">
                <ChevronLeft :size="16" />
                Back to Dashboard
            </router-link>
            <div class="flex items-end justify-between gap-6 flex-wrap">
                <div class="flex items-center gap-6">
                    <h2 class="text-4xl font-extrabold tracking-tight text-white leading-none">
                        Vulnerabilities <span class="text-blue-500 italic font-medium px-2">for</span> {{ $route.params.name === '_all_' ? 'All Projects' : $route.params.name }}
                    </h2>
                    <div class="flex gap-2">
                        <button 
                            v-if="$route.params.name !== '_all_'"
                            @click="viewMode = viewMode === 'analysis' ? 'statistics' : 'analysis'"
                            class="bg-blue-600/10 hover:bg-blue-600/20 text-blue-400 border border-blue-500/20 px-4 py-1.5 rounded-xl text-[11px] font-black uppercase tracking-widest transition-all flex items-center gap-2 group shadow-lg active:scale-95"
                        >
                            <BarChart3 v-if="viewMode === 'analysis'" :size="14" class="group-hover:rotate-12 transition-transform" />
                            <LayoutList v-else :size="14" class="group-hover:-rotate-12 transition-transform" />
                            {{ viewMode === 'analysis' ? 'Statistics' : 'Analysis' }}
                        </button>
                        <button 
                            v-if="user?.role === 'REVIEWER' && incompleteGroups.length > 0"
                            @click="showBulkModal = true"
                            class="bg-amber-500/10 hover:bg-amber-500/20 text-amber-500 border border-amber-500/20 px-4 py-1.5 rounded-xl text-[11px] font-black uppercase tracking-widest transition-all flex items-center gap-2 shadow-xl shadow-amber-900/5 active:scale-95"
                        >
                            <Layers :size="14" />
                            Bulk Sync ({{ incompleteGroups.length }})
                        </button>
                        <button 
                            v-if="user?.role === 'REVIEWER' && needsApprovalGroups.length > 0"
                            @click="showBulkApproveModal = true"
                            class="bg-purple-500/10 hover:bg-purple-500/20 text-purple-500 border border-purple-500/20 px-4 py-1.5 rounded-xl text-[11px] font-black uppercase tracking-widest transition-all flex items-center gap-2 shadow-xl shadow-purple-900/5 active:scale-95"
                        >
                            <ShieldCheck :size="14" />
                            Bulk Approve ({{ needsApprovalGroups.length }})
                        </button>
                    </div>
                </div>
            </div>
        </div>

            <div class="sticky top-0 z-40 shadow-xl transition-all duration-300 ease-in-out bg-white/2 border border-white/5 rounded-2xl p-6 backdrop-blur-sm relative">
                <button
                    @click="copyFilterUrl"
                    class="absolute top-3 right-3 text-gray-200 hover:text-white p-1 rounded-full border border-white/10 bg-white/5 hover:bg-white/15 transition-colors"
                    title="Copy current filter URL"
                >
                    <Copy :size="14" />
                    <span class="sr-only">Copy filter URL</span>
                </button>
                <span v-if="copiedUrl" class="absolute top-3 right-12 text-[10px] text-green-300">Copied!</span>

                <div class="flex flex-col gap-5">

                <!-- Row 1: Sort & Dropdown Controls -->
                <div class="flex flex-col gap-2">
                    <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Sort & Scope</label>
                    <div class="flex flex-wrap gap-3 items-end">
                        <div class="flex flex-col gap-1">
                            <label class="text-[9px] uppercase tracking-widest text-gray-400">Sort By</label>
                            <CustomSelect
                                :modelValue="sortBy"
                                @update:modelValue="sortBy = $event"
                                :options="[...SORT_OPTIONS]"
                            />
                        </div>
                        <div class="flex flex-col gap-1">
                            <label class="text-[9px] uppercase tracking-widest text-gray-400">Order</label>
                            <button 
                                @click="sortOrder = sortOrder === 'asc' ? 'desc' : 'asc'"
                                class="bg-black/40 border border-white/10 rounded-xl px-4 h-10 text-sm hover:bg-white/5 transition-colors font-medium text-blue-400 border-dashed"
                                :title="sortOrder === 'asc' ? 'Ascending' : 'Descending'"
                            >
                                {{ sortOrder === 'asc' ? 'ASC' : 'DESC' }}
                            </button>
                        </div>
                        <div class="flex flex-col gap-1 min-w-[8rem]">
                            <label class="text-[9px] uppercase tracking-widest text-gray-400">Dependency</label>
                            <CustomSelect
                                :modelValue="dependencyFilter"
                                @update:modelValue="dependencyFilter = $event as typeof dependencyFilter"
                                :options="[...DEPENDENCY_OPTIONS]"
                            />
                        </div>
                    </div>
                </div>

                <!-- Row 2: Text Search Filters -->
                <div class="flex flex-col gap-2">
                    <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Search Filters</label>
                    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                        <div class="flex flex-col gap-1">
                            <label class="text-[9px] uppercase tracking-widest text-gray-400">Vulnerability ID</label>
                            <input 
                                v-model="idFilter" 
                                type="text" 
                                placeholder="CVE or ID..." 
                                class="bg-black/40 border border-white/10 rounded-xl px-4 h-10 text-sm font-medium focus:outline-none focus:border-blue-500/50 transition-all placeholder:text-gray-600"
                            />
                        </div>
                        <div class="flex flex-col gap-1">
                            <label class="text-[9px] uppercase tracking-widest text-gray-400">Team Identifier</label>
                            <input 
                                v-model="tagFilter" 
                                type="text" 
                                placeholder="Team Identifier..." 
                                class="bg-black/40 border border-white/10 rounded-xl px-4 h-10 text-sm font-medium focus:outline-none focus:border-blue-500/50 transition-all placeholder:text-gray-600"
                            />
                        </div>
                        <div class="flex flex-col gap-1">
                            <label class="text-[9px] uppercase tracking-widest text-gray-400">Component Name</label>
                            <input 
                                v-model="componentFilter" 
                                type="text" 
                                placeholder="Component..." 
                                class="bg-black/40 border border-white/10 rounded-xl px-4 h-10 text-sm font-medium focus:outline-none focus:border-blue-500/50 transition-all placeholder:text-gray-600"
                            />
                        </div>
                        <div class="flex flex-col gap-1 relative">
                            <label class="text-[9px] uppercase tracking-widest text-gray-400">Project Versions</label>
                            <CustomSelect modelValue="" :options="[]">
                                <template #trigger="{ open }">
                                    <div class="relative" @focusin="open">
                                        <div class="flex flex-wrap items-center gap-1 bg-black/40 border border-white/10 rounded-xl px-2 min-h-[2.5rem] cursor-text focus-within:border-blue-500/50 transition-all"
                                             @click="versionSearchInput?.focus()">
                                            <span v-for="ver in versionFilterList" :key="ver" class="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-blue-500/20 text-blue-200 text-[11px] font-medium">
                                                {{ ver }}
                                                <button @click.stop="removeVersion(ver)" class="hover:text-white text-blue-300/70 leading-none">&times;</button>
                                            </span>
                                            <input
                                                ref="versionSearchInput"
                                                v-model="versionSearch"
                                                type="text"
                                                placeholder="Search versions..."
                                                class="flex-1 min-w-[6rem] bg-transparent border-none outline-none text-sm font-medium text-gray-200 placeholder:text-gray-600 h-8 px-1"
                                            />
                                        </div>
                                    </div>
                                </template>
                                <template #menu>
                                    <div class="divide-y divide-white/5">
                                        <button
                                            v-for="opt in filteredVersionOptions" :key="opt"
                                            @mousedown.prevent="toggleVersion(opt)"
                                            :class="[
                                                'w-full text-left px-3 py-1.5 text-sm transition-colors flex items-center justify-between',
                                                versionFilterList.some(v => v.toLowerCase() === opt.toLowerCase())
                                                    ? 'bg-blue-500/15 text-blue-200'
                                                    : 'text-gray-300 hover:bg-white/5'
                                            ]"
                                        >
                                            {{ opt }}
                                            <span v-if="versionFilterList.some(v => v.toLowerCase() === opt.toLowerCase())" class="text-blue-400 text-xs">&#10003;</span>
                                        </button>
                                    </div>
                                </template>
                            </CustomSelect>
                        </div>
                    </div>
                </div>

                <!-- Divider -->
                <div class="border-t border-white/5"></div>

                <!-- Row 3: Status Chips + Statistics -->
                <div class="grid grid-cols-1 lg:grid-cols-[1fr_220px] gap-6">

                    <!-- Left: Status Filters -->
                    <div class="space-y-4">
                        <div class="flex flex-col gap-3">
                            <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Lifecycle Status</label>
                            <div class="flex flex-wrap gap-2 items-center">
                                <button 
                                    v-for="opt in LIFECYCLE_OPTIONS" 
                                    :key="opt.value"
                                    @click="toggleLifecycleFilter(opt.value)"
                                    :title="opt.description"
                                    :class="[
                                        'px-4 py-1.5 rounded-full text-[10px] font-medium uppercase tracking-tight transition-all border outline-none active:scale-95 flex items-center gap-2',
                                        lifecycleFilters.includes(opt.value) 
                                            ? `${opt.color} text-white border-transparent shadow-lg shadow-blue-900/40`
                                            : 'bg-white/5 text-gray-500 border-white/5 hover:bg-white/10 hover:text-gray-300'
                                    ]"
                                >
                                    {{ opt.label }}
                                    <span 
                                        class="px-1.5 py-0.5 rounded-md text-[9px] bg-black/20"
                                        :class="lifecycleFilters.includes(opt.value) ? 'text-white' : 'text-gray-500'"
                                    >
                                        {{ filterCounts[opt.value] || 0 }}
                                    </span>
                                </button>
                            </div>
                        </div>

                        <div class="flex flex-col gap-3">
                            <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Analysis State</label>
                            <div class="flex flex-wrap gap-2 items-center">
                                <button 
                                    v-for="opt in ANALYSIS_OPTIONS" 
                                    :key="opt.value"
                                    @click="toggleAnalysisFilter(opt.value)"
                                    :class="[
                                        'px-4 py-1.5 rounded-full text-[10px] font-medium uppercase tracking-tight transition-all border outline-none active:scale-95 flex items-center gap-2',
                                        analysisFilters.includes(opt.value) 
                                            ? `${opt.color} text-white border-transparent shadow-lg shadow-gray-900/40`
                                            : 'bg-white/5 text-gray-500 border-white/5 hover:bg-white/10 hover:text-gray-300'
                                    ]"
                                >
                                    {{ opt.label }}
                                    <span 
                                        class="px-1.5 py-0.5 rounded-md text-[9px] bg-black/20"
                                        :class="analysisFilters.includes(opt.value) ? 'text-white' : 'text-gray-500'"
                                    >
                                        {{ filterCounts[opt.value] || 0 }}
                                    </span>
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- Right: Statistics Panel -->
                    <div class="flex flex-col gap-3 p-4 bg-black/20 border border-white/5 rounded-xl">
                        <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Statistics</label>
                        <div class="flex items-center gap-2 px-3 py-1.5 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                            <LayoutList :size="12" class="text-blue-400" />
                            <span class="text-[10px] font-black text-blue-400 uppercase tracking-widest">{{ filteredGroups.length }} Findings</span>
                        </div>
                        <div class="flex flex-col gap-1.5">
                            <div class="flex justify-between items-center px-2 py-1 rounded bg-green-500/10">
                                <span class="text-[10px] text-green-300">Direct</span>
                                <span class="text-[10px] font-bold text-green-200">{{ dependencyRelationshipCounts.direct }}</span>
                            </div>
                            <div class="flex justify-between items-center px-2 py-1 rounded bg-purple-500/10">
                                <span class="text-[10px] text-purple-300">Transitive</span>
                                <span class="text-[10px] font-bold text-purple-200">{{ dependencyRelationshipCounts.transitive }}</span>
                            </div>
                            <div class="flex justify-between items-center px-2 py-1 rounded bg-gray-500/10">
                                <span class="text-[10px] text-gray-400">Unknown</span>
                                <span class="text-[10px] font-bold text-gray-300">{{ dependencyRelationshipCounts.unknown }}</span>
                            </div>
                        </div>
                        <button 
                            @click="resetFilters"
                            class="mt-1 text-[10px] font-black text-blue-500 hover:text-blue-400 uppercase tracking-widest transition-colors text-center"
                        >
                            Reset All Filters
                        </button>
                    </div>
                </div>
                </div>
        </div>
    </div>
    
    <div v-if="loading" class="text-center py-10">
        <div class="mb-2 text-xl font-semibold">{{ loadingMessage }}</div>
        <div class="w-full max-w-md mx-auto bg-gray-700 rounded-full h-4 relative overflow-hidden">
             <div class="bg-blue-500 h-4 transition-all duration-300" :style="{ width: loadingProgress + '%' }"></div>
        </div>
        <div class="mt-2 text-sm text-gray-400">{{ loadingProgress }}%</div>
        <div v-if="loadingLog.length > 0" ref="logContainer" class="mt-4 w-full max-w-md mx-auto bg-gray-900 border border-gray-700 rounded-lg p-3 max-h-40 overflow-y-auto text-left">
            <div v-for="(entry, i) in loadingLog" :key="i" class="text-xs font-mono text-gray-400 py-0.5">
                <span class="text-gray-600 select-none">{{ String(i + 1).padStart(2, '0') }}</span> {{ entry }}
            </div>
        </div>
    </div>
    <div v-else-if="error" class="text-red-500 text-center py-10">{{ error }}</div>
    
    <div v-else>
        <div v-if="viewMode === 'analysis'" class="space-y-4">
            <VulnGroupCard 
                v-for="group in filteredGroups" 
                :key="group.id" 
                :group="group" 
                @update:assessment="(data) => handleLocalAssessmentUpdate(group, data)" 
                @toggle-expand="(id, expanded) => handleToggleExpand(id, expanded)"
            />
            <div v-if="filteredGroups.length === 0" class="text-gray-500 text-center py-20 font-medium">No vulnerabilities found matching criteria.</div>
        </div>
        <div v-else class="py-4">
            <div v-if="statsLoading" class="text-center py-20">
                <div class="animate-pulse flex flex-col items-center">
                    <BarChart3 :size="48" class="text-blue-500 mb-4" />
                    <div class="text-xl font-black text-gray-300 uppercase tracking-tight">Calculating metrics...</div>
                </div>
            </div>
            <div v-else-if="statsError" class="text-red-500 text-center py-20">{{ statsError }}</div>
            <ProjectStatistics v-else-if="stats" :stats="stats" :projectName="($route.params.name as string)" />
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
        @updated="(updates) => handleBulkUpdates(updates, () => { showBulkApproveModal = false })" 
    />
  </div>
</template>

<style scoped>
.overlay-fade-enter-active, .overlay-fade-leave-active {
  transition: opacity 0.25s ease, transform 0.25s ease;
}
.overlay-fade-enter-from, .overlay-fade-leave-to {
  opacity: 0;
  transform: translateY(-10px);
}
.overlay-fade-enter-to, .overlay-fade-leave-from {
  opacity: 1;
  transform: translateY(0);
}
.filter-transition-enter-active, .filter-transition-leave-active {
  transition: opacity 0.25s ease, transform 0.25s ease;
}
.filter-transition-enter-from, .filter-transition-leave-to {
  opacity: 0;
  transform: translateY(-10px);
}
.filter-transition-enter-to, .filter-transition-leave-from {
  opacity: 1;
  transform: translateY(0);
}
</style>
