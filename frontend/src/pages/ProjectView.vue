<script setup lang="ts">
import { ref, watch, computed, inject, provide, onMounted, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { getGroupedVulns, getTeamMapping, getRescoreRules, getStatistics } from '../lib/api'
import { getGroupLifecycle, isPendingReview as isPendingReviewHelper, matchesFilters, getGroupTechnicalState, tagToString } from '../lib/assessment-helpers'
import { calculateScoreFromVector } from '../lib/cvss'
import type { GroupedVuln, Statistics } from '../types'

import VulnGroupCard from '../components/VulnGroupCard.vue'
import BulkResolveIncompleteModal from '../components/BulkResolveIncompleteModal.vue'
import BulkApproveModal from '../components/BulkApproveModal.vue'
import ProjectStatistics from '../components/ProjectStatistics.vue'
import { BarChart3, Layers, ChevronLeft, ShieldCheck, LayoutList } from 'lucide-vue-next'

const route = useRoute()
const user = inject<any>('user')
const groups = ref<GroupedVuln[]>([])
const loading = ref(true)
const error = ref('')
const loadingMessage = ref('Initializing...')
const loadingProgress = ref(0)
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

const fetchVulns = async () => {
    let name = route.params.name as string
    if (!name) return
    
    const isAllProjects = name === '_all_'
    const apiName = isAllProjects ? '' : name

    loading.value = true
    error.value = ''
    loadingMessage.value = isAllProjects ? 'Starting global search...' : 'Starting search...'
    loadingProgress.value = 0

    try {
        const data = await getGroupedVulns(apiName, undefined, (msg, progress) => {
            loadingMessage.value = msg
            loadingProgress.value = progress
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
    sortBy.value = 'severity'
    sortOrder.value = 'asc'
}

// Filter state now remains local in the frontend and does not cause backend re-fetch.
// This reduces unnecessary chattiness and keeps filtering fast and responsive.
// URL sync was removed to avoid automatic API refresh for every filter tweak.

// watch([lifecycleFilters, analysisFilters, tagFilter, idFilter, componentFilter, sortBy, sortOrder], () => {
//     const query = { ...route.query }
//
//     if (lifecycleFilters.value.length > 0) query.lifecycle = lifecycleFilters.value
//     else delete query.lifecycle
//
//     if (analysisFilters.value.length > 0) query.analysis = analysisFilters.value
//     else delete query.analysis
//
//     if (tagFilter.value) query.tag = tagFilter.value
//     else delete query.tag
//
//     if (idFilter.value) query.id = idFilter.value
//     else delete query.id
//
//     if (componentFilter.value) query.component = componentFilter.value
//     else delete query.component
//
//     query.sort = sortBy.value
//     query.order = sortOrder.value
//
//     router.replace({ query }).catch(() => {})
// }, { deep: true })

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

const filteredGroups = computed(() => {
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

    groups.value.forEach(g => {
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

            <div class="sticky top-0 z-40 shadow-xl transition-all duration-300 ease-in-out bg-white/2 border border-white/5 rounded-2xl p-6 backdrop-blur-sm">
                <div class="grid grid-cols-1 lg:grid-cols-[200px_1fr] gap-8 items-end">
                <!-- Sorting Section -->
                <div class="flex flex-col gap-2">
                    <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Sort Catalog</label>
                    <div class="flex gap-2 h-10">
                        <select 
                            v-model="sortBy"
                            class="bg-black/40 border border-white/10 rounded-xl px-4 text-sm font-medium text-gray-200 focus:outline-none focus:border-blue-500/50 flex-1 appearance-none bg-no-repeat bg-[right_1rem_center] cursor-pointer"
                        >
                            <option value="severity">Criticality</option>
                            <option value="score">Score</option>
                            <option value="analysis">Analysis</option>
                            <option value="tags">Tags</option>
                            <option value="id">CVE ID</option>
                        </select>
                        <button 
                            @click="sortOrder = sortOrder === 'asc' ? 'desc' : 'asc'"
                            class="bg-black/40 border border-white/10 rounded-xl px-4 text-sm hover:bg-white/5 transition-colors font-medium text-blue-400 border-dashed"
                            :title="sortOrder === 'asc' ? 'Ascending' : 'Descending'"
                        >
                            {{ sortOrder === 'asc' ? 'ASC' : 'DESC' }}
                        </button>
                    </div>
                </div>

                <!-- Input Filters Section -->
                <div class="flex flex-col gap-2">
                    <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Search & Refine</label>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-2 h-10">
                        <div class="relative group">
                            <input 
                                v-model="idFilter" 
                                type="text" 
                                placeholder="Vulnerability ID..." 
                                class="bg-black/40 border border-white/10 rounded-xl px-4 w-full h-full text-sm font-medium focus:outline-none focus:border-blue-500/50 transition-all placeholder:text-gray-600"
                            />
                        </div>
                        <input 
                            v-model="tagFilter" 
                            type="text" 
                            placeholder="Team Identifier..." 
                            class="bg-black/40 border border-white/10 rounded-xl px-4 w-full h-full text-sm font-medium focus:outline-none focus:border-blue-500/50 transition-all placeholder:text-gray-600"
                        />
                        <input 
                            v-model="componentFilter" 
                            type="text" 
                            placeholder="Component Name..." 
                            class="bg-black/40 border border-white/10 rounded-xl px-4 w-full h-full text-sm font-medium focus:outline-none focus:border-blue-500/50 transition-all placeholder:text-gray-600"
                        />
                    </div>
                </div>
            </div>

            <!-- Status Selection Chips -->
            <div class="pt-6 border-t border-white/5 space-y-4">
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

                        <div class="ms-auto flex items-center gap-6">
                            <div class="flex items-center gap-2 px-3 py-1.5 bg-blue-500/10 border border-blue-500/20 rounded-xl">
                                <LayoutList :size="12" class="text-blue-400" />
                                <span class="text-[10px] font-black text-blue-400 uppercase tracking-widest">{{ filteredGroups.length }} Findings Visible</span>
                            </div>
                            <button 
                                @click="resetFilters"
                                class="text-[10px] font-black text-blue-500 hover:text-blue-400 uppercase tracking-widest transition-colors flex items-center gap-1"
                            >
                                Reset All
                            </button>
                        </div>
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
