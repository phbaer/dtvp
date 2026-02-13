<script setup lang="ts">
import { ref, watch, computed, inject } from 'vue'
import { useRoute } from 'vue-router'
import { getGroupedVulns } from '../lib/api'
import { calculateScoreFromVector } from '../lib/cvss'
import type { GroupedVuln } from '../types'
import VulnGroupCard from '../components/VulnGroupCard.vue'

const route = useRoute()
const user = inject<any>('user')
const groups = ref<GroupedVuln[]>([])
const loading = ref(true)
const error = ref('')
const loadingMessage = ref('Initializing...')
const loadingProgress = ref(0)

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
        const data = await getGroupedVulns(apiName, (msg, progress) => {
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

const handleLocalAssessmentUpdate = (group: GroupedVuln, data: {
    rescored_cvss: number | null,
    rescored_vector: string,
    analysis_state: string,
    analysis_details: string,
    is_suppressed: boolean,
    justification: string
}) => {
    // Update the group's rescored values
    group.rescored_cvss = data.rescored_cvss
    group.rescored_vector = data.rescored_vector

    // Update all affected instances in this group
    group.affected_versions.forEach(version => {
        version.components.forEach(instance => {
            instance.analysis_state = data.analysis_state
            instance.analysis_details = data.analysis_details
            instance.is_suppressed = data.is_suppressed
            instance.justification = data.justification
        })
    })
}

const tagFilter = ref('')
const idFilter = ref('')
const hideAssessed = ref(true)
const hideMixed = ref(true)
const showNeedsApproval = ref(false)
const sortBy = ref('severity')
const sortOrder = ref<'asc' | 'desc'>('asc')

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
    'NOT_AFFECTED': 5,
    'MIXED': 6
}

const getDisplayState = (group: GroupedVuln) => {
    const allInstances = group.affected_versions?.flatMap(v => v.components) || []
    const uniqueStates = Array.from(new Set(allInstances.map(i => i.analysis_state || 'NOT_SET')))
    return uniqueStates.length === 1 ? uniqueStates[0] : 'MIXED'
}

const filteredGroups = computed(() => {
    let result = [...groups.value]
    
    if (tagFilter.value) {
        const term = tagFilter.value.toLowerCase()
        result = result.filter(g => 
            g.tags?.some(t => t.toLowerCase().includes(term))
        )
    }

    if (idFilter.value) {
        const term = idFilter.value.toLowerCase()
        result = result.filter(g => 
            g.id.toLowerCase().includes(term)
        )
    }

    if (hideAssessed.value) {
        result = result.filter(g => {
            const state = getDisplayState(g)
            // Keep if NOT_SET or MIXED
            return state === 'NOT_SET' || state === 'MIXED'
        })
    }

    if (hideMixed.value) {
        result = result.filter(g => getDisplayState(g) !== 'MIXED')
    }

    if (showNeedsApproval.value) {
        result = result.filter(g => {
            return g.affected_versions.some(v => 
                v.components.some(c => (c.analysis_details || '').includes('[Status: Pending Review]'))
            )
        })
    }

    result.sort((a, b) => {
        let comparison = 0
        
        switch (sortBy.value) {
            case 'analysis': {
                const stateA = getDisplayState(a) || 'NOT_SET'
                const stateB = getDisplayState(b) || 'NOT_SET'
                comparison = (ANALYSIS_STATE_ORDER[stateA] ?? 99) - (ANALYSIS_STATE_ORDER[stateB] ?? 99)
                break
            }
            case 'tags': {
                const tagA = (a.tags && a.tags.length > 0) ? (a.tags[0] || '') : ''
                const tagB = (b.tags && b.tags.length > 0) ? (b.tags[0] || '') : ''
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


watch(() => route.params.name, fetchVulns, { immediate: true })
</script>

<template>
  <div class="mx-auto">
    <div class="mb-8 flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div class="flex flex-col gap-2">
            <router-link to="/" class="text-blue-400 hover:text-blue-300 text-sm flex items-center gap-1">
                &larr; Back to Dashboard
            </router-link>
            <h2 class="text-3xl font-bold">Vulnerabilities for <span class="text-blue-500">{{ $route.params.name === '_all_' ? 'All Projects' : $route.params.name }}</span></h2>
        </div>
        <div class="flex flex-col gap-4">
            <div class="flex flex-col md:flex-row gap-4 md:items-end lg:items-end">
                <div class="flex flex-col gap-1">
                    <label class="text-[10px] font-bold text-gray-500 uppercase">Sort By</label>
                    <div class="flex gap-2">
                        <select 
                            v-model="sortBy"
                            class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500"
                        >
                            <option value="severity">Criticality</option>
                            <option value="score">Score</option>
                            <option value="analysis">Analysis</option>
                            <option value="tags">Tags</option>
                            <option value="id">CVE ID</option>
                        </select>
                        <button 
                            @click="sortOrder = sortOrder === 'asc' ? 'desc' : 'asc'"
                            class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm hover:bg-gray-700 transition-colors"
                            :title="sortOrder === 'asc' ? 'Ascending' : 'Descending'"
                        >
                            {{ sortOrder === 'asc' ? '↑' : '↓' }}
                        </button>
                    </div>
                </div>
                <div class="flex flex-col gap-1">
                    <label class="text-[10px] font-bold text-gray-500 uppercase">Filter</label>
                    <div class="flex flex-col md:flex-row gap-2">
                        <input 
                            v-model="idFilter" 
                            type="text" 
                            placeholder="Filter by ID (CVE...)" 
                            class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500 w-full md:w-48"
                        />
                        <input 
                            v-model="tagFilter" 
                            type="text" 
                            placeholder="Filter by Team Tag..." 
                            class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500 w-full md:w-48"
                        />
                    </div>
                </div>
            </div>
            <div class="flex gap-4 self-end">
                <label class="inline-flex items-center cursor-pointer">
                    <input type="checkbox" v-model="hideAssessed" class="sr-only peer">
                    <div class="relative w-9 h-5 bg-gray-700 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-blue-600"></div>
                    <span class="ms-2 text-xs font-medium text-gray-300">Hide Assessed</span>
                </label>
                <label class="inline-flex items-center cursor-pointer">
                    <input type="checkbox" v-model="hideMixed" class="sr-only peer">
                    <div class="relative w-9 h-5 bg-gray-700 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-blue-600"></div>
                    <span class="ms-2 text-xs font-medium text-gray-300">Hide Mixed</span>
                </label>
            </div>
            <div class="flex gap-4 self-end">
                 <label v-if="user?.role === 'REVIEWER'" class="inline-flex items-center cursor-pointer">
                    <input type="checkbox" v-model="showNeedsApproval" class="sr-only peer">
                    <div class="relative w-9 h-5 bg-gray-700 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-yellow-500 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-yellow-600"></div>
                    <span class="ms-2 text-xs font-medium text-yellow-300">Needs Approval</span>
                </label>
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
    
    <div v-else class="space-y-4">
        <VulnGroupCard 
            v-for="group in filteredGroups" 
            :key="group.id" 
            :group="group" 
            @update:assessment="(data) => handleLocalAssessmentUpdate(group, data)" 
        />
        
        <div v-if="filteredGroups.length === 0" class="text-gray-500 text-center">No vulnerabilities found matching criteria.</div>
    </div>
  </div>
</template>
