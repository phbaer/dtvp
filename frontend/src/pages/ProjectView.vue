<script setup lang="ts">
import { ref, watch, computed } from 'vue'
import { useRoute } from 'vue-router'
import { getGroupedVulns } from '../lib/api'
import type { GroupedVuln } from '../types'
import VulnGroupCard from '../components/VulnGroupCard.vue'

const route = useRoute()
const groups = ref<GroupedVuln[]>([])
const loading = ref(true)
const error = ref('')
const loadingMessage = ref('Initializing...')
const loadingProgress = ref(0)

const fetchVulns = async () => {
    const name = route.params.name as string
    if (!name) return
    
    loading.value = true
    error.value = ''
    loadingMessage.value = 'Starting search...'
    loadingProgress.value = 0

    try {
        const data = await getGroupedVulns(name, (msg, progress) => {
            loadingMessage.value = msg
            loadingProgress.value = progress
        })
        groups.value = data
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
    is_suppressed: boolean
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
        })
    })
}

const tagFilter = ref('')

const filteredGroups = computed(() => {
    if (!tagFilter.value) return groups.value
    const term = tagFilter.value.toLowerCase()
    return groups.value.filter(g => 
        g.tags?.some(t => t.toLowerCase().includes(term))
    )
})

watch(() => route.params.name, fetchVulns, { immediate: true })
</script>

<template>
  <div>
    <div class="mb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div class="flex items-center gap-4">
            <router-link to="/" class="text-blue-400 hover:underline">&larr; Back to Dashboard</router-link>
            <h2 class="text-2xl font-bold">Vulnerabilities for <span class="text-blue-500">{{ $route.params.name }}</span></h2>
        </div>
        <div>
            <input 
                v-model="tagFilter" 
                type="text" 
                placeholder="Filter by Team Tag..." 
                class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500 w-full md:w-64"
            />
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
