<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { getGroupedVulns } from '../lib/api'
import type { GroupedVuln } from '../types'
import VulnGroupCard from '../components/VulnGroupCard.vue'

const route = useRoute()
const groups = ref<GroupedVuln[]>([])
const loading = ref(true)
const error = ref('')

const fetchVulns = async () => {
    const name = route.params.name as string
    if (!name) return
    
    loading.value = true
    try {
        const data = await getGroupedVulns(name)
        groups.value = data
        error.value = ''
    } catch (err) {
        error.value = 'Failed to load vulnerabilities'
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

watch(() => route.params.name, fetchVulns, { immediate: true })
</script>

<template>
  <div>
    <div class="mb-6 flex items-center gap-4">
        <router-link to="/" class="text-blue-400 hover:underline">&larr; Back to Dashboard</router-link>
        <h2 class="text-2xl font-bold">Vulnerabilities for <span class="text-blue-500">{{ $route.params.name }}</span></h2>
    </div>
    
    <div v-if="loading" class="text-center py-10">Loading vulnerabilities for {{ $route.params.name }}...</div>
    <div v-else-if="error" class="text-red-500 text-center py-10">{{ error }}</div>
    
    <div v-else class="space-y-4">
        <VulnGroupCard 
            v-for="group in groups" 
            :key="group.id" 
            :group="group" 
            @update:assessment="(data) => handleLocalAssessmentUpdate(group, data)" 
        />
        <div v-if="groups.length === 0" class="text-gray-500 text-center">No vulnerabilities found.</div>
    </div>
  </div>
</template>
